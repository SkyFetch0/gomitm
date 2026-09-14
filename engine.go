package gomitm

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Engine is the MITM dispatch core. It does not know domain state machines.
type Engine struct {
	ca       *CertManager
	d        Decider
	maxBody  int64
	keyLog   io.Writer
	verifyUp bool
}

func New(ca *CertManager, d Decider) *Engine {
	return &Engine{ca: ca, d: d, maxBody: DefaultMaxBody}
}

func (e *Engine) WithMaxBody(n int64) *Engine {
	e.maxBody = n
	return e
}

func (e *Engine) WithKeyLog(w io.Writer) *Engine {
	e.keyLog = w
	return e
}

func (e *Engine) WithUpstreamVerify(v bool) *Engine {
	e.verifyUp = v
	return e
}

func (e *Engine) serverTLS() *tls.Config {
	cfg := e.ca.ServerConfig()
	if e.keyLog != nil {
		cfg.KeyLogWriter = e.keyLog
	}
	return cfg
}

// Handle processes one accepted connection.
// host may be empty; it will be filled from SNI or HTTP Host.
// dst is original destination "IP:port".
func (e *Engine) Handle(conn net.Conn, host, dst string, isTLS bool) {
	defer conn.Close()
	br := bufio.NewReaderSize(conn, 16384)
	bc := &bufConn{r: br, c: conn}

	if !isTLS {
		isTLS = IsTLS(br)
	}
	if host == "" {
		if isTLS {
			host = PeekSNI(br)
		} else {
			host = PeekHTTPHost(br)
		}
	}
	host = stripPort(host)

	act := Passthrough
	if e.d != nil {
		act = e.d.OnConnect(host, dst)
	}

	if act == Passthrough {
		e.splice(bc, dst)
		return
	}
	var hello []byte
	if isTLS {
		hello = peekTLSRecord(br)
		dumpOriginChain(host, dst, e.verifyUp)
		tlsConn := tls.Server(bc, e.serverTLS())
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		if tlsConn.ConnectionState().NegotiatedProtocol == "h2" {
			e.h2Server(tlsConn, host, dst, hello)
			return
		}
		e.httpLoop(tlsConn, host, dst, true, hello)
		return
	}
	e.httpLoop(bc, host, dst, false, nil)
}

func (e *Engine) splice(client net.Conn, dst string) {
	if dst == "" {
		return
	}
	up, err := net.DialTimeout("tcp", dst, 15*time.Second)
	if err != nil {
		return
	}
	defer up.Close()
	errc := make(chan struct{}, 2)
	go func() { io.Copy(up, client); errc <- struct{}{} }()
	go func() { io.Copy(client, up); errc <- struct{}{} }()
	<-errc
}

func (e *Engine) httpLoop(client net.Conn, host, dst string, tlsUp bool, hello []byte) {
	br := bufio.NewReader(client)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		if host == "" {
			host = stripPort(req.Host)
		}
		var mock *http.Response
		if e.d != nil {
			mock = e.d.OnRequest(host, req)
		}
		if mock == nil && (isUpgrade(req) || isSSE(req)) {
			e.forwardRaw(client, br, dst, host, req, tlsUp, hello)
			return
		}
		reqSnip, reqN, reqTr, reqRest := peekBody(req.Body, e.maxBody)
		req.Body = reqRest
		if mock != nil {
			mock.Request = req
			if mock.Header == nil {
				mock.Header = make(http.Header)
			}
			resSnip, resN, resTr, resRest := peekBody(mock.Body, e.maxBody)
			mock.Body = resRest
			_ = writeHTTP11(client, mock)
			e.emit(host, req, mock.StatusCode, reqN, resN, true, reqSnip, resSnip, reqTr, resTr)
			continue
		}
		status, reqN2, resN, resSnip, resTr := e.forward(client, dst, host, req, tlsUp, hello)
		if reqN2 > reqN {
			reqN = reqN2
		}
		e.emit(host, req, status, reqN, resN, false, reqSnip, resSnip, reqTr, resTr)
	}
}

func (e *Engine) forward(client net.Conn, dst, host string, req *http.Request, tlsUp bool, hello []byte) (status int, reqN, resN int64, resSnip []byte, resTr bool) {
	if dst == "" {
		dst = net.JoinHostPort(host, portFor(tlsUp))
	}
	up, err := e.dialUpstream(dst, host, tlsUp, hello)
	if err != nil {
		msg := "upstream dial failed"
		resp := &http.Response{StatusCode: 502, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(msg))}
		_ = resp.Write(client)
		return 502, 0, int64(len(msg)), []byte(msg), false
	}
	defer up.Close()
	resp, err := e.writeHTTP(up, req)
	if err != nil {
		return 502, 0, 0, nil, false
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	reqN = req.ContentLength
	resSnip, peeked, resTr, resRest := peekBody(resp.Body, e.maxBody)
	resp.Body = resRest
	resN = resp.ContentLength
	if resN < 0 {
		resN = peeked
	}
	_ = writeHTTP11(client, resp)
	return status, reqN, resN, resSnip, resTr
}

func (e *Engine) emit(host string, req *http.Request, status int, reqN, resN int64, mocked bool, reqB, resB []byte, reqTr, resTr bool) {
	if e.d == nil {
		return
	}
	e.d.OnFlow(Flow{
		Time:         time.Now(),
		Host:         host,
		Method:       req.Method,
		Path:         req.URL.Path,
		Status:       status,
		ReqSize:      reqN,
		ResSize:      resN,
		Mocked:       mocked,
		ReqBody:      reqB,
		ResBody:      resB,
		ReqTruncated: reqTr,
		ResTruncated: resTr,
	})
}

func stripPort(h string) string {
	if h == "" {
		return h
	}
	host, _, err := net.SplitHostPort(h)
	if err != nil {
		return h
	}
	return host
}

func portFor(tlsUp bool) string {
	if tlsUp {
		return "443"
	}
	return "80"
}

func (e *Engine) upstreamTLS(host string) *tls.Config {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if !e.verifyUp {
		cfg.InsecureSkipVerify = true
	}
	return cfg
}

func isUpgrade(req *http.Request) bool {
	return strings.EqualFold(req.Header.Get("Upgrade"), "websocket") ||
		strings.Contains(strings.ToLower(req.Header.Get("Connection")), "upgrade")
}

func isSSE(req *http.Request) bool {
	return strings.Contains(strings.ToLower(req.Header.Get("Accept")), "text/event-stream")
}

func (e *Engine) forwardRaw(client net.Conn, br *bufio.Reader, dst, host string, req *http.Request, tlsUp bool, hello []byte) {
	if dst == "" {
		dst = net.JoinHostPort(host, portFor(tlsUp))
	}
	up, err := e.dialUpstream(dst, host, tlsUp, hello)
	if err != nil {
		return
	}
	defer up.Close()
	req.RequestURI = ""
	if err := req.Write(up); err != nil {
		return
	}
	kind := "upgrade"
	if isSSE(req) {
		kind = "sse"
	}
	e.emit(host, req, 101, 0, 0, false, nil, []byte(kind), false, false)
	errc := make(chan struct{}, 2)
	go func() { io.Copy(up, br); errc <- struct{}{} }()
	go func() { io.Copy(client, up); errc <- struct{}{} }()
	<-errc
}
