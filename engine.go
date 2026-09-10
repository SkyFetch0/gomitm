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
	ca      *CertManager
	d       Decider
	maxBody int64
}

func New(ca *CertManager, d Decider) *Engine {
	return &Engine{ca: ca, d: d, maxBody: DefaultMaxBody}
}

func (e *Engine) WithMaxBody(n int64) *Engine {
	e.maxBody = n
	return e
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
	if isTLS {
		tlsConn := tls.Server(bc, e.ca.ServerConfig())
		if err := tlsConn.Handshake(); err != nil {
			return
		}
		e.httpLoop(tlsConn, host, dst, true)
		return
	}
	e.httpLoop(bc, host, dst, false)
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

func (e *Engine) httpLoop(client net.Conn, host, dst string, tlsUp bool) {
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
			mock = e.d.OnRequest(host, req) // may mutate req (rewrite) then return nil
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
			_ = mock.Write(client)
			e.emit(host, req, mock.StatusCode, reqN, resN, true, reqSnip, resSnip, reqTr, resTr)
			continue
		}
		status, reqN2, resN, resSnip, resTr := e.forward(client, dst, host, req, tlsUp)
		if reqN2 > reqN {
			reqN = reqN2
		}
		e.emit(host, req, status, reqN, resN, false, reqSnip, resSnip, reqTr, resTr)
	}
}

func (e *Engine) forward(client net.Conn, dst, host string, req *http.Request, tlsUp bool) (status int, reqN, resN int64, resSnip []byte, resTr bool) {
	if dst == "" {
		dst = net.JoinHostPort(host, portFor(tlsUp))
	}
	raw, err := net.DialTimeout("tcp", dst, 15*time.Second)
	if err != nil {
		msg := "upstream dial failed"
		resp := &http.Response{StatusCode: 502, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(msg))}
		_ = resp.Write(client)
		return 502, 0, int64(len(msg)), []byte(msg), false
	}
	defer raw.Close()
	var up net.Conn = raw
	if tlsUp {
		cfg := &tls.Config{ServerName: host, InsecureSkipVerify: true}
		t := tls.Client(raw, cfg)
		if err := t.Handshake(); err != nil {
			return 502, 0, 0, nil, false
		}
		up = t
	}
	req.RequestURI = ""
	if err := req.Write(up); err != nil {
		return 502, 0, 0, nil, false
	}
	resp, err := http.ReadResponse(bufio.NewReader(up), req)
	if err != nil {
		return 502, 0, 0, nil, false
	}
	defer resp.Body.Close()
	status = resp.StatusCode
	reqN = req.ContentLength
	resSnip, resN, resTr, resRest := peekBody(resp.Body, e.maxBody)
	resp.Body = resRest
	_ = resp.Write(client)
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
