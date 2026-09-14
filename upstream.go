package gomitm

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

func peekTLSRecord(br *bufio.Reader) []byte {
	h, err := br.Peek(5)
	if err != nil || len(h) < 5 || h[0] != 0x16 {
		return nil
	}
	n := int(binary.BigEndian.Uint16(h[3:5]))
	if n > 1<<16-1 {
		return nil
	}
	need := 5 + n
	b, err := br.Peek(need)
	if err != nil {
		return b
	}
	return b
}

func (e *Engine) dialUpstream(dst, host string, tlsUp bool, clientHello []byte) (net.Conn, error) {
	raw, err := net.DialTimeout("tcp", dst, 15*time.Second)
	if err != nil {
		return nil, err
	}
	if !tlsUp {
		return raw, nil
	}
	c, err := e.utlsHandshake(raw, host, clientHello)
	if err == nil {
		return c, nil
	}
	raw.Close()
	raw2, err2 := net.DialTimeout("tcp", dst, 15*time.Second)
	if err2 != nil {
		return nil, err
	}
	return e.utlsHandshake(raw2, host, nil)
}

func (e *Engine) utlsHandshake(raw net.Conn, host string, hello []byte) (net.Conn, error) {
	cfg := &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: !e.verifyUp,
		MinVersion:         utls.VersionTLS12,
	}
	var spec *utls.ClientHelloSpec
	if len(hello) >= 9 {
		fp := &utls.Fingerprinter{AllowBluntMimicry: true}
		spec, _ = fp.RawClientHello(hello)
		if spec == nil && hello[0] == 0x16 {
			spec, _ = fp.RawClientHello(hello[5:])
		}
	}
	var u *utls.UConn
	if spec != nil {
		u = utls.UClient(raw, cfg, utls.HelloCustom)
		if err := u.ApplyPreset(spec); err != nil {
			return nil, err
		}
	} else {
		u = utls.UClient(raw, cfg, utls.HelloChrome_Auto)
	}
	if err := u.Handshake(); err != nil {
		return nil, err
	}
	return u, nil
}

func (e *Engine) writeHTTP(up net.Conn, req *http.Request) (*http.Response, error) {
	prepReqURL(req)
	if negotiatedALPN(up) == "h2" {
		tr := &http2.Transport{}
		cc, err := tr.NewClientConn(up)
		if err != nil {
			return nil, err
		}
		return cc.RoundTrip(req)
	}
	if err := req.Write(up); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(up), req)
}

func writeHTTP11(w io.Writer, resp *http.Response) error {
	if resp == nil {
		return nil
	}
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	resp.TransferEncoding = nil
	resp.Header.Del("Transfer-Encoding")
	for _, k := range []string{"Connection", "Keep-Alive", "Proxy-Connection", "Upgrade", "TE"} {
		resp.Header.Del(k)
	}
	if resp.Uncompressed {
		resp.Header.Del("Content-Encoding")
		resp.Uncompressed = false
	}
	return resp.Write(w)
}

func (e *Engine) h2Server(client *tls.Conn, sni, dst string, hello []byte) {
	if dst == "" {
		dst = net.JoinHostPort(sni, "443")
	}
	shared, err := e.dialUpstream(dst, sni, true, hello)
	var h2c *http2.ClientConn
	if err == nil && negotiatedALPN(shared) == "h2" {
		tr := &http2.Transport{}
		h2c, err = tr.NewClientConn(shared)
		if err != nil {
			shared.Close()
			h2c = nil
			shared = nil
		}
	} else if shared != nil {
		shared.Close()
		shared = nil
	}
	if shared != nil && h2c != nil {
		defer shared.Close()
	}
	srv := &http2.Server{}
	srv.ServeConn(client, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			h := sni
			if h == "" {
				h = stripPort(req.Host)
			}
			var mock *http.Response
			if e.d != nil {
				mock = e.d.OnRequest(h, req)
			}
			if mock == nil && (isUpgrade(req) || isSSE(req)) {
				e.h2ProxyStream(w, req, dst, h, hello)
				return
			}
			reqSnip, reqN, reqTr, reqRest := peekBody(req.Body, e.maxBody)
			req.Body = reqRest
			if mock != nil {
				resSnip, resN, resTr, resRest := peekBody(mock.Body, e.maxBody)
				mock.Body = resRest
				copyH2Resp(w, mock, false)
				e.emit(h, req, mock.StatusCode, reqN, resN, true, reqSnip, resSnip, reqTr, resTr)
				return
			}
			var resp *http.Response
			var rtErr error
			if h2c != nil {
				prepReqURL(req)
				resp, rtErr = h2c.RoundTrip(req)
			} else {
				up, dialErr := e.dialUpstream(dst, h, true, hello)
				if dialErr != nil {
					http.Error(w, "upstream dial failed", 502)
					e.emit(h, req, 502, reqN, 0, false, reqSnip, nil, reqTr, false)
					return
				}
				defer up.Close()
				resp, rtErr = e.writeHTTP(up, req)
			}
			if rtErr != nil || resp == nil {
				http.Error(w, "upstream dial failed", 502)
				e.emit(h, req, 502, reqN, 0, false, reqSnip, nil, reqTr, false)
				return
			}
			defer resp.Body.Close()
			if isStreamingResp(resp, req) {
				copyH2Resp(w, resp, true)
				e.emit(h, req, resp.StatusCode, reqN, 0, false, reqSnip, []byte("stream"), reqTr, false)
				return
			}
			resSnip, peeked, resTr, resRest := peekBody(resp.Body, e.maxBody)
			resp.Body = resRest
			resN := resp.ContentLength
			if resN < 0 {
				resN = peeked
			}
			copyH2Resp(w, resp, false)
			e.emit(h, req, resp.StatusCode, reqN, resN, false, reqSnip, resSnip, reqTr, resTr)
		}),
	})
}

func (e *Engine) h2ProxyStream(w http.ResponseWriter, req *http.Request, dst, host string, hello []byte) {
	up, err := e.dialUpstream(dst, host, true, hello)
	if err != nil {
		http.Error(w, "upstream dial failed", 502)
		return
	}
	defer up.Close()
	resp, err := e.writeHTTP(up, req)
	if err != nil || resp == nil {
		http.Error(w, "upstream dial failed", 502)
		return
	}
	defer resp.Body.Close()
	copyH2Resp(w, resp, true)
	kind := "stream"
	if isSSE(req) {
		kind = "sse"
	}
	e.emit(host, req, resp.StatusCode, 0, 0, false, nil, []byte(kind), false, false)
}

func prepReqURL(req *http.Request) {
	req.RequestURI = ""
	if req.URL == nil {
		return
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "https"
	}
	if req.URL.Host == "" && req.Host != "" {
		req.URL.Host = req.Host
	}
}

func isStreamingResp(resp *http.Response, req *http.Request) bool {
	if isSSE(req) || isUpgrade(req) {
		return true
	}
	if resp == nil {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/event-stream") || strings.Contains(ct, "grpc")
}

func hopHeader(k string) bool {
	switch strings.ToLower(k) {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding",
		"upgrade", "te", "trailer", "proxy-authenticate", "proxy-authorization":
		return true
	default:
		return false
	}
}

func copyH2Resp(w http.ResponseWriter, resp *http.Response, stream bool) {
	if resp == nil {
		http.Error(w, "empty response", 502)
		return
	}
	for k, vv := range resp.Header {
		if hopHeader(k) {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	st := resp.StatusCode
	if st < 100 || st > 599 {
		st = 502
	}
	w.WriteHeader(st)
	if resp.Body == nil {
		return
	}
	if stream {
		buf := make([]byte, 32*1024)
		fl, _ := w.(http.Flusher)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				if fl != nil {
					fl.Flush()
				}
			}
			if err != nil {
				break
			}
		}
		return
	}
	_, _ = io.Copy(w, resp.Body)
}

func negotiatedALPN(c net.Conn) string {
	switch t := c.(type) {
	case *tls.Conn:
		return t.ConnectionState().NegotiatedProtocol
	case *utls.UConn:
		return t.ConnectionState().NegotiatedProtocol
	default:
		return ""
	}
}
