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
	if n < 0 || n > 1<<16-1 {
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
	if len(hello) >= 5 {
		fp := &utls.Fingerprinter{AllowBluntMimicry: true}
		spec, _ = fp.FingerprintClientHello(hello)
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
	req.RequestURI = ""
	if req.URL != nil {
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}
		if req.URL.Host == "" && req.Host != "" {
			req.URL.Host = req.Host
		}
	}
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
	if resp.Uncompressed {
		resp.Header.Del("Content-Encoding")
		resp.Uncompressed = false
	}
	return resp.Write(w)
}

func (e *Engine) h2Server(client *tls.Conn, host, dst string, hello []byte) {
	up, err := e.dialUpstream(dst, host, true, hello)
	if err != nil {
		return
	}
	defer up.Close()
	var h2c *http2.ClientConn
	if negotiatedALPN(up) == "h2" {
		tr := &http2.Transport{}
		h2c, err = tr.NewClientConn(up)
		if err != nil {
			h2c = nil
		}
	}
	srv := &http2.Server{}
	srv.ServeConn(client, &http2.ServeConnOpts{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if host == "" {
				host = stripPort(req.Host)
			}
			var mock *http.Response
			if e.d != nil {
				mock = e.d.OnRequest(host, req)
			}
			reqSnip, reqN, reqTr, reqRest := peekBody(req.Body, e.maxBody)
			req.Body = reqRest
			if mock != nil {
				resSnip, resN, resTr, resRest := peekBody(mock.Body, e.maxBody)
				mock.Body = resRest
				copyH2Resp(w, mock)
				e.emit(host, req, mock.StatusCode, reqN, resN, true, reqSnip, resSnip, reqTr, resTr)
				return
			}
			var resp *http.Response
			if h2c != nil {
				if req.URL != nil {
					if req.URL.Scheme == "" {
						req.URL.Scheme = "https"
					}
					if req.URL.Host == "" {
						req.URL.Host = req.Host
					}
				}
				req.RequestURI = ""
				resp, err = h2c.RoundTrip(req)
			} else {
				resp, err = e.writeHTTP(up, req)
			}
			if err != nil || resp == nil {
				http.Error(w, "upstream dial failed", 502)
				e.emit(host, req, 502, reqN, 0, false, reqSnip, nil, reqTr, false)
				return
			}
			defer resp.Body.Close()
			resSnip, peeked, resTr, resRest := peekBody(resp.Body, e.maxBody)
			resp.Body = resRest
			resN := resp.ContentLength
			if resN < 0 {
				resN = peeked
			}
			copyH2Resp(w, resp)
			e.emit(host, req, resp.StatusCode, reqN, resN, false, reqSnip, resSnip, reqTr, resTr)
		}),
	})
}

func copyH2Resp(w http.ResponseWriter, resp *http.Response) {
	for k, vv := range resp.Header {
		if strings.EqualFold(k, "Connection") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		io.Copy(w, resp.Body)
	}
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
