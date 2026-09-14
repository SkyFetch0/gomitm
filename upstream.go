package gomitm

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"net"
	"net/http"
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
