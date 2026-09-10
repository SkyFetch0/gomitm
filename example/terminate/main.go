// Example: MITM one accepted TCP connection with a trivial Decider.
// Terminate everything; mock GET /health; otherwise forward (needs orig dst).
package main

import (
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/SkyFetch0/gomitm"
)

type d struct{}

func (d) OnConnect(host, dst string) gomitm.Action { return gomitm.Terminate }

func (d) OnRequest(host string, req *http.Request) *http.Response {
	if req.URL.Path == "/health" {
		b := `{"ok":true}`
		return &http.Response{
			StatusCode:    200,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        http.Header{"Content-Type": []string{"application/json"}},
			Body:          io.NopCloser(strings.NewReader(b)),
			ContentLength: int64(len(b)),
		}
	}
	return nil
}

func (d) OnFlow(f gomitm.Flow) {
	log.Printf("%s %s %s -> %d mocked=%v", f.Host, f.Method, f.Path, f.Status, f.Mocked)
}

func main() {
	ca, err := gomitm.LoadOrCreateCA("ca")
	if err != nil {
		log.Fatal(err)
	}
	eng := gomitm.New(ca, d{})
	ln, err := net.Listen("tcp", "127.0.0.1:9443")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("explicit TLS listen %s (trust ca/ca-cert.pem)", ln.Addr())
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go eng.Handle(c, "", "", true)
	}
}
