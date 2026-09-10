package gomitm

import (
	"net/http"
	"time"
)

// Action is the connection-level decision returned by Decider.OnConnect.
type Action int

const (
	Passthrough Action = iota // splice with io.Copy; do not decrypt
	Terminate                 // TLS terminate, then OnRequest per HTTP request
)

// Decider is implemented by the application (skytap). gomitm does not know domain states.
type Decider interface {
	OnConnect(host, dst string) Action
	OnRequest(host string, req *http.Request) *http.Response
	OnFlow(f Flow)
}

// Flow is metadata plus capped body snippets (terminate path only).
type Flow struct {
	Time               time.Time
	Host, Method, Path string
	Status             int
	ReqSize, ResSize   int64
	Mocked             bool
	ReqBody            []byte `json:"req_body,omitempty"`
	ResBody            []byte `json:"res_body,omitempty"`
	ReqTruncated       bool   `json:"req_truncated,omitempty"`
	ResTruncated       bool   `json:"res_truncated,omitempty"`
}
