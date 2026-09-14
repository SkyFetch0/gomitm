# gomitm

Go library: **MITM engine** with a local CA, on-the-fly leaf certificates, SNI / HTTP Host peek, and passthrough vs TLS terminate.

Does **not** import [skydst](https://github.com/SkyFetch0/skydst). You pass any `net.Conn` (transparent redirect, SOCKS, or a plain listen). Policy lives in your `Decider`. Used by [SkyTap](https://github.com/SkyFetch0/skytap).

Unlike an HTTP CONNECT proxy, this is the **transparent** half: the socket is already redirected; gomitm either splices or decrypts.

**License:** MIT · **Go:** 1.22+

```bash
go get github.com/SkyFetch0/gomitm@v0.1.0
```

---

## Quick start

```go
ca, err := gomitm.LoadOrCreateCA("./ca")
eng := gomitm.New(ca, myDecider{})
eng.Handle(conn, host, origDst, false)
```

```go
type Decider interface {
    OnConnect(host, dst string) Action                 // Passthrough or Terminate
    OnRequest(host string, req *http.Request) *http.Response // non-nil = mock; nil = forward (req may be mutated)
    OnFlow(f Flow)
}
```

| Action | |
|--------|--|
| `Passthrough` | Bidirectional `io.Copy`. No decrypt. |
| `Terminate` | `tls.Server`, then HTTP. `OnRequest` may short-circuit or rewrite the body and return `nil` to hit upstream. |

Peek helpers (`IsTLS`, `PeekSNI`, `PeekHTTPHost`) use `bufio.Peek` so ClientHello bytes are not consumed.

Body snippets on `Flow` are filled **only** on the terminate path (64 KiB cap + truncated flags). Passthrough does not buffer.

Example: [`example/terminate`](example/terminate).

---

## Trust

Install `CACertPEM()` in the **client** that will see terminated TLS. A host trust store is not inherited by containers.

---

## API

```go
func New(ca *CertManager, d Decider) *Engine
func (e *Engine) WithMaxBody(n int64) *Engine
func (e *Engine) Handle(conn net.Conn, host, dst string, isTLS bool)

func LoadOrCreateCA(dir string) (*CertManager, error)
func (m *CertManager) CACertPEM() []byte
func (m *CertManager) ServerConfig() *tls.Config

func IsTLS(br *bufio.Reader) bool
func PeekSNI(br *bufio.Reader) string
func PeekHTTPHost(br *bufio.Reader) string

const DefaultMaxBody = 64 << 10
```

v0.1: do not change this method set without a new major version. Adding fields to `Flow` is allowed.
