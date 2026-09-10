package gomitm

import (
	"bufio"
	"net"
	"time"
)

// bufConn reads from a bufio.Reader (preserving peeked bytes) and writes to the underlying conn.
type bufConn struct {
	r *bufio.Reader
	c net.Conn
}

func (b *bufConn) Read(p []byte) (int, error)         { return b.r.Read(p) }
func (b *bufConn) Write(p []byte) (int, error)        { return b.c.Write(p) }
func (b *bufConn) Close() error                       { return b.c.Close() }
func (b *bufConn) LocalAddr() net.Addr                { return b.c.LocalAddr() }
func (b *bufConn) RemoteAddr() net.Addr               { return b.c.RemoteAddr() }
func (b *bufConn) SetDeadline(t time.Time) error      { return b.c.SetDeadline(t) }
func (b *bufConn) SetReadDeadline(t time.Time) error  { return b.c.SetReadDeadline(t) }
func (b *bufConn) SetWriteDeadline(t time.Time) error { return b.c.SetWriteDeadline(t) }
