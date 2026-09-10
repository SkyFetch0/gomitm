package gomitm

import (
	"bytes"
	"io"
	"testing"
)

func TestPeekBodyTruncates(t *testing.T) {
	r := io.NopCloser(bytes.NewReader(bytes.Repeat([]byte("a"), 100)))
	snip, n, trunc, wrapped := peekBody(r, 16)
	if !trunc || len(snip) != 16 {
		t.Fatalf("snip=%d trunc=%v n=%d", len(snip), trunc, n)
	}
	all, _ := io.ReadAll(wrapped)
	if len(all) != 100 {
		t.Fatalf("forwarded %d", len(all))
	}
}

func TestPeekBodySmall(t *testing.T) {
	r := io.NopCloser(bytes.NewReader([]byte("ok")))
	snip, _, trunc, _ := peekBody(r, 64)
	if trunc || string(snip) != "ok" {
		t.Fatalf("%q trunc=%v", snip, trunc)
	}
}
