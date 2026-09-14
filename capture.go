package gomitm

import (
	"bytes"
	"io"
)

const DefaultMaxBody = 64 << 10 // 64 KiB; OBSERVED/passthrough never captures

type bodyCloser struct {
	io.Reader
	c io.Closer
}

func (b bodyCloser) Close() error {
	if b.c == nil {
		return nil
	}
	return b.c.Close()
}

// peekBody reads at most max+1 bytes so we can set Truncated, then restores
// the full stream for forwarding (prefix + remainder). Does not buffer the rest.
func peekBody(r io.ReadCloser, max int64) (snippet []byte, sizeHint int64, trunc bool, wrapped io.ReadCloser) {
	if r == nil {
		return nil, 0, false, nil
	}
	if max <= 0 {
		max = DefaultMaxBody
	}
	pref, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil && len(pref) == 0 {
		return nil, 0, false, r
	}
	trunc = int64(len(pref)) > max
	snippet = pref
	if trunc {
		snippet = append([]byte(nil), pref[:max]...)
	} else {
		snippet = append([]byte(nil), pref...)
	}
	hint := int64(len(pref))
	if trunc {
		hint = max
	}
	return snippet, hint, trunc, bodyCloser{Reader: io.MultiReader(bytes.NewReader(pref), r), c: r}
}
