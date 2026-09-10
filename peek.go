package gomitm

import (
	"bufio"
	"bytes"
	"encoding/binary"
)

// IsTLS reports whether the next bytes look like a TLS record (handshake).
func IsTLS(br *bufio.Reader) bool {
	b, err := br.Peek(3)
	if err != nil || len(b) < 3 {
		return false
	}
	return b[0] == 0x16 && b[1] == 0x03 && b[2] <= 0x04
}

// PeekSNI extracts the SNI hostname from a TLS ClientHello without consuming bytes.
func PeekSNI(br *bufio.Reader) string {
	n := br.Buffered()
	if n < 5 {
		n = 16384
	}
	b, err := br.Peek(n)
	if err != nil && len(b) < 5 {
		b, err = br.Peek(5)
		if err != nil {
			return ""
		}
	}
	return parseSNI(b)
}

func parseSNI(data []byte) string {
	if len(data) < 5 || data[0] != 0x16 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(data[3:5]))
	need := 5 + recLen
	if len(data) < need {
		need = len(data)
	}
	p := data[5:need]
	if len(p) < 4 || p[0] != 0x01 { // handshake type client_hello
		return ""
	}
	hsLen := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	p = p[4:]
	if hsLen > len(p) {
		hsLen = len(p)
	}
	p = p[:hsLen]
	if len(p) < 34 {
		return ""
	}
	p = p[34:] // version + random
	if len(p) < 1 {
		return ""
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen+2 {
		return ""
	}
	p = p[sidLen:]
	csLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if len(p) < csLen+1 {
		return ""
	}
	p = p[csLen:]
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen+2 {
		return ""
	}
	p = p[cmLen:]
	extLen := int(binary.BigEndian.Uint16(p[:2]))
	p = p[2:]
	if extLen > len(p) {
		extLen = len(p)
	}
	p = p[:extLen]
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p[:2])
		l := int(binary.BigEndian.Uint16(p[2:4]))
		p = p[4:]
		if l > len(p) {
			return ""
		}
		if typ == 0x0000 { // server_name
			return parseServerName(p[:l])
		}
		p = p[l:]
	}
	return ""
}

func parseServerName(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	listLen := int(binary.BigEndian.Uint16(b[:2]))
	b = b[2:]
	if listLen > len(b) {
		listLen = len(b)
	}
	b = b[:listLen]
	for len(b) >= 3 {
		nameType := b[0]
		nl := int(binary.BigEndian.Uint16(b[1:3]))
		b = b[3:]
		if nl > len(b) {
			return ""
		}
		if nameType == 0 {
			return string(b[:nl])
		}
		b = b[nl:]
	}
	return ""
}

// PeekHTTPHost reads Host from a plaintext HTTP request without consuming bytes.
func PeekHTTPHost(br *bufio.Reader) string {
	b, err := br.Peek(4096)
	if err != nil && len(b) == 0 {
		return ""
	}
	idx := bytes.Index(b, []byte("\r\n\r\n"))
	head := b
	if idx >= 0 {
		head = b[:idx]
	}
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		if len(line) >= 5 && bytes.EqualFold(line[:5], []byte("Host:")) {
			return string(bytes.TrimSpace(line[5:]))
		}
	}
	return ""
}
