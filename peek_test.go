package gomitm

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPeekHTTPHost(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n"
	br := bufio.NewReader(bytes.NewReader([]byte(raw)))
	if g := PeekHTTPHost(br); g != "example.com" {
		t.Fatalf("got %q", g)
	}
	b, _ := br.Peek(3)
	if string(b) != "GET" {
		t.Fatalf("consumed bytes: %q", b)
	}
}

func TestParseSNI(t *testing.T) {
	// minimal ClientHello with SNI example.com
	hello := buildClientHello("example.com")
	if g := parseSNI(hello); g != "example.com" {
		t.Fatalf("got %q", g)
	}
}

func buildClientHello(sni string) []byte {
	ext := serverNameExt(sni)
	// client hello body: ver(2)+random(32)+sid_len(1)+cs_len(2)+cs(2)+cm_len(1)+cm(1)+ext_len(2)+ext
	var ch bytes.Buffer
	ch.Write([]byte{0x03, 0x03})
	ch.Write(make([]byte, 32))
	ch.WriteByte(0)
	binary.Write(&ch, binary.BigEndian, uint16(2))
	ch.Write([]byte{0x00, 0x2f})
	ch.WriteByte(1)
	ch.WriteByte(0)
	binary.Write(&ch, binary.BigEndian, uint16(len(ext)))
	ch.Write(ext)
	body := ch.Bytes()
	var hs bytes.Buffer
	hs.WriteByte(0x01)
	hs.WriteByte(byte(len(body) >> 16))
	hs.WriteByte(byte(len(body) >> 8))
	hs.WriteByte(byte(len(body)))
	hs.Write(body)
	rec := hs.Bytes()
	var out bytes.Buffer
	out.Write([]byte{0x16, 0x03, 0x01})
	binary.Write(&out, binary.BigEndian, uint16(len(rec)))
	out.Write(rec)
	return out.Bytes()
}

func serverNameExt(name string) []byte {
	var list bytes.Buffer
	list.WriteByte(0) // host_name
	binary.Write(&list, binary.BigEndian, uint16(len(name)))
	list.WriteString(name)
	inner := list.Bytes()
	var ext bytes.Buffer
	binary.Write(&ext, binary.BigEndian, uint16(0)) // type SNI
	payload := append([]byte{byte(len(inner) >> 8), byte(len(inner))}, inner...)
	binary.Write(&ext, binary.BigEndian, uint16(len(payload)))
	ext.Write(payload)
	return ext.Bytes()
}
