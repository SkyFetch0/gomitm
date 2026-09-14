package gomitm

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const maxOriginDump = 512

var (
	originDumpDir string
	originDumpMu  sync.Mutex
	originDumped  = map[string]struct{}{}
)

func SetOriginDumpDir(dir string) {
	originDumpDir = dir
}

func OriginDumpDir() string {
	return originDumpDir
}

func dumpOriginChain(host, dst string, verify bool) {
	_ = DumpOriginChain(host, dst, false, verify)
}

// DumpOriginChain writes originDumpDir/<host>.pem (leaf + intermediates).
func DumpOriginChain(host, dst string, force bool, verify ...bool) error {
	v := false
	if len(verify) > 0 {
		v = verify[0]
	}
	if originDumpDir == "" || host == "" {
		return fmt.Errorf("origin dump dir or host empty")
	}
	originDumpMu.Lock()
	if !force {
		if _, ok := originDumped[host]; ok {
			originDumpMu.Unlock()
			return nil
		}
	}
	if len(originDumped) >= maxOriginDump {
		originDumped = map[string]struct{}{}
	}
	originDumpMu.Unlock()

	if dst == "" {
		dst = net.JoinHostPort(host, "443")
	}
	raw, err := net.DialTimeout("tcp", dst, 15*time.Second)
	if err != nil {
		return err
	}
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, InsecureSkipVerify: !v}
	t := tls.Client(raw, cfg)
	if err := t.Handshake(); err != nil {
		raw.Close()
		return err
	}
	st := t.ConnectionState()
	t.Close()
	raw.Close()
	if len(st.PeerCertificates) == 0 {
		return fmt.Errorf("no peer certificates")
	}
	if err := os.MkdirAll(originDumpDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(originDumpDir, host+".pem")
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	for _, c := range st.PeerCertificates {
		_ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	if err := f.Close(); err != nil {
		return err
	}
	originDumpMu.Lock()
	originDumped[host] = struct{}{}
	originDumpMu.Unlock()
	return nil
}
