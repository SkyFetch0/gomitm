package gomitm

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CertManager holds a root CA and caches leaf certs issued on the fly.
type CertManager struct {
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
	leafMu sync.Mutex
	leafs  map[string]*tls.Certificate
}

// LoadOrCreateCA loads PEM files from dir or creates a new CA.
func LoadOrCreateCA(dir string) (*CertManager, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	certPath := filepath.Join(dir, "ca-cert.pem")
	keyPath := filepath.Join(dir, "ca-key.pem")
	m := &CertManager{leafs: make(map[string]*tls.Certificate)}
	if _, err := os.Stat(certPath); err == nil {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			return nil, err
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode(certPEM)
		if block == nil {
			return nil, fmt.Errorf("gomitm: invalid CA cert PEM")
		}
		m.caCert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		kblock, _ := pem.Decode(keyPEM)
		if kblock == nil {
			return nil, fmt.Errorf("gomitm: invalid CA key PEM")
		}
		key, err := x509.ParseECPrivateKey(kblock.Bytes)
		if err != nil {
			return nil, err
		}
		m.caKey = key
		return m, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "SkyTap Root CA", Organization: []string{"SkyTap"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	m.caCert, m.caKey = cert, key
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	return m, nil
}

// CACertPEM returns the root CA certificate for trust stores.
func (m *CertManager) CACertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.caCert.Raw})
}

// ServerConfig returns a tls.Config that mints leaf certs via GetCertificate.
func (m *CertManager) ServerConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := chi.ServerName
			if name == "" {
				name = "localhost"
			}
			return m.leaf(name)
		},
		MinVersion: tls.VersionTLS12,
	}
}

func (m *CertManager) leaf(host string) (*tls.Certificate, error) {
	m.leafMu.Lock()
	defer m.leafMu.Unlock()
	if c, ok := m.leafs[host]; ok {
		return c, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour * 90),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
		tmpl.DNSNames = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, m.caCert, &key.PublicKey, m.caKey)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{
		Certificate: [][]byte{der, m.caCert.Raw},
		PrivateKey:  key,
	}
	m.leafs[host] = leaf
	return leaf, nil
}
