package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/elazarl/goproxy"
)

// caStore holds the MITM CA and caches per-hostname leaf certificates. It
// implements goproxy.CertStorage so the explicit proxy reuses generated
// certificates, and it is also used directly by the transparent HTTPS path.
type caStore struct {
	ca tls.Certificate
	mu sync.Mutex
	m  map[string]*tls.Certificate
}

func newCAStore(ca tls.Certificate) *caStore {
	return &caStore{ca: ca, m: make(map[string]*tls.Certificate)}
}

// Fetch satisfies goproxy.CertStorage.
func (s *caStore) Fetch(hostname string, gen func() (*tls.Certificate, error)) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.m[hostname]; ok {
		return c, nil
	}
	c, err := gen()
	if err != nil {
		return nil, err
	}
	s.m[hostname] = c
	return c, nil
}

// tlsConfig returns a server-side tls.Config for MITM-ing the given hostname,
// offering HTTP/2 and HTTP/1.1 so browsers can keep using HTTP/2 multiplexing.
func (s *caStore) tlsConfig(host string) (*tls.Config, error) {
	cert, err := s.Fetch(host, func() (*tls.Certificate, error) {
		return generateLeaf(s.ca, host)
	})
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// generateLeaf signs a short-lived ECDSA leaf certificate for host with the CA.
func generateLeaf(ca tls.Certificate, host string) (*tls.Certificate, error) {
	caCert, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, err
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	ski := sha1.Sum(pubDER)

	tmpl := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        pkix.Name{CommonName: host},
		DNSNames:       []string{host},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(825 * 24 * time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		SubjectKeyId:   ski[:],
		AuthorityKeyId: caCert.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &priv.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

// generateCA creates a unique, self-signed CA certificate and key in PEM form.
func generateCA() (certPEM, keyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	ski := sha1.Sum(pubDER)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "flow-local CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		SubjectKeyId:          ski[:],
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// loadCA loads a custom CA from PEM files, or falls back to goproxy's embedded
// CA when the files are absent. It returns the CA and whether a custom CA was
// actually loaded.
func loadCA(certFile, keyFile string) (tls.Certificate, bool) {
	if certFile != "" && keyFile != "" {
		if cert, err := tls.LoadX509KeyPair(certFile, keyFile); err == nil {
			return cert, true
		}
	}
	// Fallback: goproxy's embedded CA. Its private key is public, so this is
	// only for quick testing; gen-ca.sh should be used in real deployments.
	return goproxy.GoproxyCa, false
}

// exportCA writes the CA certificate (PEM) to path.
func exportCA(ca tls.Certificate, path string) error {
	block := pem.Block{Type: "CERTIFICATE", Bytes: ca.Certificate[0]}
	data := pem.EncodeToMemory(&block)
	return os.WriteFile(path, data, 0o644)
}
