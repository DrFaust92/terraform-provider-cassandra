// Command certgen writes a throwaway CA and the server and client certificates
// used by the TLS acceptance tests:
//
//	ca.pem                  CA certificate (Cassandra truststore, provider root_ca)
//	server.pem              server private key and certificate (Cassandra keystore)
//	client.pem, client-key.pem  client certificate and key (provider client_certificate/client_key)
//
// Usage: go run ./tests/certgen <dir>
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: certgen <dir>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "terraform-provider-cassandra test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		return err
	}

	issue := func(serial int64, cn string, usage x509.ExtKeyUsage) (certPEM, keyPEM []byte, err error) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(serial),
			Subject:      pkix.Name{CommonName: cn},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(7 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{usage},
			DNSNames:     []string{"localhost"},
			IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			return nil, nil, err
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, nil, err
		}
		return pemBlock("CERTIFICATE", der), pemBlock("PRIVATE KEY", keyDER), nil
	}

	serverCert, serverKey, err := issue(2, "localhost", x509.ExtKeyUsageServerAuth)
	if err != nil {
		return err
	}
	clientCert, clientKey, err := issue(3, "terraform", x509.ExtKeyUsageClientAuth)
	if err != nil {
		return err
	}

	// Cassandra runs as another user in its container, so the files are world-readable.
	files := map[string][]byte{
		"ca.pem":         pemBlock("CERTIFICATE", caDER),
		"server.pem":     append(serverKey, serverCert...),
		"client.pem":     clientCert,
		"client-key.pem": clientKey,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func pemBlock(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
