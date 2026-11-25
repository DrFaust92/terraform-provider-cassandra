package cassandra

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/types"
)

// selfSignedPEM returns a self-signed certificate and its key, PEM-encoded.
func selfSignedPEM(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
}

// The TLS settings can come from the CASSANDRA_* environment variables.
func TestClusterConfig_tlsEnv(t *testing.T) {
	certPEM, keyPEM := selfSignedPEM(t)
	t.Setenv("CASSANDRA_USE_SSL", "true")
	t.Setenv("CASSANDRA_ROOT_CA", certPEM)
	t.Setenv("CASSANDRA_CLIENT_CERTIFICATE", certPEM)
	t.Setenv("CASSANDRA_CLIENT_KEY", keyPEM)

	cluster, err := clusterConfig(context.Background(), providerModel{
		Host:  types.StringValue("127.0.0.1"),
		Hosts: types.ListNull(types.StringType),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cluster.SslOpts == nil {
		t.Fatal("CASSANDRA_USE_SSL=true did not enable TLS")
	}
	if cluster.SslOpts.RootCAs == nil {
		t.Fatal("CASSANDRA_ROOT_CA was not used")
	}
	if len(cluster.SslOpts.Certificates) != 1 {
		t.Fatal("CASSANDRA_CLIENT_CERTIFICATE and CASSANDRA_CLIENT_KEY were not used")
	}

	// Configuration takes precedence: use_ssl = false disables TLS.
	cluster, err = clusterConfig(context.Background(), providerModel{
		Host:   types.StringValue("127.0.0.1"),
		Hosts:  types.ListNull(types.StringType),
		UseSSL: types.BoolValue(false),
	})
	if err != nil {
		t.Fatal(err)
	}
	if cluster.SslOpts != nil {
		t.Fatal("use_ssl = false: TLS enabled from the environment")
	}

	t.Setenv("CASSANDRA_ROOT_CA", "not a certificate")
	if _, err := clusterConfig(context.Background(), providerModel{
		Host:  types.StringValue("127.0.0.1"),
		Hosts: types.ListNull(types.StringType),
	}); err == nil {
		t.Fatal("expected an error for an invalid CASSANDRA_ROOT_CA")
	}
}
