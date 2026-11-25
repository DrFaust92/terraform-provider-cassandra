package cassandra

import (
	"context"
	"log"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

var (
	testAccProviderFactories map[string]func() (*schema.Provider, error)
	testAccProvider          *schema.Provider
)

func init() {
	testAccProvider = Provider()
	testAccProviderFactories = map[string]func() (*schema.Provider, error){
		"cassandra": func() (*schema.Provider, error) {
			log.Printf("testAccProviderFactories: 1")
			return testAccProvider, nil
		},
	}
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	_ = Provider()
}

func TestProvider_configure1(t *testing.T) {
	rc := terraform.NewResourceConfigRaw(map[string]interface{}{
		"username": "cassanrda",
		"password": "cassanrda",
		"port":     9042,
		"host":     "asdf",
	})
	p := Provider()
	v := p.Validate(rc)
	if v.HasError() {
		t.Fatal("Error during parsing")
	}
	err := p.Configure(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
}

func TestProvider_configure2(t *testing.T) {
	rc := terraform.NewResourceConfigRaw(map[string]interface{}{
		"username": "cassanrda",
		"password": "cassanrda",
		"port":     9042,
		"hosts":    []interface{}{"asd"},
	})
	p := Provider()
	v := p.Validate(rc)
	if v.HasError() {
		t.Fatal("Error during parsing")
	}
	err := p.Configure(context.Background(), rc)
	if err != nil {
		t.Fatal(err)
	}
}

func testAccPreCheck(t *testing.T) {
	url := os.Getenv("CASSANDRA_HOST")
	if url == "" {
		t.Fatal("CASSANDRA_HOST must be set for acceptance tests")
	}

	err := testAccProvider.Configure(context.Background(), terraform.NewResourceConfigRaw(nil))
	if err != nil {
		t.Fatal(err)
	}
}
