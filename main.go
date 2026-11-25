package main

// Format the examples and generate the docs/ directory.
//go:generate terraform fmt -recursive ./examples/
//go:generate go tool tfplugindocs generate --provider-name cassandra

import (
	"context"
	"flag"
	"log"

	"github.com/bartoszj/terraform-provider-cassandra/cassandra"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

// version is set by goreleaser.
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers like delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), cassandra.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/DrFaust92/cassandra",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err.Error())
	}
}
