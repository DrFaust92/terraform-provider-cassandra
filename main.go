package main

// Format the examples and generate the docs/ directory.
//go:generate terraform fmt -recursive ./examples/
//go:generate go tool tfplugindocs generate --provider-name cassandra

import (
	"github.com/bartoszj/terraform-provider-cassandra/cassandra"
	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{ProviderFunc: cassandra.Provider})
}
