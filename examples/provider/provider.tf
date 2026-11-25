terraform {
  required_providers {
    cassandra = {
      source  = "DrFaust92/cassandra"
      version = "~> 2.0"
    }
  }
}

# Credentials and host can also come from the CASSANDRA_USERNAME,
# CASSANDRA_PASSWORD, CASSANDRA_HOST and CASSANDRA_PORT environment variables.
provider "cassandra" {
  username = "cluster_username"
  password = "cluster_password"
  host     = "localhost"
  port     = 9042
}

# A multi-DC cluster over TLS that requires client certificates. Queries go
# to the local data center; use the LOCAL_* consistency levels with it.
provider "cassandra" {
  alias              = "tls"
  hosts              = ["cassandra-1.dc1.internal", "cassandra-2.dc1.internal"]
  username           = "cluster_username"
  password           = "cluster_password"
  use_ssl            = true
  root_ca            = file("${path.module}/ca.pem")
  client_certificate = file("${path.module}/client.pem")
  client_key         = file("${path.module}/client-key.pem")
  local_dc           = "dc1"
  consistency        = "LOCAL_QUORUM"
  query_timeout      = 30000
}
