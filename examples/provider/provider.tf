terraform {
  required_providers {
    cassandra = {
      source  = "DrFaust92/cassandra"
      version = "~> 1.2"
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
