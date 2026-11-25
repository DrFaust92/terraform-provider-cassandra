# Cassandra Provider

It will provide the following features with respect to CQL 3.0.0 spec
- Manage Keyspace(s)
- Manage Role(s)
- Managing Grants

## Example Usage

Terraform 0.13 and later:

```hcl
terraform {
  required_providers {
    cassandra = {
      source  = "DrFaust92/cassandra"
      version = "~> 1.0"
    }
  }
}

provider "cassandra" {
  username = "cluster_username"
  password = "cluster_password"
  port     = 9042
  host     = "localhost"
}

resource "cassandra_keyspace" "keyspace" {
  name                 = "some_keyspace_name"
  replication_strategy = "SimpleStrategy"
  strategy_options     = {
    replication_factor = 1
  }
}
```

Terraform 0.12 and earlier:

```hcl
provider "cassandra" {
  username = "cluster_username"
  password = "cluster_password"
  port     = 9042
  host     = "localhost"
}

resource "cassandra_keyspace" "keyspace" {
  name                 = "some_keyspace_name"
  replication_strategy = "SimpleStrategy"
  strategy_options     = {
    replication_factor = 1
  }
}
```

## Argument Reference

- `username` - Cassandra client username. Default `CASSANDRA_USERNAME` environment variable.

- `password` - Cassandra client password. Default `CASSANDRA_PASSWORD` environment variable.

- `port` - Cassandra client port. Default `CASSANDRA_PORT` environment variable, default value is __9042__. 

- `host` - Host pointing to node in the cassandra cluster. Default `CASSANDRA_HOST` environment variable.

- `hosts` - Array of hosts pointing to nodes in the cassandra cluster.

- `host_filter` - Filter all incoming events for a host. Hosts have to existing before using this provider.

- `connection_timeout` - Connection timeout to the cluster in milliseconds. Default value is __1000__.

- `root_ca` - Optional value, only used if you are connecting to cluster using certificates.

- `use_ssl` - Optional value, it is __false__ by default. Only turned on when connecting to cluster with ssl.

- `min_tls_version` - Default value is __TLS1.2__. It is only applicable when use_ssl is __true__.

- `protocol_version` - The cql protocol binary version. Defaults to __4__.
