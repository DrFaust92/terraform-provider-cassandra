# Basic terraform provider for Apache Cassandra

It will provide the following features with respect to CQL 3.0.0 spec
- Manage Keyspace(s)
- Manage Role(s)
- Managing Grants

# Requirements

-	[Terraform](https://www.terraform.io/downloads.html) >= 1.0
-	[Go](https://golang.org/doc/install) >= 1.27 (see `go.mod`)
-	Apache Cassandra 4.1 or 5.0 (the versions the acceptance tests run against). 3.x and 4.0 are end of life and not tested

## [Documentation](docs/)
