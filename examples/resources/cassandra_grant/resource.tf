# Read access to every table in a keyspace.
resource "cassandra_grant" "read_app" {
  privilege     = "select"
  resource_type = "keyspace"
  keyspace_name = cassandra_keyspace.simple.name
  grantee       = cassandra_role.app.name
}

# Write access to a single table.
resource "cassandra_grant" "write_events" {
  privilege     = "modify"
  resource_type = "table"
  keyspace_name = cassandra_keyspace.simple.name
  table_name    = "events"
  grantee       = cassandra_role.app.name
}
