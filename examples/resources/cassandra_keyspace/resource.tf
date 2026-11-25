resource "cassandra_keyspace" "simple" {
  name                 = "app"
  replication_strategy = "SimpleStrategy"
  strategy_options = {
    replication_factor = 1
  }
}

resource "cassandra_keyspace" "multi_dc" {
  name                 = "app_multi_dc"
  replication_strategy = "NetworkTopologyStrategy"
  strategy_options = {
    dc1 = 3
    dc2 = 3
  }
}
