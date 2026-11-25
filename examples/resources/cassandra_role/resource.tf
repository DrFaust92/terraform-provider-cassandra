resource "cassandra_role" "app" {
  name     = "app_user"
  password = var.app_password # 40 to 512 characters
}
