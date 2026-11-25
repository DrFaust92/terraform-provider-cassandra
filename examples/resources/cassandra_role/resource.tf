resource "cassandra_role" "app" {
  name     = "app_user"
  password = var.app_password # 40 to 512 characters
}

# Keep the password out of state (Terraform 1.11+). Bump
# password_wo_version to apply a new password_wo.
resource "cassandra_role" "app_wo" {
  name                = "app_user_wo"
  password_wo         = var.app_password
  password_wo_version = "1"
}
