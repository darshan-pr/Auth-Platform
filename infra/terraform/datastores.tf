resource "aws_db_subnet_group" "main" {
  name       = "${local.name}-db"
  subnet_ids = [aws_subnet.data_a.id, aws_subnet.data_b.id]
}

resource "aws_db_parameter_group" "postgres" {
  name   = "${local.name}-postgres16"
  family = "postgres16"

  parameter {
    name         = "rds.force_ssl"
    value        = "1"
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "main" {
  identifier = "${local.name}-postgres"

  engine         = "postgres"
  engine_version = "16"
  instance_class = var.db_instance_class

  allocated_storage = var.db_allocated_storage_gb
  storage_type      = "gp3"
  storage_encrypted = true

  db_name  = "authplatform"
  username = "authplatform"
  password = random_password.db.result
  port     = 5432

  multi_az               = false
  availability_zone      = var.az
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false
  parameter_group_name   = aws_db_parameter_group.postgres.name

  backup_retention_period    = 7
  backup_window              = "21:00-22:00"
  maintenance_window         = "sun:22:30-sun:23:30"
  auto_minor_version_upgrade = true
  copy_tags_to_snapshot      = true

  deletion_protection       = var.deletion_protection
  skip_final_snapshot       = false
  final_snapshot_identifier = "${local.name}-postgres-final"

  lifecycle {
    ignore_changes = [engine_version]
  }
}

resource "aws_memorydb_subnet_group" "main" {
  name       = "${local.name}-memorydb"
  subnet_ids = [aws_subnet.data_a.id]
}

resource "aws_memorydb_user" "app" {
  user_name     = "authplatform"
  access_string = "on ~* &* +@all"

  authentication_mode {
    type      = "password"
    passwords = [random_password.redis.result]
  }
}

resource "aws_memorydb_acl" "main" {
  name       = "${local.name}-acl"
  user_names = [aws_memorydb_user.app.user_name]
}

resource "aws_memorydb_cluster" "main" {
  name = "${local.name}-redis"

  engine                 = "valkey"
  engine_version         = "7.3"
  parameter_group_name   = "default.memorydb-valkey7"
  node_type              = var.memorydb_node_type
  num_shards             = 1
  num_replicas_per_shard = 0

  acl_name           = aws_memorydb_acl.main.name
  subnet_group_name  = aws_memorydb_subnet_group.main.name
  security_group_ids = [aws_security_group.memorydb.id]
  port               = 6379
  tls_enabled        = true

  snapshot_retention_limit   = 1
  snapshot_window            = "20:00-21:00"
  maintenance_window         = "sun:23:30-mon:00:30"
  auto_minor_version_upgrade = true
}
