resource "aws_security_group" "alb" {
  name        = "${local.name}-alb"
  description = "Public HTTP/HTTPS entry point"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.name}-alb" }
}

resource "aws_security_group" "app" {
  name        = "${local.name}-app"
  description = "Frontend and backend instance"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.name}-app" }
}

resource "aws_security_group" "rds" {
  name        = "${local.name}-rds"
  description = "PostgreSQL"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.name}-rds" }
}

resource "aws_security_group" "memorydb" {
  name        = "${local.name}-memorydb"
  description = "MemoryDB"
  vpc_id      = aws_vpc.main.id
  tags        = { Name = "${local.name}-memorydb" }
}

# ALB: HTTP/HTTPS from anywhere, forwards only to the app ports.
resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP (redirected to HTTPS)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTPS"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_frontend" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To Next.js"
  ip_protocol                  = "tcp"
  from_port                    = 3000
  to_port                      = 3000
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_vpc_security_group_egress_rule" "alb_to_backend" {
  security_group_id            = aws_security_group.alb.id
  description                  = "To Spring Boot"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.app.id
}

# App instance: reachable only from the ALB. No SSH; use SSM Session Manager.
resource "aws_vpc_security_group_ingress_rule" "app_frontend" {
  security_group_id            = aws_security_group.app.id
  description                  = "Next.js from ALB"
  ip_protocol                  = "tcp"
  from_port                    = 3000
  to_port                      = 3000
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_ingress_rule" "app_backend" {
  security_group_id            = aws_security_group.app.id
  description                  = "Spring Boot from ALB"
  ip_protocol                  = "tcp"
  from_port                    = 8080
  to_port                      = 8080
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "app_https" {
  security_group_id = aws_security_group.app.id
  description       = "HTTPS: SSM, package repos, npm, Maven Central, GitHub API, the public ALB URL"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "app_http" {
  security_group_id = aws_security_group.app.id
  description       = "HTTP: package repository mirrors"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "app_git_ssh" {
  security_group_id = aws_security_group.app.id
  description       = "git over SSH to GitHub"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "app_smtp" {
  security_group_id = aws_security_group.app.id
  description       = "SMTP submission (STARTTLS)"
  ip_protocol       = "tcp"
  from_port         = var.smtp_port
  to_port           = var.smtp_port
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "app_to_rds" {
  security_group_id            = aws_security_group.app.id
  description                  = "PostgreSQL"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.rds.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_memorydb" {
  security_group_id            = aws_security_group.app.id
  description                  = "MemoryDB"
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = aws_security_group.memorydb.id
}

resource "aws_vpc_security_group_ingress_rule" "rds_from_app" {
  security_group_id            = aws_security_group.rds.id
  description                  = "PostgreSQL from the app instance"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.app.id
}

resource "aws_vpc_security_group_ingress_rule" "memorydb_from_app" {
  security_group_id            = aws_security_group.memorydb.id
  description                  = "MemoryDB from the app instance"
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = aws_security_group.app.id
}
