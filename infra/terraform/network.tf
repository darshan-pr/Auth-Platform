resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = local.name }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = local.name }
}

# Public subnets: the ALB (both) and the EC2 instance (AZ a only).
resource "aws_subnet" "public_a" {
  vpc_id                  = aws_vpc.main.id
  availability_zone       = var.az
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 0)
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-public-a" }
}

resource "aws_subnet" "public_b" {
  vpc_id                  = aws_vpc.main.id
  availability_zone       = var.secondary_az
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, 1)
  map_public_ip_on_launch = false
  tags                    = { Name = "${local.name}-public-b-alb-only" }
}

# Data subnets: no route to the internet. RDS and MemoryDB live in AZ a.
resource "aws_subnet" "data_a" {
  vpc_id            = aws_vpc.main.id
  availability_zone = var.az
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 10)
  tags              = { Name = "${local.name}-data-a" }
}

resource "aws_subnet" "data_b" {
  vpc_id            = aws_vpc.main.id
  availability_zone = var.secondary_az
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, 11)
  tags              = { Name = "${local.name}-data-b-rds-subnet-group-only" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name}-public" }

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table" "data" {
  vpc_id = aws_vpc.main.id
  tags   = { Name = "${local.name}-data" }
}

resource "aws_route_table_association" "public_a" {
  subnet_id      = aws_subnet.public_a.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "public_b" {
  subnet_id      = aws_subnet.public_b.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "data_a" {
  subnet_id      = aws_subnet.data_a.id
  route_table_id = aws_route_table.data.id
}

resource "aws_route_table_association" "data_b" {
  subnet_id      = aws_subnet.data_b.id
  route_table_id = aws_route_table.data.id
}
