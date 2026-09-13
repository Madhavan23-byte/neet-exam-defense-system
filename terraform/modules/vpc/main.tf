terraform {
  required_version = ">= 1.5.0, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

# Dynamically discover available AZs in target region
data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  # Dynamically select the first two available AZs in the target AWS account
  selected_azs = slice(data.aws_availability_zones.available.names, 0, 2)
}

# Dedicated VPC for B-SEA
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc-${var.environment}"
  }
}

# Internet Gateway for Public Subnets
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw-${var.environment}"
  }
}

# ── Public Subnets (ALB & NAT Gateway only) ─────────────────────────────────
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone       = local.selected_azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet-${count.index + 1}-${var.environment}"
    Tier = "Public"
  }
}

# ── Private Application Subnets (ECS Fargate Tasks) ──────────────────────────
resource "aws_subnet" "private_app" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index + 2)
  availability_zone       = local.selected_azs[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-private-app-subnet-${count.index + 1}-${var.environment}"
    Tier = "Private-App"
  }
}

# ── Isolated Database Subnets (RDS, RDS Proxy, ElastiCache) ───────────────────
resource "aws_subnet" "database" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 4, count.index + 4)
  availability_zone       = local.selected_azs[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${var.project_name}-database-subnet-${count.index + 1}-${var.environment}"
    Tier = "Database"
  }
}

# ── NAT Gateway (Staging Cost Control: Single NAT in AZ 1) ───────────────────
# NOTE: Single NAT Gateway is a STAGING-ONLY cost optimization (~$65/mo savings).
# Production requires Multi-AZ NAT Gateways (one per AZ) for HA egress.
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-nat-eip-${var.environment}"
  }
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.project_name}-nat-${var.environment}"
  }

  depends_on = [aws_internet_gateway.gw]
}

# ── Route Tables ─────────────────────────────────────────────────────────────

# 1. Public Route Table (0.0.0.0/0 -> IGW)
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }

  tags = {
    Name = "${var.project_name}-public-rt-${var.environment}"
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# 2. Private App Route Table (0.0.0.0/0 -> NAT Gateway)
resource "aws_route_table" "private_app" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "${var.project_name}-private-app-rt-${var.environment}"
  }
}

resource "aws_route_table_association" "private_app" {
  count          = 2
  subnet_id      = aws_subnet.private_app[count.index].id
  route_table_id = aws_route_table.private_app.id
}

# 3. Database Route Table (NO Internet Route — Isolated)
resource "aws_route_table" "database" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-database-rt-${var.environment}"
  }
}

resource "aws_route_table_association" "database" {
  count          = 2
  subnet_id      = aws_subnet.database[count.index].id
  route_table_id = aws_route_table.database.id
}
