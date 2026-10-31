terraform {
  required_version = ">= 1.9"

  required_providers {
    aws    = { source = "hashicorp/aws", version = "~> 6.0" }
    random = { source = "hashicorp/random", version = "~> 3.6" }
    tls    = { source = "hashicorp/tls", version = "~> 4.0" }
  }
}

provider "aws" {
  region              = var.region
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = {
      Project     = "authplatform"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

locals {
  name       = "${var.name_prefix}-${var.environment}"
  ssm_prefix = "/${var.name_prefix}/${var.environment}"
  app_url    = "https://${var.domain_name}"
}
