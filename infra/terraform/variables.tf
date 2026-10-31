variable "region" {
  type    = string
  default = "eu-north-1"
}

variable "aws_account_id" {
  description = "Guard: Terraform refuses to run against any other AWS account."
  type        = string
}

variable "name_prefix" {
  type    = string
  default = "authplatform"
}

variable "environment" {
  type    = string
  default = "prod"
}

variable "domain_name" {
  description = "Public hostname for both the console UI and the /api backend, e.g. auth.example.com."
  type        = string
}

variable "az" {
  description = "The single Availability Zone that hosts EC2, RDS and MemoryDB."
  type        = string
  default     = "eu-north-1a"
}

variable "secondary_az" {
  description = "Only used for an empty subnet pair that the ALB and the RDS subnet group require. No compute runs here."
  type        = string
  default     = "eu-north-1b"

  validation {
    condition     = var.secondary_az != var.az
    error_message = "secondary_az must differ from az."
  }
}

variable "vpc_cidr" {
  description = "Keep this inside 10.0.0.0/8 so Tomcat trusts the ALB as an internal proxy for X-Forwarded-* headers."
  type        = string
  default     = "10.20.0.0/16"
}

variable "instance_type" {
  type    = string
  default = "t4g.small"
}

variable "root_volume_gb" {
  type    = number
  default = 30
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.micro"
}

variable "db_allocated_storage_gb" {
  type    = number
  default = 20
}

variable "memorydb_node_type" {
  type    = string
  default = "db.t4g.small"
}

variable "repo_ssh_url" {
  type    = string
  default = "git@github.com:darshan-pr/Auth-Platform-V2.git"
}

variable "app_git_ref" {
  description = "Commit SHA (preferred), tag or branch the instance deploys. Pin a SHA for reproducible releases."
  type        = string
}

variable "node_version" {
  type    = string
  default = "v22.20.0"
}

variable "smtp_host" {
  type = string
}

variable "smtp_port" {
  type    = number
  default = 587
}

variable "smtp_username" {
  type = string
}

variable "smtp_from" {
  type = string
}

variable "sa_bootstrap_enabled" {
  description = "Create the first platform SA account on backend start. Set to false after the account exists."
  type        = bool
  default     = true
}

variable "sa_bootstrap_email" {
  type = string
}

variable "sa_bootstrap_name" {
  type    = string
  default = "Platform SA"
}

variable "deletion_protection" {
  description = "Protects RDS and the ALB from accidental deletion. Set false and apply before terraform destroy."
  type        = bool
  default     = true
}

variable "budget_limit_usd" {
  description = "Monthly gross-cost budget (credits excluded) that triggers email alerts."
  type        = number
  default     = 130
}

variable "github_repo" {
  description = "owner/name of the repository whose main branch may deploy through GitHub Actions."
  type        = string
  default     = "darshan-pr/Auth-Platform-V2"
}

variable "budget_email" {
  type = string
}
