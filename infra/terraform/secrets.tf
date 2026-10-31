resource "random_password" "db" {
  length  = 32
  special = false
}

resource "random_password" "redis" {
  length  = 32
  special = false
}

resource "random_password" "key_encryption" {
  length  = 64
  special = false
}

resource "random_password" "sa_bootstrap" {
  length      = 24
  special     = false
  min_upper   = 2
  min_lower   = 2
  min_numeric = 2
}

resource "tls_private_key" "jwt" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

locals {
  jwt_kid = "${local.name}-1"
  # The backend expects kid|base64(PKCS#8 private DER)|base64(X.509 public DER).
  jwt_private_b64 = replace(replace(tls_private_key.jwt.private_key_pem_pkcs8, "/-----[^-]+-----/", ""), "/\\s/", "")
  jwt_public_b64  = replace(replace(tls_private_key.jwt.public_key_pem, "/-----[^-]+-----/", ""), "/\\s/", "")
  jwt_keys_value  = "${local.jwt_kid}|${local.jwt_private_b64}|${local.jwt_public_b64}"

  secure_params = {
    db_password           = random_password.db.result
    redis_password        = random_password.redis.result
    key_encryption_secret = random_password.key_encryption.result
    jwt_signing_keys      = local.jwt_keys_value
    sa_bootstrap_password = random_password.sa_bootstrap.result
  }

  plain_params = {
    sa_bootstrap_enabled = tostring(var.sa_bootstrap_enabled)
  }
}

# CI owns this value (it writes the commit SHA on every deploy), so Terraform only seeds it.
resource "aws_ssm_parameter" "git_ref" {
  name  = "${local.ssm_prefix}/git_ref"
  type  = "String"
  value = var.app_git_ref

  lifecycle {
    ignore_changes = [value]
  }
}

moved {
  from = aws_ssm_parameter.plain["git_ref"]
  to   = aws_ssm_parameter.git_ref
}

resource "aws_ssm_parameter" "secure" {
  for_each = nonsensitive(toset(keys(local.secure_params)))

  name  = "${local.ssm_prefix}/${each.key}"
  type  = "SecureString"
  value = local.secure_params[each.key]
}

resource "aws_ssm_parameter" "plain" {
  for_each = local.plain_params

  name  = "${local.ssm_prefix}/${each.key}"
  type  = "String"
  value = each.value
}
