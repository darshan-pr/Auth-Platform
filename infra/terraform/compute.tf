data "aws_ssm_parameter" "al2023_arm64" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

locals {
  build_script = templatefile("${path.module}/templates/build.sh.tftpl", {
    app_url = local.app_url
  })

  deploy_script = templatefile("${path.module}/templates/deploy.sh.tftpl", {
    region             = var.region
    ssm_prefix         = local.ssm_prefix
    repo_ssh_url       = var.repo_ssh_url
    app_url            = local.app_url
    rds_address        = aws_db_instance.main.address
    db_name            = aws_db_instance.main.db_name
    db_user            = aws_db_instance.main.username
    redis_user         = aws_memorydb_user.app.user_name
    redis_address      = aws_memorydb_cluster.main.cluster_endpoint[0].address
    smtp_host          = var.smtp_host
    smtp_port          = var.smtp_port
    smtp_username      = var.smtp_username
    smtp_from          = var.smtp_from
    jwt_kid            = local.jwt_kid
    sa_bootstrap_email = var.sa_bootstrap_email
    sa_bootstrap_name  = var.sa_bootstrap_name
  })

  user_data = templatefile("${path.module}/templates/bootstrap.sh.tftpl", {
    node_version  = var.node_version
    deploy_script = local.deploy_script
    build_script  = local.build_script
    backend_unit  = file("${path.module}/templates/authplatform-backend.service")
    frontend_unit = file("${path.module}/templates/authplatform-frontend.service")
  })
}

resource "aws_instance" "app" {
  ami                         = data.aws_ssm_parameter.al2023_arm64.value
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public_a.id
  vpc_security_group_ids      = [aws_security_group.app.id]
  iam_instance_profile        = aws_iam_instance_profile.app.name
  associate_public_ip_address = true

  user_data_base64            = base64gzip(local.user_data)
  user_data_replace_on_change = true

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    encrypted   = true
  }

  tags = { Name = "${local.name}-app" }

  # Config is read from SSM at boot, so those parameters must exist first.
  depends_on = [
    aws_ssm_parameter.secure,
    aws_ssm_parameter.plain,
    aws_iam_role_policy.read_config,
    aws_iam_role_policy_attachment.ssm_core,
  ]

  lifecycle {
    ignore_changes = [ami]
  }
}
