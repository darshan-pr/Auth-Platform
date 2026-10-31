# GitHub Actions deploys through OIDC: no AWS keys are stored in GitHub.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_policy_document" "github_assume" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    # Only workflows running on the main branch of this repository.
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:${var.github_repo}:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "github_deploy" {
  name                 = "${local.name}-github-deploy"
  assume_role_policy   = data.aws_iam_policy_document.github_assume.json
  max_session_duration = 3600
}

# The only thing CI may run on the instance: this fixed deploy script.
resource "aws_ssm_document" "deploy" {
  name            = "${local.name}-deploy"
  document_type   = "Command"
  document_format = "YAML"

  content = <<-YAML
    schemaVersion: "2.2"
    description: "Deploy the commit in the git_ref parameter on the Auth Platform instance"
    mainSteps:
      - action: aws:runShellScript
        name: deploy
        inputs:
          timeoutSeconds: "1500"
          runCommand:
            - "bash -o pipefail -c '/opt/authplatform/deploy.sh 2>&1 | tail -n 80'"
  YAML
}

data "aws_iam_policy_document" "github_deploy" {
  statement {
    sid       = "SetDeployRef"
    actions   = ["ssm:PutParameter", "ssm:GetParameter"]
    resources = [aws_ssm_parameter.git_ref.arn]
  }

  statement {
    sid       = "RunDeployDocument"
    actions   = ["ssm:SendCommand"]
    resources = [aws_ssm_document.deploy.arn]
  }

  statement {
    sid       = "TargetOnlyTheAppInstance"
    actions   = ["ssm:SendCommand"]
    resources = ["arn:aws:ec2:${var.region}:${data.aws_caller_identity.current.account_id}:instance/*"]

    condition {
      test     = "StringEquals"
      variable = "ssm:resourceTag/Name"
      values   = ["${local.name}-app"]
    }
  }

  statement {
    sid       = "ReadCommandResult"
    actions   = ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations", "ec2:DescribeInstances"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "github_deploy" {
  name   = "deploy"
  role   = aws_iam_role.github_deploy.id
  policy = data.aws_iam_policy_document.github_deploy.json
}

output "github_deploy_role_arn" {
  value = aws_iam_role.github_deploy.arn
}

output "deploy_document_name" {
  value = aws_ssm_document.deploy.name
}
