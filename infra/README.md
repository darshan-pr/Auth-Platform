# Auth Platform on AWS (Terraform)

Single-AZ deployment in `eu-north-1`:

```text
Internet -> ALB (HTTPS, ACM)  --/api/*, /.well-known/* -->  Spring Boot :8080 ┐
                              --everything else-------->  Next.js     :3000 ┤ one EC2 (t4g.small, public subnet, SG allows ALB only)
                                                                              ├-> RDS PostgreSQL 16 (db.t4g.micro, private subnet)
                                                                              └-> MemoryDB (Valkey, db.t4g.small, TLS + ACL user, private subnet)
```

- EC2, RDS and MemoryDB all run in `eu-north-1a`. An empty subnet in `eu-north-1b` exists only because an ALB and an RDS subnet group must span two AZs.
- The EC2 instance has a public IP to avoid NAT Gateway cost, but its security group only accepts traffic from the ALB. There is no SSH; use SSM Session Manager.
- This is **not highly available**: one instance, one AZ, no read replica or MemoryDB replica.
- Rough running cost is about $90-100/month (ALB, MemoryDB, RDS, EC2, public IPv4 addresses). Credits are consumed, not a free tier.

## Prerequisites (once)

Two secrets are created outside Terraform so they never enter its state:

```sh
# Read-only deploy key so the instance can clone the private repo
ssh-keygen -t ed25519 -N "" -f deploy_key
gh repo deploy-key add deploy_key.pub --title "authplatform-ec2-prod (read-only)"
aws ssm put-parameter --name /authplatform/prod/github_deploy_key --type SecureString --value file://deploy_key
rm deploy_key deploy_key.pub

# SMTP password (Gmail app password or any SMTP provider)
aws ssm put-parameter --name /authplatform/prod/smtp_password --type SecureString --value file://smtp_password.txt
```

Copy `terraform.tfvars.example` to `terraform.tfvars` and fill it in. `terraform.tfvars` and the local state are gitignored because they hold secrets; back them up safely.

## Deploy

```sh
terraform init
terraform apply
```

`terraform apply` waits for ACM certificate validation. While it runs, add the CNAME from `terraform output acm_validation_records` at your DNS provider. After the apply finishes, create a CNAME from your domain to `terraform output alb_dns_name`.

## Release a new version

Pushing to `main` deploys automatically (`.github/workflows/deploy.yml`):

1. Backend, SDK and console tests run (they also run on every pull request).
2. If they pass, the deploy job signs in to AWS with GitHub OIDC (no stored AWS keys; only `main` of this repo can assume `authplatform-prod-github-deploy`).
3. It writes the commit SHA to `/authplatform/prod/git_ref` and runs the `authplatform-prod-deploy` SSM document, a fixed command that executes `/opt/authplatform/deploy.sh` on the instance. That builds the commit, restarts both services (a short interruption) and runs Flyway migrations on backend start.
4. It then checks that `/sa/login` and `/api/console/csrf` respond over the public URL.

The repository variables `AWS_DEPLOY_ROLE_ARN` and `APP_URL` configure the workflow. Deploys are serialized; a failing health check fails the run, and the fix is to push a corrected commit or a revert (there is no automatic rollback).

`git_ref` is owned by CI: Terraform only seeds it and ignores later changes. Infrastructure changes (`infra/terraform`) are still applied manually with `terraform apply`; the state is local.

Manual deploy of the current `git_ref`, if you ever need it:

```sh
aws ssm send-command --document-name authplatform-prod-deploy \
  --instance-ids "$(terraform output -raw instance_id)"
```

Logs: `journalctl -u authplatform-backend`, `journalctl -u authplatform-frontend`, `/var/log/authplatform-bootstrap.log`.

## First platform admin (SA)

The first deploy creates the SA account with `sa_bootstrap_email` and a generated password:

```sh
aws ssm get-parameter --name /authplatform/prod/sa_bootstrap_password --with-decryption --query Parameter.Value --output text
```

After signing in, set `sa_bootstrap_enabled = false`, run `terraform apply`, then redeploy as above.

## Tear down

Deletion protection is on for RDS and the ALB.

```sh
# set deletion_protection = false in terraform.tfvars
terraform apply
terraform destroy
```

A final RDS snapshot named `authplatform-prod-postgres-final` is kept and billed until you delete it. SSM parameters created outside Terraform (`github_deploy_key`, `smtp_password`) and the GitHub deploy key must be removed manually.
