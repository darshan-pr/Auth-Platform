# Caddy — EC2 Host Reverse Proxy

Caddy runs **natively on the EC2 host** (not in Docker). It owns ports `:80` and `:443`,
handles TLS automatically, and reverse-proxies to the Nginx Docker container on port `8000`.

```
Internet
  │  HTTPS :443
  ▼
Caddy (EC2 host — systemd service)
  │  HTTP  127.0.0.1:8000
  ▼
Nginx (Docker container — docker-compose.prod.yml)
  │  HTTP  backend:8000 (internal Docker network)
  ▼
FastAPI / Gunicorn
```

## Why `/.well-known/` needed an explicit rule

Caddy's implicit file-server and security layer treats paths starting with `/.` as hidden
files and returns `403 Forbidden` before the request ever reaches the backend.

The `handle /.well-known/* { … }` block placed **above** the catch-all `reverse_proxy`
directive ensures JWKS (`/.well-known/jwks.json`) and OIDC discovery
(`/.well-known/openid-configuration`) are passed through cleanly.

## First-time setup on EC2

Run these commands **once** on the EC2 instance after Caddy is installed:

```bash
# 1. Install Caddy (if not already installed)
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy

# 2. Allow the deploy user to reload Caddy without a password
#    Add this line to /etc/sudoers (via visudo):
#    <deploy-user> ALL=(ALL) NOPASSWD: /usr/bin/caddy validate *, /bin/cp */caddy/Caddyfile /etc/caddy/Caddyfile, /bin/systemctl reload caddy

# 3. Copy the initial Caddyfile
sudo cp /path/to/auth-platform/caddy/Caddyfile /etc/caddy/Caddyfile

# 4. Validate and reload
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

## Subsequent deploys

The CI/CD pipeline (`.github/workflows/ci-cd.yml`) automatically:
1. Validates `caddy/Caddyfile` from the repo
2. Copies it to `/etc/caddy/Caddyfile`
3. Runs `systemctl reload caddy` (zero-downtime hot-reload)

## Validate the fix

```bash
curl -i https://auth-platform.darshan-pr.tech/.well-known/jwks.json
curl -i https://auth-platform.darshan-pr.tech/.well-known/openid-configuration
```

Both should return `200 OK` with JSON bodies.
