# Tranquil PDS containerized production deployment

This guide covers deploying Tranquil PDS using containers with podman.

- **Debian 13+**: Uses systemd quadlets (modern, declarative container management)
- **Alpine 3.23+**: Uses OpenRC service script with podman-compose

## Prerequisites

- A server :p
- Disk space for blobs (depends on usage; plan for ~1GB per active user as a baseline)
- A domain name pointing to your server's IP
- A **wildcard TLS certificate** for `*.pds.example.com` (user handles are served as subdomains)
- Root/sudo/doas access

## Quickstart (docker/podman compose)

If you just want to get running quickly:

```sh
cp example.toml config.toml
```

Edit `config.toml` with your values. Generate secrets with `openssl rand -base64 48`.

Build and start:
```sh
podman build -t tranquil-pds:latest .
podman build -t tranquil-pds-frontend:latest ./frontend
podman-compose -f docker-compose.prod.yaml up -d
```

Get initial certificate (after DNS is configured):
```sh
podman-compose -f docker-compose.prod.yaml run --rm certbot certonly \
  --webroot -w /var/www/acme -d pds.example.com -d '*.pds.example.com'
ln -sf live/pds.example.com/fullchain.pem certs/fullchain.pem
ln -sf live/pds.example.com/privkey.pem certs/privkey.pem
podman-compose -f docker-compose.prod.yaml restart nginx
```

The end!!!

Or wait, you want more? Perhaps a deployment that comes back on server restart?

For production setups with proper service management, continue to either the Debian or Alpine section below.

## Standalone containers (no compose)

If you already have postgres running on the host (eg. from the [Debian install guide](install-debian.md)), you can run just the app containers.

Build the images:
```sh
podman build -t tranquil-pds:latest .
podman build -t tranquil-pds-frontend:latest ./frontend
```

Run the backend with host networking (so it can access postgres on localhost) and mount the blob storage:
```sh
podman run -d --name tranquil-pds \
  --network=host \
  -v /etc/tranquil-pds/config.toml:/etc/tranquil-pds/config.toml:ro,Z \
  -v /var/lib/tranquil:/var/lib/tranquil:Z \
  tranquil-pds:latest
```

Run the frontend with port mapping (the container's nginx listens on port 80):
```sh
podman run -d --name tranquil-pds-frontend \
  -p 8080:80 \
  tranquil-pds-frontend:latest
```

Then configure your host nginx to proxy to both containers. Replace the static file `try_files` directives with proxy passes:

```nginx
# API routes to backend
location /xrpc/ {
    proxy_pass http://127.0.0.1:3000;
    # ... (see Debian guide for full proxy headers)
}

# Static routes to frontend container
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

See the [Debian install guide](install-debian.md) for the full nginx config with all API routes.

---

# Debian with systemd quadlets

Quadlets are a nice way to run podman containers under systemd.

## Install podman

```bash
apt update
apt install -y podman
```

## Create the directory structure

```bash
mkdir -p /etc/containers/systemd
mkdir -p /srv/tranquil-pds/{postgres,blobs,backups,certs,acme,config}
```

## Create a configuration file

```bash
cp /opt/tranquil-pds/example.toml /srv/tranquil-pds/config/config.toml
chmod 600 /srv/tranquil-pds/config/config.toml
```

Edit `/srv/tranquil-pds/config/config.toml` and fill in your values. Generate secrets with:
```bash
openssl rand -base64 48
```

> **Note:** Every config option can also be set via environment variables
> (see comments in `example.toml`). Environment variables always take
> precedence over the config file.

## Install quadlet definitions

Copy the quadlet files from the repository:
```bash
cp /opt/tranquil-pds/deploy/quadlets/tranquil-pds.pod /etc/containers/systemd/
cp /opt/tranquil-pds/deploy/quadlets/tranquil-pds-db.container /etc/containers/systemd/
cp /opt/tranquil-pds/deploy/quadlets/tranquil-pds-app.container /etc/containers/systemd/
cp /opt/tranquil-pds/deploy/quadlets/tranquil-pds-frontend.container /etc/containers/systemd/
cp /opt/tranquil-pds/deploy/quadlets/tranquil-pds-nginx.container /etc/containers/systemd/
```

Optional quadlets for valkey and minio are also available in `deploy/quadlets/` if you need them.

## Create nginx configuration

```bash
cp /opt/tranquil-pds/nginx.frontend.conf /srv/tranquil-pds/config/nginx.conf
```

## Clone and build images

```bash
cd /opt
git clone https://tangled.org/tranquil.farm/tranquil-pds tranquil-pds
cd tranquil-pds
podman build -t tranquil-pds:latest .
podman build -t tranquil-pds-frontend:latest ./frontend
```

## Create podman secrets

```bash
echo "$DB_PASSWORD" | podman secret create tranquil-pds-db-password -
```

## Start services and initialize

```bash
systemctl daemon-reload
systemctl start tranquil-pds-db
sleep 10
```

## Obtain a wildcard SSL cert

User handles are served as subdomains (eg. `alice.pds.example.com`), so you need a wildcard certificate. Wildcard certs require DNS-01 validation.

Create temporary self-signed cert to start services:
```bash
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
  -keyout /srv/tranquil-pds/certs/privkey.pem \
  -out /srv/tranquil-pds/certs/fullchain.pem \
  -subj "/CN=pds.example.com"
systemctl start tranquil-pds-app tranquil-pds-frontend tranquil-pds-nginx
```

Get a wildcard certificate using DNS validation:
```bash
podman run --rm -it \
  -v /srv/tranquil-pds/certs:/etc/letsencrypt:Z \
  docker.io/certbot/certbot:v5.2.2 certonly \
  --manual --preferred-challenges dns \
  -d pds.example.com -d '*.pds.example.com' \
  --agree-tos --email you@example.com
```

Follow the prompts to add TXT records to your DNS. Note: manual mode doesn't auto-renew.

For automated renewal, use a DNS provider plugin (eg. cloudflare, route53).

Link certificates and restart:
```bash
ln -sf /srv/tranquil-pds/certs/live/pds.example.com/fullchain.pem /srv/tranquil-pds/certs/fullchain.pem
ln -sf /srv/tranquil-pds/certs/live/pds.example.com/privkey.pem /srv/tranquil-pds/certs/privkey.pem
systemctl restart tranquil-pds-nginx
```

## Enable all services

```bash
systemctl enable tranquil-pds-db tranquil-pds-app tranquil-pds-frontend tranquil-pds-nginx
```

## Configure firewall if you're into that sort of thing

```bash
apt install -y ufw
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

## Cert renewal

Add to root's crontab (`crontab -e`):
```
0 0 * * * podman run --rm -v /srv/tranquil-pds/certs:/etc/letsencrypt:Z -v /srv/tranquil-pds/acme:/var/www/acme:Z docker.io/certbot/certbot:v5.2.2 renew --quiet && systemctl reload tranquil-pds-nginx
```

---

# Alpine with OpenRC

Alpine uses OpenRC, not systemd. So instead of quadlets we'll use podman-compose with an OpenRC service wrapper.

## Install podman

```sh
apk update
apk add podman podman-compose fuse-overlayfs cni-plugins
rc-update add cgroups
rc-service cgroups start
```

Enable podman socket for compose:
```sh
rc-update add podman
rc-service podman start
```

## Create the directory structure

```sh
mkdir -p /srv/tranquil-pds/{data,config}
mkdir -p /srv/tranquil-pds/data/{postgres,blobs,backups,certs,acme}
```

## Clone the repo and build images

```sh
cd /opt
git clone https://tangled.org/tranquil.farm/tranquil-pds tranquil-pds
cd tranquil-pds
podman build -t tranquil-pds:latest .
podman build -t tranquil-pds-frontend:latest ./frontend
```

## Create a configuration file

```sh
cp /opt/tranquil-pds/example.toml /srv/tranquil-pds/config/config.toml
chmod 600 /srv/tranquil-pds/config/config.toml
```

Edit `/srv/tranquil-pds/config/config.toml` and fill in your values. Generate secrets with:
```sh
openssl rand -base64 48
```

> **Note:** Every config option can also be set via environment variables
> (see comments in `example.toml`). Environment variables always take
> precedence over the config file.

## Set up compose and nginx

Copy the production compose and nginx configs:
```sh
cp /opt/tranquil-pds/docker-compose.prod.yaml /srv/tranquil-pds/docker-compose.yml
cp /opt/tranquil-pds/nginx.frontend.conf /srv/tranquil-pds/config/nginx.conf
```

Edit `/srv/tranquil-pds/docker-compose.yml` to adjust paths if needed:
- Update volume mounts to use `/srv/tranquil-pds/data/` paths
- Update nginx config path to `/srv/tranquil-pds/config/nginx.conf`

Edit `/srv/tranquil-pds/config/nginx.conf` to update cert paths:
- Change `/etc/nginx/certs/live/${PDS_HOSTNAME}/` to `/etc/nginx/certs/`

## Create OpenRC service

```sh
cat > /etc/init.d/tranquil-pds << 'EOF'
#!/sbin/openrc-run
name="tranquil-pds"
description="Tranquil PDS AT Protocol PDS"
command="/usr/bin/podman-compose"
command_args="-f /srv/tranquil-pds/docker-compose.yml up"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
directory="/srv/tranquil-pds"
depend() {
    need net podman
    after firewall
}
start_pre() {
    checkpath -d /srv/tranquil-pds
}
stop() {
    ebegin "Stopping ${name}"
    cd /srv/tranquil-pds
    podman-compose -f /srv/tranquil-pds/docker-compose.yml down
    eend $?
}
EOF
chmod +x /etc/init.d/tranquil-pds
```

## Initialize services

Start services:
```sh
rc-service tranquil-pds start
sleep 15
```

Run migrations:
```sh
apk add rustup
rustup-init -y
source ~/.cargo/env
cargo install sqlx-cli --no-default-features --features postgres
DB_IP=$(podman inspect tranquil-pds-db-1 --format '{{.NetworkSettings.Networks.tranquil-pds_default.IPAddress}}')
DATABASE_URL="postgres://tranquil_pds:$DB_PASSWORD@$DB_IP:5432/pds" sqlx migrate run --source /opt/tranquil-pds/migrations
```

## Obtain wildcard SSL cert

User handles are served as subdomains (eg. `alice.pds.example.com`), so you need a wildcard certificate. Wildcard certs require DNS-01 validation.

Create temporary self-signed cert to start services:
```sh
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
  -keyout /srv/tranquil-pds/data/certs/privkey.pem \
  -out /srv/tranquil-pds/data/certs/fullchain.pem \
  -subj "/CN=pds.example.com"
rc-service tranquil-pds restart
```

Get a wildcard certificate using DNS validation:
```sh
podman run --rm -it \
  -v /srv/tranquil-pds/data/certs:/etc/letsencrypt \
  docker.io/certbot/certbot:v5.2.2 certonly \
  --manual --preferred-challenges dns \
  -d pds.example.com -d '*.pds.example.com' \
  --agree-tos --email you@example.com
```

Follow the prompts to add TXT records to your DNS. Note: manual mode doesn't auto-renew.

Link certificates and restart:
```sh
ln -sf /srv/tranquil-pds/data/certs/live/pds.example.com/fullchain.pem /srv/tranquil-pds/data/certs/fullchain.pem
ln -sf /srv/tranquil-pds/data/certs/live/pds.example.com/privkey.pem /srv/tranquil-pds/data/certs/privkey.pem
rc-service tranquil-pds restart
```

## Enable service at boot time

```sh
rc-update add tranquil-pds
```

## Configure firewall if you're into that sort of thing

```sh
apk add iptables ip6tables
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -P INPUT DROP
ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 80 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 443 -j ACCEPT
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
ip6tables -P INPUT DROP
rc-update add iptables
rc-update add ip6tables
/etc/init.d/iptables save
/etc/init.d/ip6tables save
```

## Cert renewal

Add to root's crontab (`crontab -e`):
```
0 0 * * * podman run --rm -v /srv/tranquil-pds/data/certs:/etc/letsencrypt -v /srv/tranquil-pds/data/acme:/var/www/acme docker.io/certbot/certbot:v5.2.2 renew --quiet && rc-service tranquil-pds restart
```

---

# Verification and maintenance

## Verify installation

```sh
curl -s https://pds.example.com/xrpc/_health | jq
curl -s https://pds.example.com/.well-known/atproto-did
```

## View logs

**Debian:**
```bash
journalctl -u tranquil-pds-app -f
podman logs -f tranquil-pds-app
podman logs -f tranquil-pds-frontend
```

**Alpine:**
```sh
podman-compose -f /srv/tranquil-pds/docker-compose.yml logs -f
podman logs -f tranquil-pds-tranquil-pds-1
podman logs -f tranquil-pds-frontend-1
```

## Update Tranquil PDS

```sh
cd /opt/tranquil-pds
git pull
podman build -t tranquil-pds:latest .
podman build -t tranquil-pds-frontend:latest ./frontend
```

Debian:
```bash
systemctl restart tranquil-pds-app tranquil-pds-frontend
```

Alpine:
```sh
rc-service tranquil-pds restart
```

## Backup database

**Debian:**
```bash
podman exec tranquil-pds-db pg_dump -U tranquil_pds pds > /var/backups/pds-$(date +%Y%m%d).sql
```

**Alpine:**
```sh
podman exec tranquil-pds-db-1 pg_dump -U tranquil_pds pds > /var/backups/pds-$(date +%Y%m%d).sql
```

## Custom homepage

The frontend container serves `homepage.html` as the landing page. To customize it, either:

1. Build a custom frontend image with your own `homepage.html`
2. Mount a custom `homepage.html` into the frontend container

Example custom homepage:
```html
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to my PDS</title>
    <style>
        body { font-family: system-ui; max-width: 600px; margin: 100px auto; padding: 20px; }
    </style>
</head>
<body>
    <h1>Welcome to my dark web popsocket store</h1>
    <p>This is a <a href="https://atproto.com">AT Protocol</a> Personal Data Server.</p>
    <p><a href="/app/">Sign in</a> or learn more at <a href="https://bsky.social">Bluesky</a>.</p>
</body>
</html>
```
