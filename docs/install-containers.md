# Tranquil PDS Containerized Production Deployment
> **Warning**: These instructions are untested and theoretical, written from the top of Lewis' head. They may contain errors or omissions. This warning will be removed once the guide has been verified.
This guide covers deploying Tranquil PDS using containers with podman.
- **Debian 13+**: Uses systemd quadlets (modern, declarative container management)
- **Alpine 3.23+**: Uses OpenRC service script with podman-compose
## Prerequisites
- A VPS with at least 2GB RAM and 20GB disk
- A domain name pointing to your server's IP
- A **wildcard TLS certificate** for `*.pds.example.com` (user handles are served as subdomains)
- Root or sudo access
## Quick Start (Docker/Podman Compose)
If you just want to get running quickly:
```sh
cp .env.example .env
```

Edit `.env` with your values. Generate secrets with `openssl rand -base64 48`.

Build and start:
```sh
podman-compose -f docker-compose.prod.yml up -d
```

Get initial certificate (after DNS is configured):
```sh
podman-compose -f docker-compose.prod.yml run --rm certbot certonly \
  --webroot -w /var/www/acme -d pds.example.com
podman-compose -f docker-compose.prod.yml restart nginx
```
For production setups with proper service management, continue to either the Debian or Alpine section below.
---
# Debian 13+ with Systemd Quadlets
Quadlets are the modern way to run podman containers under systemd.
## 1. Install Podman
```bash
apt update
apt install -y podman
```
## 2. Create Directory Structure
```bash
mkdir -p /etc/containers/systemd
mkdir -p /srv/tranquil-pds/{postgres,minio,valkey,certs,acme,config}
```
## 3. Create Environment File
```bash
cp /opt/tranquil-pds/.env.example /srv/tranquil-pds/config/tranquil-pds.env
chmod 600 /srv/tranquil-pds/config/tranquil-pds.env
```
Edit `/srv/tranquil-pds/config/tranquil-pds.env` and fill in your values. Generate secrets with:
```bash
openssl rand -base64 48
```
For quadlets, also add `DATABASE_URL` with the full connection string (systemd doesn't support variable expansion).
## 4. Install Quadlet Definitions
Copy the quadlet files from the repository:
```bash
cp /opt/tranquil-pds/deploy/quadlets/*.pod /etc/containers/systemd/
cp /opt/tranquil-pds/deploy/quadlets/*.container /etc/containers/systemd/
```
Note: Systemd doesn't support shell-style variable expansion in `Environment=` lines. The quadlet files expect DATABASE_URL to be set in the environment file.
## 5. Create nginx Configuration
```bash
cp /opt/tranquil-pds/deploy/nginx/nginx-quadlet.conf /srv/tranquil-pds/config/nginx.conf
```
## 6. Build Tranquil PDS Image
```bash
cd /opt
git clone https://tangled.org/lewis.moe/bspds-sandbox tranquil-pds
cd tranquil-pds
podman build -t tranquil-pds:latest .
```
## 7. Create Podman Secrets
```bash
source /srv/tranquil-pds/config/tranquil-pds.env
echo "$DB_PASSWORD" | podman secret create tranquil-pds-db-password -
echo "$MINIO_ROOT_PASSWORD" | podman secret create tranquil-pds-minio-password -
```
## 8. Start Services and Initialize
```bash
systemctl daemon-reload
systemctl start tranquil-pds-db tranquil-pds-minio tranquil-pds-valkey
sleep 10
```

Create the minio buckets:
```bash
podman run --rm --pod tranquil-pds \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=your-minio-password \
  docker.io/minio/mc:RELEASE.2025-07-16T15-35-03Z \
  sh -c "mc alias set local http://localhost:9000 \$MINIO_ROOT_USER \$MINIO_ROOT_PASSWORD && mc mb --ignore-existing local/pds-blobs && mc mb --ignore-existing local/pds-backups"
```

Run migrations:
```bash
cargo install sqlx-cli --no-default-features --features postgres
DATABASE_URL="postgres://tranquil_pds:your-db-password@localhost:5432/pds" sqlx migrate run --source /opt/tranquil-pds/migrations
```
## 9. Obtain Wildcard SSL Certificate
User handles are served as subdomains (e.g., `alice.pds.example.com`), so you need a wildcard certificate. Wildcard certs require DNS-01 validation.

Create temporary self-signed cert to start services:
```bash
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
  -keyout /srv/tranquil-pds/certs/privkey.pem \
  -out /srv/tranquil-pds/certs/fullchain.pem \
  -subj "/CN=pds.example.com"
systemctl start tranquil-pds-app tranquil-pds-nginx
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

For automated renewal, use a DNS provider plugin (e.g., cloudflare, route53).

Link certificates and restart:
```bash
ln -sf /srv/tranquil-pds/certs/live/pds.example.com/fullchain.pem /srv/tranquil-pds/certs/fullchain.pem
ln -sf /srv/tranquil-pds/certs/live/pds.example.com/privkey.pem /srv/tranquil-pds/certs/privkey.pem
systemctl restart tranquil-pds-nginx
```
## 10. Enable All Services
```bash
systemctl enable tranquil-pds-db tranquil-pds-minio tranquil-pds-valkey tranquil-pds-app tranquil-pds-nginx
```
## 11. Configure Firewall
```bash
apt install -y ufw
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```
## 12. Certificate Renewal
Add to root's crontab (`crontab -e`):
```
0 0 * * * podman run --rm -v /srv/tranquil-pds/certs:/etc/letsencrypt:Z -v /srv/tranquil-pds/acme:/var/www/acme:Z docker.io/certbot/certbot:v5.2.2 renew --quiet && systemctl reload tranquil-pds-nginx
```
---
# Alpine 3.23+ with OpenRC
Alpine uses OpenRC, not systemd. We'll use podman-compose with an OpenRC service wrapper.
## 1. Install Podman
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
## 2. Create Directory Structure
```sh
mkdir -p /srv/tranquil-pds/{data,config}
mkdir -p /srv/tranquil-pds/data/{postgres,minio,valkey,certs,acme}
```
## 3. Clone Repository and Build
```sh
cd /opt
git clone https://tangled.org/lewis.moe/bspds-sandbox tranquil-pds
cd tranquil-pds
podman build -t tranquil-pds:latest .
```
## 4. Create Environment File
```sh
cp /opt/tranquil-pds/.env.example /srv/tranquil-pds/config/tranquil-pds.env
chmod 600 /srv/tranquil-pds/config/tranquil-pds.env
```
Edit `/srv/tranquil-pds/config/tranquil-pds.env` and fill in your values. Generate secrets with:
```sh
openssl rand -base64 48
```
## 5. Set Up Compose and nginx
Copy the production compose and nginx configs:
```sh
cp /opt/tranquil-pds/docker-compose.prod.yml /srv/tranquil-pds/docker-compose.yml
cp /opt/tranquil-pds/nginx.prod.conf /srv/tranquil-pds/config/nginx.conf
```
Edit `/srv/tranquil-pds/docker-compose.yml` to adjust paths if needed:
- Update volume mounts to use `/srv/tranquil-pds/data/` paths
- Update nginx cert paths to match `/srv/tranquil-pds/data/certs/`
Edit `/srv/tranquil-pds/config/nginx.conf` to update cert paths:
- Change `/etc/nginx/certs/live/${PDS_HOSTNAME}/` to `/etc/nginx/certs/`
## 6. Create OpenRC Service
```sh
cat > /etc/init.d/tranquil-pds << 'EOF'
#!/sbin/openrc-run
name="tranquil-pds"
description="Tranquil PDS AT Protocol PDS (containerized)"
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
    set -a
    . /srv/tranquil-pds/config/tranquil-pds.env
    set +a
}
stop() {
    ebegin "Stopping ${name}"
    cd /srv/tranquil-pds
    set -a
    . /srv/tranquil-pds/config/tranquil-pds.env
    set +a
    podman-compose -f /srv/tranquil-pds/docker-compose.yml down
    eend $?
}
EOF
chmod +x /etc/init.d/tranquil-pds
```
## 7. Initialize Services
Start services:
```sh
rc-service tranquil-pds start
sleep 15
```

Create the minio buckets:
```sh
source /srv/tranquil-pds/config/tranquil-pds.env
podman run --rm --network tranquil-pds_default \
  -e MINIO_ROOT_USER="$MINIO_ROOT_USER" \
  -e MINIO_ROOT_PASSWORD="$MINIO_ROOT_PASSWORD" \
  docker.io/minio/mc:RELEASE.2025-07-16T15-35-03Z \
  sh -c 'mc alias set local http://minio:9000 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD && mc mb --ignore-existing local/pds-blobs && mc mb --ignore-existing local/pds-backups'
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
## 8. Obtain Wildcard SSL Certificate
User handles are served as subdomains (e.g., `alice.pds.example.com`), so you need a wildcard certificate. Wildcard certs require DNS-01 validation.

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
## 9. Enable Service at Boot
```sh
rc-update add tranquil-pds
```
## 10. Configure Firewall
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
## 11. Certificate Renewal
Add to root's crontab (`crontab -e`):
```
0 0 * * * podman run --rm -v /srv/tranquil-pds/data/certs:/etc/letsencrypt -v /srv/tranquil-pds/data/acme:/var/www/acme docker.io/certbot/certbot:v5.2.2 renew --quiet && rc-service tranquil-pds restart
```
---
# Verification and Maintenance
## Verify Installation
```sh
curl -s https://pds.example.com/xrpc/_health | jq
curl -s https://pds.example.com/.well-known/atproto-did
```
## View Logs
**Debian:**
```bash
journalctl -u tranquil-pds-app -f
podman logs -f tranquil-pds-app
```
**Alpine:**
```sh
podman-compose -f /srv/tranquil-pds/docker-compose.yml logs -f
podman logs -f tranquil-pds-tranquil-pds-1
```
## Update Tranquil PDS
```sh
cd /opt/tranquil-pds
git pull
podman build -t tranquil-pds:latest .
```

Debian:
```bash
systemctl restart tranquil-pds-app
```

Alpine:
```sh
rc-service tranquil-pds restart
```
## Backup Database
**Debian:**
```bash
podman exec tranquil-pds-db pg_dump -U tranquil_pds pds > /var/backups/pds-$(date +%Y%m%d).sql
```
**Alpine:**
```sh
podman exec tranquil-pds-db-1 pg_dump -U tranquil_pds pds > /var/backups/pds-$(date +%Y%m%d).sql
```

## Custom Homepage

Mount a `homepage.html` into the container's frontend directory and it becomes your landing page. Go nuts with it. Account dashboard is at `/app/` so you won't break anything.

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
