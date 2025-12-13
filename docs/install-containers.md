# BSPDS Containerized Production Deployment

> **Warning**: These instructions are untested and theoretical, written from the top of Lewis' head. They may contain errors or omissions. This warning will be removed once the guide has been verified.

This guide covers deploying BSPDS using containers with podman.

- **Debian 13+**: Uses systemd quadlets (modern, declarative container management)
- **Alpine 3.23+**: Uses OpenRC service script with podman-compose

## Prerequisites

- A VPS with at least 2GB RAM and 20GB disk
- A domain name pointing to your server's IP
- Root or sudo access

## Quick Start (Docker/Podman Compose)

If you just want to get running quickly:

```sh
cp .env.example .env

# Edit .env with your values
# Generate secrets: openssl rand -base64 48

# Build and start
podman-compose -f docker-compose.prod.yml up -d

# Get initial certificate (after DNS is configured)
podman-compose -f docker-compose.prod.yml run --rm certbot certonly \
  --webroot -w /var/www/acme -d pds.example.com

# Restart nginx to load certificate
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
mkdir -p /srv/bspds/{postgres,minio,valkey,certs,acme,config}
```

## 3. Create Environment File

```bash
cp /opt/bspds/.env.example /srv/bspds/config/bspds.env
chmod 600 /srv/bspds/config/bspds.env
```

Edit `/srv/bspds/config/bspds.env` and fill in your values. Generate secrets with:

```bash
openssl rand -base64 48
```

For quadlets, also add `DATABASE_URL` with the full connection string (systemd doesn't support variable expansion).

## 4. Install Quadlet Definitions

Copy the quadlet files from the repository:

```bash
cp /opt/bspds/deploy/quadlets/*.pod /etc/containers/systemd/
cp /opt/bspds/deploy/quadlets/*.container /etc/containers/systemd/
```

Note: Systemd doesn't support shell-style variable expansion in `Environment=` lines. The quadlet files expect DATABASE_URL to be set in the environment file.

## 5. Create nginx Configuration

```bash
cp /opt/bspds/deploy/nginx/nginx-quadlet.conf /srv/bspds/config/nginx.conf
```

## 6. Build BSPDS Image

```bash
cd /opt
git clone https://tangled.org/lewis.moe/bspds.git
cd bspds
podman build -t bspds:latest .
```

## 7. Create Podman Secrets

```bash
source /srv/bspds/config/bspds.env
echo "$DB_PASSWORD" | podman secret create bspds-db-password -
echo "$MINIO_ROOT_PASSWORD" | podman secret create bspds-minio-password -
```

## 8. Start Services and Initialize

```bash
systemctl daemon-reload
systemctl start bspds-db bspds-minio bspds-valkey

sleep 10

# Create MinIO bucket
podman run --rm --pod bspds \
  -e MINIO_ROOT_USER=minioadmin \
  -e MINIO_ROOT_PASSWORD=your-minio-password \
  docker.io/minio/mc:RELEASE.2025-07-16T15-35-03Z \
  sh -c "mc alias set local http://localhost:9000 \$MINIO_ROOT_USER \$MINIO_ROOT_PASSWORD && mc mb --ignore-existing local/pds-blobs"

# Run migrations
cargo install sqlx-cli --no-default-features --features postgres
DATABASE_URL="postgres://bspds:your-db-password@localhost:5432/pds" sqlx migrate run --source /opt/bspds/migrations
```

## 9. Obtain SSL Certificate

Create temporary self-signed cert:

```bash
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
  -keyout /srv/bspds/certs/privkey.pem \
  -out /srv/bspds/certs/fullchain.pem \
  -subj "/CN=pds.example.com"

systemctl start bspds-app bspds-nginx

# Get real certificate
podman run --rm \
  -v /srv/bspds/certs:/etc/letsencrypt:Z \
  -v /srv/bspds/acme:/var/www/acme:Z \
  docker.io/certbot/certbot:v5.2.2 certonly \
  --webroot -w /var/www/acme -d pds.example.com --agree-tos --email you@example.com

# Link certificates
ln -sf /srv/bspds/certs/live/pds.example.com/fullchain.pem /srv/bspds/certs/fullchain.pem
ln -sf /srv/bspds/certs/live/pds.example.com/privkey.pem /srv/bspds/certs/privkey.pem

systemctl restart bspds-nginx
```

## 10. Enable All Services

```bash
systemctl enable bspds-db bspds-minio bspds-valkey bspds-app bspds-nginx
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
0 0 * * * podman run --rm -v /srv/bspds/certs:/etc/letsencrypt:Z -v /srv/bspds/acme:/var/www/acme:Z docker.io/certbot/certbot:v5.2.2 renew --quiet && systemctl reload bspds-nginx
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
mkdir -p /srv/bspds/{data,config}
mkdir -p /srv/bspds/data/{postgres,minio,valkey,certs,acme}
```

## 3. Clone Repository and Build

```sh
cd /opt
git clone https://tangled.org/lewis.moe/bspds.git
cd bspds
podman build -t bspds:latest .
```

## 4. Create Environment File

```sh
cp /opt/bspds/.env.example /srv/bspds/config/bspds.env
chmod 600 /srv/bspds/config/bspds.env
```

Edit `/srv/bspds/config/bspds.env` and fill in your values. Generate secrets with:

```sh
openssl rand -base64 48
```

## 5. Set Up Compose and nginx

Copy the production compose and nginx configs:

```sh
cp /opt/bspds/docker-compose.prod.yml /srv/bspds/docker-compose.yml
cp /opt/bspds/nginx.prod.conf /srv/bspds/config/nginx.conf
```

Edit `/srv/bspds/docker-compose.yml` to adjust paths if needed:
- Update volume mounts to use `/srv/bspds/data/` paths
- Update nginx cert paths to match `/srv/bspds/data/certs/`

Edit `/srv/bspds/config/nginx.conf` to update cert paths:
- Change `/etc/nginx/certs/live/${PDS_HOSTNAME}/` to `/etc/nginx/certs/`

## 6. Create OpenRC Service

```sh
cat > /etc/init.d/bspds << 'EOF'
#!/sbin/openrc-run

name="bspds"
description="BSPDS AT Protocol PDS (containerized)"

command="/usr/bin/podman-compose"
command_args="-f /srv/bspds/docker-compose.yml up"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"

directory="/srv/bspds"

depend() {
    need net podman
    after firewall
}

start_pre() {
    set -a
    . /srv/bspds/config/bspds.env
    set +a
}

stop() {
    ebegin "Stopping ${name}"
    cd /srv/bspds
    set -a
    . /srv/bspds/config/bspds.env
    set +a
    podman-compose -f /srv/bspds/docker-compose.yml down
    eend $?
}
EOF

chmod +x /etc/init.d/bspds
```

## 7. Initialize Services

```sh
# Start services
rc-service bspds start

sleep 15

# Create MinIO bucket
source /srv/bspds/config/bspds.env
podman run --rm --network bspds_default \
  -e MINIO_ROOT_USER="$MINIO_ROOT_USER" \
  -e MINIO_ROOT_PASSWORD="$MINIO_ROOT_PASSWORD" \
  docker.io/minio/mc:RELEASE.2025-07-16T15-35-03Z \
  sh -c 'mc alias set local http://minio:9000 $MINIO_ROOT_USER $MINIO_ROOT_PASSWORD && mc mb --ignore-existing local/pds-blobs'

# Run migrations
apk add rustup
rustup-init -y
source ~/.cargo/env
cargo install sqlx-cli --no-default-features --features postgres

# Get database container IP
DB_IP=$(podman inspect bspds-db-1 --format '{{.NetworkSettings.Networks.bspds_default.IPAddress}}')
DATABASE_URL="postgres://bspds:$DB_PASSWORD@$DB_IP:5432/pds" sqlx migrate run --source /opt/bspds/migrations
```

## 8. Obtain SSL Certificate

Create temporary self-signed cert:

```sh
openssl req -x509 -nodes -days 1 -newkey rsa:2048 \
  -keyout /srv/bspds/data/certs/privkey.pem \
  -out /srv/bspds/data/certs/fullchain.pem \
  -subj "/CN=pds.example.com"

rc-service bspds restart

# Get real certificate
podman run --rm \
  -v /srv/bspds/data/certs:/etc/letsencrypt \
  -v /srv/bspds/data/acme:/var/www/acme \
  --network bspds_default \
  docker.io/certbot/certbot:v5.2.2 certonly \
  --webroot -w /var/www/acme -d pds.example.com --agree-tos --email you@example.com

# Link certificates
ln -sf /srv/bspds/data/certs/live/pds.example.com/fullchain.pem /srv/bspds/data/certs/fullchain.pem
ln -sf /srv/bspds/data/certs/live/pds.example.com/privkey.pem /srv/bspds/data/certs/privkey.pem

rc-service bspds restart
```

## 9. Enable Service at Boot

```sh
rc-update add bspds
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
0 0 * * * podman run --rm -v /srv/bspds/data/certs:/etc/letsencrypt -v /srv/bspds/data/acme:/var/www/acme docker.io/certbot/certbot:v5.2.2 renew --quiet && rc-service bspds restart
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
journalctl -u bspds-app -f
podman logs -f bspds-app
```

**Alpine:**
```sh
podman-compose -f /srv/bspds/docker-compose.yml logs -f
podman logs -f bspds-bspds-1
```

## Update BSPDS

```sh
cd /opt/bspds
git pull
podman build -t bspds:latest .

# Debian:
systemctl restart bspds-app

# Alpine:
rc-service bspds restart
```

## Backup Database

**Debian:**
```bash
podman exec bspds-db pg_dump -U bspds pds > /var/backups/pds-$(date +%Y%m%d).sql
```

**Alpine:**
```sh
podman exec bspds-db-1 pg_dump -U bspds pds > /var/backups/pds-$(date +%Y%m%d).sql
```
