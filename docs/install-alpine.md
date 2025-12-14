# BSPDS Production Installation on Alpine Linux
> **Warning**: These instructions are untested and theoretical, written from the top of Lewis' head. They may contain errors or omissions. This warning will be removed once the guide has been verified.
This guide covers installing BSPDS on Alpine Linux 3.23 (current stable as of December 2025).
## Choose Your Installation Method
| Method | Best For |
|--------|----------|
| **Native (this guide)** | Maximum performance, minimal footprint, full control |
| **[Containerized](install-containers.md)** | Easier updates, isolation, reproducible deployments |
| **[Kubernetes](install-kubernetes.md)** | Multi-node, high availability, auto-scaling |
This guide covers native installation. For containerized deployment with podman and systemd quadlets, see the [container guide](install-containers.md).
---
## Prerequisites
- A VPS with at least 2GB RAM and 20GB disk
- A domain name pointing to your server's IP
- Root access
## 1. System Setup
```sh
apk update && apk upgrade
apk add curl git build-base openssl-dev pkgconf
```
## 2. Install Rust
```sh
apk add rustup
rustup-init -y
source ~/.cargo/env
rustup default stable
```
This installs the latest stable Rust (1.92+ as of December 2025). Alpine 3.23 also ships Rust 1.91 via `apk add rust cargo` if you prefer system packages.
## 3. Install postgres
Alpine 3.23 includes PostgreSQL 18:
```sh
apk add postgresql postgresql-contrib
rc-update add postgresql
/etc/init.d/postgresql setup
rc-service postgresql start
psql -U postgres -c "CREATE USER bspds WITH PASSWORD 'your-secure-password';"
psql -U postgres -c "CREATE DATABASE pds OWNER bspds;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE pds TO bspds;"
```
## 4. Install minio
```sh
curl -O https://dl.min.io/server/minio/release/linux-amd64/minio
chmod +x minio
mv minio /usr/local/bin/
mkdir -p /var/lib/minio/data
adduser -D -H -s /sbin/nologin minio-user
chown -R minio-user:minio-user /var/lib/minio
cat > /etc/conf.d/minio << 'EOF'
MINIO_ROOT_USER="minioadmin"
MINIO_ROOT_PASSWORD="your-minio-password"
MINIO_VOLUMES="/var/lib/minio/data"
MINIO_OPTS="--console-address :9001"
EOF
cat > /etc/init.d/minio << 'EOF'
#!/sbin/openrc-run
name="minio"
description="MinIO Object Storage"
command="/usr/local/bin/minio"
command_args="server ${MINIO_VOLUMES} ${MINIO_OPTS}"
command_user="minio-user"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/minio.log"
error_log="/var/log/minio.log"
depend() {
    need net
}
start_pre() {
    . /etc/conf.d/minio
    export MINIO_ROOT_USER MINIO_ROOT_PASSWORD
}
EOF
chmod +x /etc/init.d/minio
rc-update add minio
rc-service minio start
```
Create the blob bucket (wait a few seconds for minio to start):
```sh
curl -O https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
mv mc /usr/local/bin/
mc alias set local http://localhost:9000 minioadmin your-minio-password
mc mb local/pds-blobs
```
## 5. Install valkey
Alpine 3.23 includes Valkey 9:
```sh
apk add valkey
rc-update add valkey
rc-service valkey start
```
## 6. Install deno (for frontend build)
```sh
curl -fsSL https://deno.land/install.sh | sh
export PATH="$HOME/.deno/bin:$PATH"
echo 'export PATH="$HOME/.deno/bin:$PATH"' >> ~/.profile
```
## 7. Clone and Build BSPDS
```sh
mkdir -p /opt && cd /opt
git clone https://tangled.org/lewis.moe/bspds-sandbox bspds
cd bspds
cd frontend
deno task build
cd ..
cargo build --release
```
## 8. Install sqlx-cli and Run Migrations
```sh
cargo install sqlx-cli --no-default-features --features postgres
export DATABASE_URL="postgres://bspds:your-secure-password@localhost:5432/pds"
sqlx migrate run
```
## 9. Configure BSPDS
```sh
mkdir -p /etc/bspds
cp /opt/bspds/.env.example /etc/bspds/bspds.env
chmod 600 /etc/bspds/bspds.env
```
Edit `/etc/bspds/bspds.env` and fill in your values. Generate secrets with:
```sh
openssl rand -base64 48
```
## 10. Create OpenRC Service
```sh
adduser -D -H -s /sbin/nologin bspds
cp /opt/bspds/target/release/bspds /usr/local/bin/
mkdir -p /var/lib/bspds
cp -r /opt/bspds/frontend/dist /var/lib/bspds/frontend
chown -R bspds:bspds /var/lib/bspds
cat > /etc/init.d/bspds << 'EOF'
#!/sbin/openrc-run
name="bspds"
description="BSPDS - AT Protocol PDS"
command="/usr/local/bin/bspds"
command_user="bspds"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/bspds.log"
error_log="/var/log/bspds.log"
depend() {
    need net postgresql minio
}
start_pre() {
    export FRONTEND_DIR=/var/lib/bspds/frontend
    . /etc/bspds/bspds.env
    export SERVER_HOST SERVER_PORT PDS_HOSTNAME DATABASE_URL
    export S3_ENDPOINT AWS_REGION S3_BUCKET AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
    export VALKEY_URL JWT_SECRET DPOP_SECRET MASTER_KEY APPVIEW_URL CRAWLERS
}
EOF
chmod +x /etc/init.d/bspds
rc-update add bspds
rc-service bspds start
```
## 11. Install and Configure nginx
Alpine 3.23 includes nginx 1.28:
```sh
apk add nginx certbot certbot-nginx
cat > /etc/nginx/http.d/bspds.conf << 'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name pds.example.com;
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }
}
EOF
rc-update add nginx
rc-service nginx start
```
## 12. Obtain SSL Certificate
```sh
certbot --nginx -d pds.example.com
```
Set up auto-renewal:
```sh
echo "0 0 * * * certbot renew --quiet" | crontab -
```
## 13. Configure Firewall
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
## 14. Verify Installation
```sh
rc-service bspds status
curl -s https://pds.example.com/xrpc/_health
curl -s https://pds.example.com/.well-known/atproto-did
```
## Maintenance
View logs:
```sh
tail -f /var/log/bspds.log
```
Update BSPDS:
```sh
cd /opt/bspds
git pull
cd frontend && deno task build && cd ..
cargo build --release
rc-service bspds stop
cp target/release/bspds /usr/local/bin/
cp -r frontend/dist /var/lib/bspds/frontend
DATABASE_URL="postgres://bspds:your-secure-password@localhost:5432/pds" sqlx migrate run
rc-service bspds start
```
Backup database:
```sh
pg_dump -U postgres pds > /var/backups/pds-$(date +%Y%m%d).sql
```
