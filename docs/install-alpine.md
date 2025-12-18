# Tranquil PDS Production Installation on Alpine Linux
> **Warning**: These instructions are untested and theoretical, written from the top of Lewis' head. They may contain errors or omissions. This warning will be removed once the guide has been verified.

This guide covers installing Tranquil PDS on Alpine Linux 3.23.

## Prerequisites
- A VPS with at least 2GB RAM and 20GB disk
- A domain name pointing to your server's IP
- A **wildcard TLS certificate** for `*.pds.example.com` (user handles are served as subdomains)
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
This installs the latest stable Rust. Alpine also ships Rust via `apk add rust cargo` if you prefer system packages.
## 3. Install postgres
```sh
apk add postgresql postgresql-contrib
rc-update add postgresql
/etc/init.d/postgresql setup
rc-service postgresql start
psql -U postgres -c "CREATE USER tranquil_pds WITH PASSWORD 'your-secure-password';"
psql -U postgres -c "CREATE DATABASE pds OWNER tranquil_pds;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE pds TO tranquil_pds;"
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
## 7. Clone and Build Tranquil PDS
```sh
mkdir -p /opt && cd /opt
git clone https://tangled.org/lewis.moe/bspds-sandbox tranquil-pds
cd tranquil-pds
cd frontend
deno task build
cd ..
cargo build --release
```
## 8. Install sqlx-cli and Run Migrations
```sh
cargo install sqlx-cli --no-default-features --features postgres
export DATABASE_URL="postgres://tranquil_pds:your-secure-password@localhost:5432/pds"
sqlx migrate run
```
## 9. Configure Tranquil PDS
```sh
mkdir -p /etc/tranquil-pds
cp /opt/tranquil-pds/.env.example /etc/tranquil-pds/tranquil-pds.env
chmod 600 /etc/tranquil-pds/tranquil-pds.env
```
Edit `/etc/tranquil-pds/tranquil-pds.env` and fill in your values. Generate secrets with:
```sh
openssl rand -base64 48
```
## 10. Create OpenRC Service
```sh
adduser -D -H -s /sbin/nologin tranquil-pds
cp /opt/tranquil-pds/target/release/tranquil-pds /usr/local/bin/
mkdir -p /var/lib/tranquil-pds
cp -r /opt/tranquil-pds/frontend/dist /var/lib/tranquil-pds/frontend
chown -R tranquil-pds:tranquil-pds /var/lib/tranquil-pds
cat > /etc/init.d/tranquil-pds << 'EOF'
#!/sbin/openrc-run
name="tranquil-pds"
description="Tranquil PDS - AT Protocol PDS"
command="/usr/local/bin/tranquil-pds"
command_user="tranquil-pds"
command_background=true
pidfile="/run/${RC_SVCNAME}.pid"
output_log="/var/log/tranquil-pds.log"
error_log="/var/log/tranquil-pds.log"
depend() {
    need net postgresql minio
}
start_pre() {
    export FRONTEND_DIR=/var/lib/tranquil-pds/frontend
    . /etc/tranquil-pds/tranquil-pds.env
    export SERVER_HOST SERVER_PORT PDS_HOSTNAME DATABASE_URL
    export S3_ENDPOINT AWS_REGION S3_BUCKET AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
    export VALKEY_URL JWT_SECRET DPOP_SECRET MASTER_KEY CRAWLERS
}
EOF
chmod +x /etc/init.d/tranquil-pds
rc-update add tranquil-pds
rc-service tranquil-pds start
```
## 11. Install and Configure nginx
```sh
apk add nginx certbot certbot-nginx
cat > /etc/nginx/http.d/tranquil-pds.conf << 'EOF'
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
## 12. Obtain Wildcard SSL Certificate
User handles are served as subdomains (e.g., `alice.pds.example.com`), so you need a wildcard certificate.

Wildcard certs require DNS-01 validation. For manual DNS validation (works with any provider):
```sh
certbot certonly --manual --preferred-challenges dns \
  -d pds.example.com -d '*.pds.example.com'
```
Follow the prompts to add TXT records to your DNS.

If your DNS provider has a certbot plugin, you can use that for auto-renewal:
```sh
apk add certbot-dns-cloudflare
certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /etc/cloudflare.ini \
  -d pds.example.com -d '*.pds.example.com'
```

After obtaining the cert, update nginx to use it, then set up auto-renewal:
```sh
echo "0 0 * * * certbot renew --quiet && rc-service nginx reload" | crontab -
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
rc-service tranquil-pds status
curl -s https://pds.example.com/xrpc/_health
curl -s https://pds.example.com/.well-known/atproto-did
```
## Maintenance
View logs:
```sh
tail -f /var/log/tranquil-pds.log
```
Update Tranquil PDS:
```sh
cd /opt/tranquil-pds
git pull
cd frontend && deno task build && cd ..
cargo build --release
rc-service tranquil-pds stop
cp target/release/tranquil-pds /usr/local/bin/
cp -r frontend/dist /var/lib/tranquil-pds/frontend
DATABASE_URL="postgres://tranquil_pds:your-secure-password@localhost:5432/pds" sqlx migrate run
rc-service tranquil-pds start
```
Backup database:
```sh
pg_dump -U postgres pds > /var/backups/pds-$(date +%Y%m%d).sql
```
