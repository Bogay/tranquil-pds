# Tranquil PDS Production Installation on OpenBSD
> **Warning**: These instructions are untested and theoretical, written from the top of Lewis' head. They may contain errors or omissions. This warning will be removed once the guide has been verified.
This guide covers installing Tranquil PDS on OpenBSD 7.8.
## Prerequisites
- A VPS with at least 2GB RAM and 20GB disk
- A domain name pointing to your server's IP
- A **wildcard TLS certificate** for `*.pds.example.com` (user handles are served as subdomains)
- Root access (or doas configured)
## Why nginx over relayd?
OpenBSD's native `relayd` supports WebSockets but does **not** support HTTP/2. For a modern PDS deployment, we recommend nginx which provides HTTP/2, WebSocket support, and automatic OCSP stapling.
## 1. System Setup
```sh
pkg_add curl git
```
## 2. Install Rust
```sh
pkg_add rust
```
OpenBSD ships Rust in ports. For the latest stable, use rustup:
```sh
pkg_add rustup
rustup-init -y
source ~/.cargo/env
rustup default stable
```
## 3. Install postgres
```sh
pkg_add postgresql-server postgresql-client
mkdir -p /var/postgresql/data
chown _postgresql:_postgresql /var/postgresql/data
su - _postgresql -c "initdb -D /var/postgresql/data -U postgres -A scram-sha-256"
rcctl enable postgresql
rcctl start postgresql
psql -U postgres -c "CREATE USER tranquil_pds WITH PASSWORD 'your-secure-password';"
psql -U postgres -c "CREATE DATABASE pds OWNER tranquil_pds;"
psql -U postgres -c "GRANT ALL PRIVILEGES ON DATABASE pds TO tranquil_pds;"
```
## 4. Install minio
OpenBSD doesn't have a minio package. Options:
**Option A: Use an external S3-compatible service (recommended for production)**
aws s3, backblaze b2, or upcloud managed object storage. Skip to step 5 and configure the S3 credentials in step 9.
**Option B: Build minio from source**
```sh
pkg_add go
mkdir -p /tmp/minio-build && cd /tmp/minio-build
ftp -o minio.tar.gz https://github.com/minio/minio/archive/refs/tags/RELEASE.2025-10-15T17-29-55Z.tar.gz
tar xzf minio.tar.gz
cd minio-*
go build -o minio .
cp minio /usr/local/bin/
mkdir -p /var/minio/data
useradd -d /var/minio -s /sbin/nologin _minio
chown -R _minio:_minio /var/minio
cat > /etc/minio.conf << 'EOF'
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=your-minio-password
EOF
chmod 600 /etc/minio.conf
cat > /etc/rc.d/minio << 'EOF'
#!/bin/ksh
daemon="/usr/local/bin/minio"
daemon_user="_minio"
daemon_flags="server /var/minio/data --console-address :9001"
. /etc/rc.d/rc.subr
rc_pre() {
    . /etc/minio.conf
    export MINIO_ROOT_USER MINIO_ROOT_PASSWORD
}
rc_cmd $1
EOF
chmod +x /etc/rc.d/minio
rcctl enable minio
rcctl start minio
```
Create the buckets:
```sh
ftp -o /usr/local/bin/mc https://dl.min.io/client/mc/release/openbsd-amd64/mc
chmod +x /usr/local/bin/mc
mc alias set local http://localhost:9000 minioadmin your-minio-password
mc mb local/pds-blobs
mc mb local/pds-backups
```
## 5. Install redis
OpenBSD has redis in ports (valkey not available yet):
```sh
pkg_add redis
rcctl enable redis
rcctl start redis
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
cp /opt/tranquil-pds/.env.example /etc/tranquil-pds/tranquil-pds.conf
chmod 600 /etc/tranquil-pds/tranquil-pds.conf
```
Edit `/etc/tranquil-pds/tranquil-pds.conf` and fill in your values. Generate secrets with:
```sh
openssl rand -base64 48
```
## 10. Create rc.d Service
```sh
useradd -d /var/empty -s /sbin/nologin _tranquil_pds
cp /opt/tranquil-pds/target/release/tranquil-pds /usr/local/bin/
mkdir -p /var/tranquil-pds
cp -r /opt/tranquil-pds/frontend/dist /var/tranquil-pds/frontend
chown -R _tranquil_pds:_tranquil_pds /var/tranquil-pds
cat > /etc/rc.d/tranquil_pds << 'EOF'
#!/bin/ksh
daemon="/usr/local/bin/tranquil-pds"
daemon_user="_tranquil_pds"
daemon_logger="daemon.info"
. /etc/rc.d/rc.subr
rc_pre() {
    export FRONTEND_DIR=/var/tranquil-pds/frontend
    while IFS='=' read -r key value; do
        case "$key" in
            \#*|"") continue ;;
        esac
        export "$key=$value"
    done < /etc/tranquil-pds/tranquil-pds.conf
}
rc_cmd $1
EOF
chmod +x /etc/rc.d/tranquil_pds
rcctl enable tranquil_pds
rcctl start tranquil_pds
```
## 11. Install and Configure nginx
```sh
pkg_add nginx
cat > /etc/nginx/nginx.conf << 'EOF'
worker_processes 1;
events {
    worker_connections 1024;
}
http {
    include mime.types;
    server {
        listen 80;
        listen [::]:80;
        server_name pds.example.com;
        location /.well-known/acme-challenge/ {
            root /var/www/acme;
        }
        location / {
            return 301 https://$host$request_uri;
        }
    }
    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
        server_name pds.example.com;
        ssl_certificate /etc/ssl/pds.example.com.fullchain.pem;
        ssl_certificate_key /etc/ssl/private/pds.example.com.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers on;
        ssl_session_cache shared:SSL:10m;
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
}
EOF
mkdir -p /var/www/acme
rcctl enable nginx
```
## 12. Obtain Wildcard SSL Certificate
User handles are served as subdomains (e.g., `alice.pds.example.com`), so you need a wildcard certificate.

OpenBSD's native `acme-client` only supports HTTP-01 validation, which can't issue wildcard certs. You have a few options:

**Option A: Use certbot with DNS validation (recommended)**
```sh
pkg_add certbot
certbot certonly --manual --preferred-challenges dns \
  -d pds.example.com -d '*.pds.example.com'
```
Follow the prompts to add TXT records to your DNS. Then update nginx.conf to point to the certbot certs.

**Option B: Use a managed DNS provider with API**
If your DNS provider has a certbot plugin, you can automate renewal.

**Option C: Use acme.sh**
[acme.sh](https://github.com/acmesh-official/acme.sh) supports many DNS providers for automated wildcard cert renewal.

After obtaining the cert, update nginx to use it and restart:
```sh
rcctl restart nginx
```
## 13. Configure Packet Filter (pf)
```sh
cat >> /etc/pf.conf << 'EOF'
pass in on egress proto tcp from any to any port { 22, 80, 443 }
EOF
pfctl -f /etc/pf.conf
```
## 14. Verify Installation
```sh
rcctl check tranquil_pds
ftp -o - https://pds.example.com/xrpc/_health
ftp -o - https://pds.example.com/.well-known/atproto-did
```
## Maintenance
View logs:
```sh
tail -f /var/log/daemon
```
Update Tranquil PDS:
```sh
cd /opt/tranquil-pds
git pull
cd frontend && deno task build && cd ..
cargo build --release
rcctl stop tranquil_pds
cp target/release/tranquil-pds /usr/local/bin/
cp -r frontend/dist /var/tranquil-pds/frontend
DATABASE_URL="postgres://tranquil_pds:your-secure-password@localhost:5432/pds" sqlx migrate run
rcctl start tranquil_pds
```
Backup database:
```sh
pg_dump -U postgres pds > /var/backups/pds-$(date +%Y%m%d).sql
```

## Custom Homepage

Drop a `homepage.html` in `/var/tranquil-pds/frontend/` and it becomes your landing page. Go nuts with it. Account dashboard is at `/app/` so you won't break anything.

```sh
cat > /var/tranquil-pds/frontend/homepage.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to my PDS</title>
    <style>
        body { font-family: system-ui; max-width: 600px; margin: 100px auto; padding: 20px; }
    </style>
</head>
<body>
    <h1>Welcome to my uma musume shipping site!</h1>
    <p>This is a <a href="https://atproto.com">AT Protocol</a> Personal Data Server.</p>
    <p><a href="/app/">Sign in</a> or learn more at <a href="https://bsky.social">Bluesky</a>.</p>
</body>
</html>
EOF
```
