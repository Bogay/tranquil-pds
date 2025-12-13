# BSPDS Production Installation on Debian

> **Warning**: These instructions are untested and theoretical, written from the top of Lewis' head. They may contain errors or omissions. This warning will be removed once the guide has been verified.

This guide covers installing BSPDS on Debian 13 "Trixie" (current stable as of December 2025).

## Choose Your Installation Method

| Method | Best For |
|--------|----------|
| **Native (this guide)** | Maximum performance, full control, simpler debugging |
| **[Containerized](install-containers.md)** | Easier updates, isolation, reproducible deployments |
| **[Kubernetes](install-kubernetes.md)** | Multi-node, high availability, auto-scaling |

This guide covers native installation. For containerized deployment with podman and systemd quadlets, see the [container guide](install-containers.md).

---

## Prerequisites

- A VPS with at least 2GB RAM and 20GB disk
- A domain name pointing to your server's IP
- Root or sudo access

## 1. System Setup

```bash
apt update && apt upgrade -y
apt install -y curl git build-essential pkg-config libssl-dev
```

## 2. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup default stable
```

This installs the latest stable Rust (1.92+ as of December 2025).

## 3. Install postgres

Debian 13 includes PostgreSQL 17:

```bash
apt install -y postgresql postgresql-contrib

systemctl enable postgresql
systemctl start postgresql

sudo -u postgres psql -c "CREATE USER bspds WITH PASSWORD 'your-secure-password';"
sudo -u postgres psql -c "CREATE DATABASE pds OWNER bspds;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE pds TO bspds;"
```

## 4. Install minio

```bash
curl -O https://dl.min.io/server/minio/release/linux-amd64/minio
chmod +x minio
mv minio /usr/local/bin/

mkdir -p /var/lib/minio/data
useradd -r -s /sbin/nologin minio-user
chown -R minio-user:minio-user /var/lib/minio

cat > /etc/default/minio << 'EOF'
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=your-minio-password
MINIO_VOLUMES="/var/lib/minio/data"
MINIO_OPTS="--console-address :9001"
EOF

cat > /etc/systemd/system/minio.service << 'EOF'
[Unit]
Description=MinIO Object Storage
After=network.target

[Service]
User=minio-user
Group=minio-user
EnvironmentFile=/etc/default/minio
ExecStart=/usr/local/bin/minio server $MINIO_VOLUMES $MINIO_OPTS
Restart=always
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable minio
systemctl start minio
```

Create the blob bucket (wait a few seconds for minio to start):

```bash
curl -O https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
mv mc /usr/local/bin/

mc alias set local http://localhost:9000 minioadmin your-minio-password
mc mb local/pds-blobs
```

## 5. Install valkey

Debian 13 includes Valkey 8:

```bash
apt install -y valkey

systemctl enable valkey-server
systemctl start valkey-server
```

## 6. Install deno (for frontend build)

```bash
curl -fsSL https://deno.land/install.sh | sh
export PATH="$HOME/.deno/bin:$PATH"
echo 'export PATH="$HOME/.deno/bin:$PATH"' >> ~/.bashrc
```

## 7. Clone and Build BSPDS

```bash
cd /opt
git clone https://tangled.org/lewis.moe/bspds-sandbox bspds
cd bspds

cd frontend
deno task build
cd ..

cargo build --release
```

## 8. Install sqlx-cli and Run Migrations

```bash
cargo install sqlx-cli --no-default-features --features postgres

export DATABASE_URL="postgres://bspds:your-secure-password@localhost:5432/pds"
sqlx migrate run
```

## 9. Configure BSPDS

```bash
mkdir -p /etc/bspds
cp /opt/bspds/.env.example /etc/bspds/bspds.env
chmod 600 /etc/bspds/bspds.env
```

Edit `/etc/bspds/bspds.env` and fill in your values. Generate secrets with:

```bash
openssl rand -base64 48
```

## 10. Create Systemd Service

```bash
useradd -r -s /sbin/nologin bspds

cp /opt/bspds/target/release/bspds /usr/local/bin/
mkdir -p /var/lib/bspds
cp -r /opt/bspds/frontend/dist /var/lib/bspds/frontend
chown -R bspds:bspds /var/lib/bspds

cat > /etc/systemd/system/bspds.service << 'EOF'
[Unit]
Description=BSPDS - AT Protocol PDS
After=network.target postgresql.service minio.service

[Service]
Type=simple
User=bspds
Group=bspds
EnvironmentFile=/etc/bspds/bspds.env
Environment=FRONTEND_DIR=/var/lib/bspds/frontend
ExecStart=/usr/local/bin/bspds
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable bspds
systemctl start bspds
```

## 11. Install and Configure nginx

Debian 13 includes nginx 1.26:

```bash
apt install -y nginx certbot python3-certbot-nginx

cat > /etc/nginx/sites-available/bspds << 'EOF'
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

ln -s /etc/nginx/sites-available/bspds /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx
```

## 12. Obtain SSL Certificate

```bash
certbot --nginx -d pds.example.com
```

Certbot automatically configures nginx for HTTP/2 and sets up auto-renewal.

## 13. Configure Firewall

```bash
apt install -y ufw
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

## 14. Verify Installation

```bash
systemctl status bspds
curl -s https://pds.example.com/xrpc/_health | jq
curl -s https://pds.example.com/.well-known/atproto-did
```

## Maintenance

View logs:
```bash
journalctl -u bspds -f
```

Update BSPDS:
```bash
cd /opt/bspds
git pull
cd frontend && deno task build && cd ..
cargo build --release
systemctl stop bspds
cp target/release/bspds /usr/local/bin/
cp -r frontend/dist /var/lib/bspds/frontend
DATABASE_URL="postgres://bspds:your-secure-password@localhost:5432/pds" sqlx migrate run
systemctl start bspds
```

Backup database:
```bash
sudo -u postgres pg_dump pds > /var/backups/pds-$(date +%Y%m%d).sql
```
