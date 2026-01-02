# Tranquil PDS Production Installation on Debian
This guide covers installing Tranquil PDS on Debian 13.

## Prerequisites
- A VPS with at least 2GB RAM and 20GB disk
- A domain name pointing to your server's IP
- A wildcard TLS certificate for `*.pds.example.com` (user handles are served as subdomains)
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
This installs the latest stable Rust.
## 3. Install postgres
```bash
apt install -y postgresql postgresql-contrib
systemctl enable postgresql
systemctl start postgresql
sudo -u postgres psql -c "CREATE USER tranquil_pds WITH PASSWORD 'your-secure-password';"
sudo -u postgres psql -c "CREATE DATABASE pds OWNER tranquil_pds;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE pds TO tranquil_pds;"
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
Create the buckets (wait a few seconds for minio to start):
```bash
curl -O https://dl.min.io/client/mc/release/linux-amd64/mc
chmod +x mc
mv mc /usr/local/bin/
mc alias set local http://localhost:9000 minioadmin your-minio-password
mc mb local/pds-blobs
mc mb local/pds-backups
```
## 5. Install valkey
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
## 7. Clone and Build Tranquil PDS
```bash
cd /opt
git clone https://tangled.org/lewis.moe/bspds-sandbox tranquil-pds
cd tranquil-pds
cd frontend
deno task build
cd ..
cargo build --release
```
## 8. Install sqlx-cli and Run Migrations
```bash
cargo install sqlx-cli --no-default-features --features postgres
export DATABASE_URL="postgres://tranquil_pds:your-secure-password@localhost:5432/pds"
sqlx migrate run
```
## 9. Configure Tranquil PDS
```bash
mkdir -p /etc/tranquil-pds
cp /opt/tranquil-pds/.env.example /etc/tranquil-pds/tranquil-pds.env
chmod 600 /etc/tranquil-pds/tranquil-pds.env
```
Edit `/etc/tranquil-pds/tranquil-pds.env` and fill in your values. Generate secrets with:
```bash
openssl rand -base64 48
```
## 10. Create Systemd Service
```bash
useradd -r -s /sbin/nologin tranquil-pds
cp /opt/tranquil-pds/target/release/tranquil-pds /usr/local/bin/
mkdir -p /var/lib/tranquil-pds
cp -r /opt/tranquil-pds/frontend/dist /var/lib/tranquil-pds/frontend
chown -R tranquil-pds:tranquil-pds /var/lib/tranquil-pds
cat > /etc/systemd/system/tranquil-pds.service << 'EOF'
[Unit]
Description=Tranquil PDS - AT Protocol PDS
After=network.target postgresql.service minio.service
[Service]
Type=simple
User=tranquil-pds
Group=tranquil-pds
EnvironmentFile=/etc/tranquil-pds/tranquil-pds.env
Environment=FRONTEND_DIR=/var/lib/tranquil-pds/frontend
ExecStart=/usr/local/bin/tranquil-pds
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable tranquil-pds
systemctl start tranquil-pds
```
## 11. Install and Configure nginx
```bash
apt install -y nginx certbot python3-certbot-nginx
cat > /etc/nginx/sites-available/tranquil-pds << 'EOF'
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
ln -s /etc/nginx/sites-available/tranquil-pds /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx
```
## 12. Obtain Wildcard SSL Certificate
User handles are served as subdomains (e.g., `alice.pds.example.com`), so you need a wildcard certificate.

Wildcard certs require DNS-01 validation. If your DNS provider has a certbot plugin:
```bash
apt install -y python3-certbot-dns-cloudflare
certbot certonly --dns-cloudflare \
  --dns-cloudflare-credentials /etc/cloudflare.ini \
  -d pds.example.com -d '*.pds.example.com'
```

For manual DNS validation (works with any provider):
```bash
certbot certonly --manual --preferred-challenges dns \
  -d pds.example.com -d '*.pds.example.com'
```
Follow the prompts to add TXT records to your DNS. Note: manual mode doesn't auto-renew.

After obtaining the cert, update nginx to use it and reload.
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
systemctl status tranquil-pds
curl -s https://pds.example.com/xrpc/_health | jq
curl -s https://pds.example.com/.well-known/atproto-did
```
## Maintenance
View logs:
```bash
journalctl -u tranquil-pds -f
```
Update Tranquil PDS:
```bash
cd /opt/tranquil-pds
git pull
cd frontend && deno task build && cd ..
cargo build --release
systemctl stop tranquil-pds
cp target/release/tranquil-pds /usr/local/bin/
cp -r frontend/dist /var/lib/tranquil-pds/frontend
DATABASE_URL="postgres://tranquil_pds:your-secure-password@localhost:5432/pds" sqlx migrate run
systemctl start tranquil-pds
```
Backup database:
```bash
sudo -u postgres pg_dump pds > /var/backups/pds-$(date +%Y%m%d).sql
```

## Custom Homepage

Drop a `homepage.html` in `/var/lib/tranquil-pds/frontend/` and it becomes your landing page. Go nuts with it. Account dashboard is at `/app/` so you won't break anything.

```bash
cat > /var/lib/tranquil-pds/frontend/homepage.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Welcome to my PDS</title>
    <style>
        body { font-family: system-ui; max-width: 600px; margin: 100px auto; padding: 20px; }
    </style>
</head>
<body>
    <h1>Welcome to my secret PDS</h1>
    <p>This is a <a href="https://atproto.com">AT Protocol</a> Personal Data Server.</p>
    <p><a href="/app/">Sign in</a> or learn more at <a href="https://bsky.social">Bluesky</a>.</p>
</body>
</html>
EOF
```
