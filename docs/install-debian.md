# Tranquil PDS production installation on debian

This guide covers installing Tranquil PDS on Debian.

It is a "compile the thing on the server itself" -style guide.
This cop-out is because Tranquil isn't built and released via CI as of yet.

## Prerequisites

- A server :p
- Disk space enough for blobs (depends on usage; plan for ~1GB per active user as a baseline)
- A domain name pointing to your server's IP
- A wildcard TLS certificate for `*.pds.example.com` (user handles are served as subdomains)
- Root/sudo/doas access

## System setup

```bash
apt update && apt upgrade -y
apt install -y curl git build-essential pkg-config libssl-dev
```

## Install rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source ~/.cargo/env
rustup default stable
```

This installs the latest stable Rust.

## Install postgres

```bash
apt install -y postgresql postgresql-contrib
systemctl enable postgresql
systemctl start postgresql
sudo -u postgres psql -c "CREATE USER tranquil_pds WITH PASSWORD 'your-secure-password';"
sudo -u postgres psql -c "CREATE DATABASE pds OWNER tranquil_pds;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE pds TO tranquil_pds;"
```

## Create blob storage directories

```bash
mkdir -p /var/lib/tranquil/blobs
```

We'll set ownership after creating the service user.

## Install Node.js and pnpm (for frontend build)

```bash
curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
apt install -y nodejs
npm install -g pnpm
```

## Clone and build Tranquil PDS

```bash
cd /opt
git clone https://tangled.org/tranquil.farm/tranquil-pds tranquil-pds
cd tranquil-pds
cd frontend
pnpm install --frozen-lockfile
pnpm build
cd ..
cargo build --release
```

## Configure Tranquil PDS

```bash
mkdir -p /etc/tranquil-pds
cp /opt/tranquil-pds/example.toml /etc/tranquil-pds/config.toml
chmod 600 /etc/tranquil-pds/config.toml
```

Edit `/etc/tranquil-pds/config.toml` and fill in your values. Generate secrets with:
```bash
openssl rand -base64 48
```

> **Note:** Every config option can also be set via environment variables
> (see comments in `example.toml`). Environment variables always take
> precedence over the config file. You can also pass the config file path
> via the `TRANQUIL_PDS_CONFIG` env var instead of `--config`.

You can validate your configuration before starting the service:
```bash
/usr/local/bin/tranquil-pds --config /etc/tranquil-pds/config.toml validate
```

## Install frontend files

```bash
mkdir -p /var/www/tranquil-pds
cp -r /opt/tranquil-pds/frontend/dist/* /var/www/tranquil-pds/
chown -R www-data:www-data /var/www/tranquil-pds
```

## Create systemd service

```bash
useradd -r -s /sbin/nologin tranquil-pds
chown -R tranquil-pds:tranquil-pds /var/lib/tranquil
cp /opt/tranquil-pds/target/release/tranquil-pds /usr/local/bin/

cat > /etc/systemd/system/tranquil-pds.service << 'EOF'
[Unit]
Description=Tranquil PDS - AT Protocol PDS
After=network.target postgresql.service
[Service]
Type=simple
User=tranquil-pds
Group=tranquil-pds
ExecStart=/usr/local/bin/tranquil-pds --config /etc/tranquil-pds/config.toml
Restart=always
RestartSec=5
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/tranquil
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable tranquil-pds
systemctl start tranquil-pds
```

## Install and configure nginx

```bash
apt install -y nginx certbot python3-certbot-nginx

cat > /etc/nginx/sites-available/tranquil-pds << 'EOF'
server {
    listen 80;
    listen [::]:80;
    server_name pds.example.com *.pds.example.com;

    location /.well-known/acme-challenge/ {
        root /var/www/acme;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name pds.example.com *.pds.example.com;

    ssl_certificate /etc/letsencrypt/live/pds.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pds.example.com/privkey.pem;

    client_max_body_size 10G;

    root /var/www/tranquil-pds;

    location /xrpc/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_buffering off;
        proxy_request_buffering off;
    }

    location = /oauth-client-metadata.json {
        root /var/www/tranquil-pds;
        default_type application/json;
        sub_filter_once off;
        sub_filter_types application/json;
        sub_filter '__PDS_HOSTNAME__' $host;
    }

    location /oauth/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
        proxy_send_timeout 300;
    }

    location /.well-known/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /webhook/ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location = /metrics {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }

    location = /health {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }

    location = /robots.txt {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }

    location = /logo {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
    }

    location ~ ^/u/[^/]+/did\.json$ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /assets/ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        try_files $uri =404;
    }

    location /app/ {
        try_files $uri $uri/ /index.html;
    }

    location = / {
        try_files /homepage.html /index.html;
    }

    location / {
        try_files $uri $uri/ /index.html;
    }
}
EOF

ln -sf /etc/nginx/sites-available/tranquil-pds /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
mkdir -p /var/www/acme
nginx -t
systemctl reload nginx
```

## Obtain a wildcard SSL cert

User handles are served as subdomains (eg., `alice.pds.example.com`), so you need a wildcard certificate.

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

After obtaining the cert, reload nginx:
```bash
systemctl reload nginx
```

## Configure firewall if you're into that sort of thing

```bash
apt install -y ufw
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable
```

## Verify installation

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
cd frontend && pnpm install --frozen-lockfile && pnpm build && cd ..
cargo build --release
systemctl stop tranquil-pds
cp target/release/tranquil-pds /usr/local/bin/
cp -r frontend/dist/* /var/www/tranquil-pds/
systemctl start tranquil-pds
```

Tranquil should auto-migrate if there are any new migrations to be applied to the db, so you don't need to worry.

Backup database:
```bash
sudo -u postgres pg_dump pds > /var/backups/pds-$(date +%Y%m%d).sql
```

## Custom homepage

Drop a `homepage.html` in `/var/www/tranquil-pds/` and it becomes your landing page. Account dashboard is at `/app/` so you won't break anything.

```bash
cat > /var/www/tranquil-pds/homepage.html << 'EOF'
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
