#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

if ! grep -qi "debian" /etc/os-release 2>/dev/null; then
    log_warn "This script is designed for Debian. Proceed with caution on other distros."
fi

nuke_installation() {
    log_warn "NUKING EXISTING INSTALLATION"
    log_info "Stopping services..."
    systemctl stop tranquil-pds 2>/dev/null || true
    systemctl disable tranquil-pds 2>/dev/null || true

    log_info "Removing Tranquil PDS files..."
    rm -rf /opt/tranquil-pds
    rm -rf /var/lib/tranquil-pds
    rm -f /usr/local/bin/tranquil-pds
    rm -f /usr/local/bin/tranquil-pds-sendmail
    rm -f /usr/local/bin/tranquil-pds-mailq
    rm -rf /var/spool/tranquil-pds-mail
    rm -f /etc/systemd/system/tranquil-pds.service
    systemctl daemon-reload

    log_info "Removing Tranquil PDS configuration..."
    rm -rf /etc/tranquil-pds

    log_info "Dropping postgres database and user..."
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS pds;" 2>/dev/null || true
    sudo -u postgres psql -c "DROP USER IF EXISTS tranquil_pds;" 2>/dev/null || true

    log_info "Removing blob storage..."
    rm -rf /var/lib/tranquil 2>/dev/null || true

    log_info "Removing nginx config..."
    rm -f /etc/nginx/sites-enabled/tranquil-pds
    rm -f /etc/nginx/sites-available/tranquil-pds
    systemctl reload nginx 2>/dev/null || true

    log_success "Previous installation nuked"
}

if [[ -f /etc/tranquil-pds/tranquil-pds.env ]] || [[ -d /opt/tranquil-pds ]] || [[ -f /usr/local/bin/tranquil-pds ]]; then
    log_warn "Existing installation detected"
    echo ""
    echo "Options:"
    echo "  1) Nuke everything and start fresh (destroys database!)"
    echo "  2) Continue with existing installation (idempotent update)"
    echo "  3) Exit"
    echo ""
    read -p "Choose an option [1/2/3]: " INSTALL_CHOICE

    case "$INSTALL_CHOICE" in
        1)
            echo ""
            log_warn "This will DELETE:"
            echo "  - PostgreSQL database 'pds' and all data"
            echo "  - All Tranquil PDS configuration and credentials"
            echo "  - All source code in /opt/tranquil-pds"
            echo "  - All blobs in /var/lib/tranquil/"
            echo ""
            read -p "Type 'NUKE' to confirm: " CONFIRM_NUKE
            if [[ "$CONFIRM_NUKE" == "NUKE" ]]; then
                nuke_installation
            else
                log_error "Nuke cancelled"
                exit 1
            fi
            ;;
        2)
            log_info "Continuing with existing installation..."
            ;;
        3)
            exit 0
            ;;
        *)
            log_error "Invalid option"
            exit 1
            ;;
    esac
fi

echo ""
log_info "Tranquil PDS Installation Script for Debian"
echo ""

get_public_ips() {
    IPV4=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null || curl -4 -s --max-time 5 icanhazip.com 2>/dev/null || echo "Could not detect")
    IPV6=$(curl -6 -s --max-time 5 ifconfig.me 2>/dev/null || curl -6 -s --max-time 5 icanhazip.com 2>/dev/null || echo "")
}

log_info "Detecting public IP addresses..."
get_public_ips
echo "  IPv4: ${IPV4}"
[[ -n "$IPV6" ]] && echo "  IPv6: ${IPV6}"
echo ""

read -p "Enter your PDS domain (eg., pds.example.com): " PDS_DOMAIN
if [[ -z "$PDS_DOMAIN" ]]; then
    log_error "Domain cannot be empty"
    exit 1
fi

read -p "Enter your email for Let's Encrypt: " CERTBOT_EMAIL
if [[ -z "$CERTBOT_EMAIL" ]]; then
    log_error "Email cannot be empty"
    exit 1
fi

echo ""
log_info "DNS records required (create these now if you haven't):"
echo ""
echo "  ${PDS_DOMAIN}      A      ${IPV4}"
[[ -n "$IPV6" ]] && echo "  ${PDS_DOMAIN}      AAAA   ${IPV6}"
echo "  *.${PDS_DOMAIN}    A      ${IPV4}    (for user handles)"
[[ -n "$IPV6" ]] && echo "  *.${PDS_DOMAIN}    AAAA   ${IPV6}    (for user handles)"
echo ""
read -p "Have you created these DNS records? (y/N): " DNS_CONFIRMED
if [[ ! "$DNS_CONFIRMED" =~ ^[Yy]$ ]]; then
    log_warn "Please create the DNS records and run this script again."
    exit 0
fi

CREDENTIALS_FILE="/etc/tranquil-pds/.credentials"
if [[ -f "$CREDENTIALS_FILE" ]]; then
    log_info "Loading existing credentials..."
    source "$CREDENTIALS_FILE"
else
    log_info "Generating secrets..."
    JWT_SECRET=$(openssl rand -base64 48)
    DPOP_SECRET=$(openssl rand -base64 48)
    MASTER_KEY=$(openssl rand -base64 48)
    DB_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)

    mkdir -p /etc/tranquil-pds
    cat > "$CREDENTIALS_FILE" << EOF
JWT_SECRET="$JWT_SECRET"
DPOP_SECRET="$DPOP_SECRET"
MASTER_KEY="$MASTER_KEY"
DB_PASSWORD="$DB_PASSWORD"
EOF
    chmod 600 "$CREDENTIALS_FILE"
    log_success "Secrets generated"
fi

log_info "Checking swap space..."
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_SWAP_KB=$(grep SwapTotal /proc/meminfo | awk '{print $2}')

if [[ $TOTAL_SWAP_KB -lt 2000000 ]]; then
    if [[ ! -f /swapfile ]]; then
        log_info "Adding swap space for compilation..."
        SWAP_SIZE="4G"
        [[ $TOTAL_MEM_KB -ge 4000000 ]] && SWAP_SIZE="2G"
        fallocate -l $SWAP_SIZE /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
        log_success "Swap added ($SWAP_SIZE)"
    else
        swapon /swapfile 2>/dev/null || true
    fi
fi

log_info "Updating system packages..."
apt update && apt upgrade -y

log_info "Installing build dependencies..."
apt install -y curl git build-essential pkg-config libssl-dev ca-certificates gnupg lsb-release unzip xxd

log_info "Installing postgres..."
apt install -y postgresql postgresql-contrib
systemctl enable postgresql
systemctl start postgresql
sudo -u postgres psql -c "CREATE USER tranquil_pds WITH PASSWORD '${DB_PASSWORD}';" 2>/dev/null || \
    sudo -u postgres psql -c "ALTER USER tranquil_pds WITH PASSWORD '${DB_PASSWORD}';"
sudo -u postgres psql -c "CREATE DATABASE pds OWNER tranquil_pds;" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE pds TO tranquil_pds;"
log_success "postgres configured"

log_info "Creating blob storage directories..."
mkdir -p /var/lib/tranquil/blobs
log_success "Blob storage directories created"

log_info "Installing rust..."
if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi
if ! command -v rustc &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

log_info "Installing Node.js..."
if ! command -v node &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_24.x | bash -
    apt install -y nodejs
fi

log_info "Installing pnpm..."
if ! command -v pnpm &>/dev/null; then
    npm install -g pnpm
fi

log_info "Cloning Tranquil PDS..."
if [[ ! -d /opt/tranquil-pds ]]; then
    git clone https://tangled.org/tranquil.farm/tranquil-pds /opt/tranquil-pds
else
    cd /opt/tranquil-pds && git pull
fi
cd /opt/tranquil-pds

log_info "Building frontend..."
cd frontend && pnpm install --frozen-lockfile && pnpm build && cd ..
log_success "Frontend built"

log_info "Building Tranquil PDS (this takes a while)..."
source "$HOME/.cargo/env"
if [[ $TOTAL_MEM_KB -lt 4000000 ]]; then
    log_info "Low memory - limiting parallel jobs"
    CARGO_BUILD_JOBS=1 cargo build --release
else
    cargo build --release
fi
log_success "Tranquil PDS built"

log_info "Running migrations..."
cargo install sqlx-cli --no-default-features --features postgres
export DATABASE_URL="postgres://tranquil_pds:${DB_PASSWORD}@localhost:5432/pds"
"$HOME/.cargo/bin/sqlx" migrate run
log_success "Migrations complete"

log_info "Setting up mail trap..."
mkdir -p /var/spool/tranquil-pds-mail
chmod 1777 /var/spool/tranquil-pds-mail

cat > /usr/local/bin/tranquil-pds-sendmail << 'SENDMAIL_EOF'
#!/bin/bash
MAIL_DIR="/var/spool/tranquil-pds-mail"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RANDOM_ID=$(head -c 4 /dev/urandom | xxd -p)
MAIL_FILE="${MAIL_DIR}/${TIMESTAMP}-${RANDOM_ID}.eml"
mkdir -p "$MAIL_DIR"
{
    echo "X-Tranquil-PDS-Received: $(date -Iseconds)"
    echo "X-Tranquil-PDS-Args: $*"
    echo ""
    cat
} > "$MAIL_FILE"
chmod 644 "$MAIL_FILE"
exit 0
SENDMAIL_EOF
chmod +x /usr/local/bin/tranquil-pds-sendmail

cat > /usr/local/bin/tranquil-pds-mailq << 'MAILQ_EOF'
#!/bin/bash
MAIL_DIR="/var/spool/tranquil-pds-mail"
case "${1:-list}" in
    list)
        ls -lt "$MAIL_DIR"/*.eml 2>/dev/null | head -20 || echo "No emails"
        ;;
    latest)
        f=$(ls -t "$MAIL_DIR"/*.eml 2>/dev/null | head -1)
        [[ -f "$f" ]] && cat "$f" || echo "No emails"
        ;;
    clear)
        rm -f "$MAIL_DIR"/*.eml
        echo "Cleared"
        ;;
    count)
        ls -1 "$MAIL_DIR"/*.eml 2>/dev/null | wc -l
        ;;
    [0-9]*)
        f=$(ls -t "$MAIL_DIR"/*.eml 2>/dev/null | sed -n "${1}p")
        [[ -f "$f" ]] && cat "$f" || echo "Not found"
        ;;
    *)
        [[ -f "$MAIL_DIR/$1" ]] && cat "$MAIL_DIR/$1" || echo "Usage: tranquil-pds-mailq [list|latest|clear|count|N]"
        ;;
esac
MAILQ_EOF
chmod +x /usr/local/bin/tranquil-pds-mailq

log_info "Creating Tranquil PDS configuration..."
cat > /etc/tranquil-pds/tranquil-pds.env << EOF
SERVER_HOST=127.0.0.1
SERVER_PORT=3000
PDS_HOSTNAME=${PDS_DOMAIN}
DATABASE_URL=postgres://tranquil_pds:${DB_PASSWORD}@localhost:5432/pds
DATABASE_MAX_CONNECTIONS=100
DATABASE_MIN_CONNECTIONS=10
BLOB_STORAGE_PATH=/var/lib/tranquil/blobs
JWT_SECRET=${JWT_SECRET}
DPOP_SECRET=${DPOP_SECRET}
MASTER_KEY=${MASTER_KEY}
PLC_DIRECTORY_URL=https://plc.directory
CRAWLERS=https://bsky.network
AVAILABLE_USER_DOMAINS=${PDS_DOMAIN}
MAIL_FROM_ADDRESS=noreply@${PDS_DOMAIN}
MAIL_FROM_NAME=Tranquil PDS
SENDMAIL_PATH=/usr/local/bin/tranquil-pds-sendmail
EOF
chmod 600 /etc/tranquil-pds/tranquil-pds.env

log_info "Installing Tranquil PDS..."
id -u tranquil-pds &>/dev/null || useradd -r -s /sbin/nologin tranquil-pds
cp /opt/tranquil-pds/target/release/tranquil-server /usr/local/bin/tranquil-pds
mkdir -p /var/lib/tranquil-pds
cp -r /opt/tranquil-pds/frontend/dist /var/lib/tranquil-pds/frontend
chown -R tranquil-pds:tranquil-pds /var/lib/tranquil-pds
chown -R tranquil-pds:tranquil-pds /var/lib/tranquil

cat > /etc/systemd/system/tranquil-pds.service << 'EOF'
[Unit]
Description=Tranquil PDS - AT Protocol PDS
After=network.target postgresql.service

[Service]
Type=simple
User=tranquil-pds
Group=tranquil-pds
EnvironmentFile=/etc/tranquil-pds/tranquil-pds.env
ExecStart=/usr/local/bin/tranquil-pds
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
log_success "Tranquil PDS service started"

log_info "Installing nginx..."
apt install -y nginx
cat > /etc/nginx/sites-available/tranquil-pds << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${PDS_DOMAIN} *.${PDS_DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        client_max_body_size 100M;
    }
}
EOF

ln -sf /etc/nginx/sites-available/tranquil-pds /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx
log_success "nginx configured"

log_info "Configuring firewall..."
apt install -y ufw
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable
log_success "Firewall configured"

echo ""
log_info "Obtaining wildcard SSL certificate..."
echo ""
echo "User handles are served as subdomains (eg., alice.${PDS_DOMAIN}),"
echo "so you need a wildcard certificate. This requires DNS validation."
echo ""
echo "You'll need to add a TXT record to your DNS when prompted."
echo ""
read -p "Ready to proceed? (y/N): " CERT_READY

if [[ "$CERT_READY" =~ ^[Yy]$ ]]; then
    apt install -y certbot python3-certbot-nginx

    log_info "Running certbot with DNS challenge..."
    echo ""
    echo "When prompted, add the TXT record to your DNS, wait a minute"
    echo "for propagation, then press Enter to continue."
    echo ""

    if certbot certonly --manual --preferred-challenges dns \
        -d "${PDS_DOMAIN}" -d "*.${PDS_DOMAIN}" \
        --email "${CERTBOT_EMAIL}" --agree-tos; then

        cat > /etc/nginx/sites-available/tranquil-pds << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${PDS_DOMAIN} *.${PDS_DOMAIN};

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${PDS_DOMAIN} *.${PDS_DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${PDS_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${PDS_DOMAIN}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        client_max_body_size 100M;
    }
}
EOF
        nginx -t && systemctl reload nginx
        log_success "Wildcard SSL certificate installed"

        echo ""
        log_warn "Certificate renewal note:"
        echo "Manual DNS challenges don't auto-renew. Before expiry, run:"
        echo "  certbot renew --manual"
        echo ""
        echo "For auto-renewal, consider using a DNS provider plugin:"
        echo "  apt install python3-certbot-dns-cloudflare  # or your provider"
        echo ""
    else
        log_warn "Wildcard cert failed. You can retry later with:"
        echo "  certbot certonly --manual --preferred-challenges dns \\"
        echo "    -d ${PDS_DOMAIN} -d '*.${PDS_DOMAIN}'"
    fi
else
    log_warn "Skipping SSL. Your PDS is running on HTTP only."
    echo "To add SSL later, run:"
    echo "  certbot certonly --manual --preferred-challenges dns \\"
    echo "    -d ${PDS_DOMAIN} -d '*.${PDS_DOMAIN}'"
fi

log_info "Verifying installation..."
sleep 3
if curl -s "http://localhost:3000/xrpc/_health" | grep -q "version"; then
    log_success "Tranquil PDS is responding"
else
    log_warn "Tranquil PDS may still be starting. Check: journalctl -u tranquil-pds -f"
fi

echo ""
log_success "Installation complete"
echo ""
echo "PDS: https://${PDS_DOMAIN}"
echo ""
echo "Credentials (also in /etc/tranquil-pds/.credentials):"
echo "  DB password: ${DB_PASSWORD}"
echo ""
echo "Data locations:"
echo "  Blobs:   /var/lib/tranquil/blobs"
echo ""
echo "Commands:"
echo "  journalctl -u tranquil-pds -f    # logs"
echo "  systemctl restart tranquil-pds   # restart"
echo "  tranquil-pds-mailq               # view trapped emails"
echo ""
