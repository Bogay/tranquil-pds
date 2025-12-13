#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════════╗"
echo "║              BSPDS Installation Script for Debian                 ║"
echo "║           AT Protocol Personal Data Server in Rust                ║"
echo "╚═══════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

get_public_ips() {
    IPV4=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null || curl -4 -s --max-time 5 icanhazip.com 2>/dev/null || echo "Could not detect")
    IPV6=$(curl -6 -s --max-time 5 ifconfig.me 2>/dev/null || curl -6 -s --max-time 5 icanhazip.com 2>/dev/null || echo "Not available")
}

log_info "Detecting public IP addresses..."
get_public_ips

echo ""
echo -e "${CYAN}Your server's public IPs:${NC}"
echo -e "  IPv4: ${GREEN}${IPV4}${NC}"
echo -e "  IPv6: ${GREEN}${IPV6}${NC}"
echo ""

read -p "Enter your PDS domain (e.g., pds.example.com): " PDS_DOMAIN
if [[ -z "$PDS_DOMAIN" ]]; then
    log_error "Domain cannot be empty"
    exit 1
fi

read -p "Enter your email for Let's Encrypt notifications: " CERTBOT_EMAIL
if [[ -z "$CERTBOT_EMAIL" ]]; then
    log_error "Email cannot be empty"
    exit 1
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${YELLOW}DNS RECORDS REQUIRED${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Before continuing, create these DNS records at your registrar:"
echo ""
echo -e "${GREEN}A Record:${NC}"
echo "  Name:  ${PDS_DOMAIN}"
echo "  Type:  A"
echo "  Value: ${IPV4}"
echo ""
if [[ "$IPV6" != "Not available" ]]; then
echo -e "${GREEN}AAAA Record:${NC}"
echo "  Name:  ${PDS_DOMAIN}"
echo "  Type:  AAAA"
echo "  Value: ${IPV6}"
echo ""
fi
echo -e "${GREEN}Wildcard A Record (for user handles):${NC}"
echo "  Name:  *.${PDS_DOMAIN}"
echo "  Type:  A"
echo "  Value: ${IPV4}"
echo ""
if [[ "$IPV6" != "Not available" ]]; then
echo -e "${GREEN}Wildcard AAAA Record (for user handles):${NC}"
echo "  Name:  *.${PDS_DOMAIN}"
echo "  Type:  AAAA"
echo "  Value: ${IPV6}"
echo ""
fi
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
read -p "Have you created these DNS records? (y/N): " DNS_CONFIRMED
if [[ ! "$DNS_CONFIRMED" =~ ^[Yy]$ ]]; then
    log_warn "Please create the DNS records and run this script again."
    exit 0
fi

CREDENTIALS_FILE="/etc/bspds/.credentials"

if [[ -f "$CREDENTIALS_FILE" ]]; then
    log_info "Loading existing credentials from previous installation..."
    source "$CREDENTIALS_FILE"
    log_success "Credentials loaded"
else
    log_info "Generating secure secrets..."
    JWT_SECRET=$(openssl rand -base64 48)
    DPOP_SECRET=$(openssl rand -base64 48)
    MASTER_KEY=$(openssl rand -base64 48)
    DB_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)
    MINIO_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 32)

    mkdir -p /etc/bspds
    cat > "$CREDENTIALS_FILE" << EOF
JWT_SECRET="$JWT_SECRET"
DPOP_SECRET="$DPOP_SECRET"
MASTER_KEY="$MASTER_KEY"
DB_PASSWORD="$DB_PASSWORD"
MINIO_PASSWORD="$MINIO_PASSWORD"
EOF
    chmod 600 "$CREDENTIALS_FILE"
    log_success "Secrets generated and saved"
fi

log_info "Checking swap space..."
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_SWAP_KB=$(grep SwapTotal /proc/meminfo | awk '{print $2}')

if [[ $TOTAL_SWAP_KB -lt 2000000 ]]; then
    log_info "Adding swap space (needed for compilation)..."
    if [[ ! -f /swapfile ]]; then
        SWAP_SIZE="4G"
        if [[ $TOTAL_MEM_KB -lt 2000000 ]]; then
            SWAP_SIZE="4G"
        elif [[ $TOTAL_MEM_KB -lt 4000000 ]]; then
            SWAP_SIZE="2G"
        fi
        fallocate -l $SWAP_SIZE /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
        log_success "Swap space added ($SWAP_SIZE)"
    else
        swapon /swapfile 2>/dev/null || true
        log_success "Existing swap enabled"
    fi
else
    log_success "Sufficient swap already configured"
fi

log_info "Updating system packages..."
apt update && apt upgrade -y
log_success "System updated"

log_info "Installing build dependencies..."
apt install -y curl git build-essential pkg-config libssl-dev ca-certificates gnupg lsb-release unzip xxd
log_success "Build dependencies installed"

log_info "Installing postgres..."
apt install -y postgresql postgresql-contrib
systemctl enable postgresql
systemctl start postgresql

sudo -u postgres psql -c "CREATE USER bspds WITH PASSWORD '${DB_PASSWORD}';" 2>/dev/null || \
    sudo -u postgres psql -c "ALTER USER bspds WITH PASSWORD '${DB_PASSWORD}';"
sudo -u postgres psql -c "CREATE DATABASE pds OWNER bspds;" 2>/dev/null || true
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE pds TO bspds;"
log_success "postgres installed and configured"

log_info "Installing valkey..."
apt install -y valkey || {
    log_warn "valkey not in repos, trying redis..."
    apt install -y redis-server
    systemctl enable redis-server
    systemctl start redis-server
}
systemctl enable valkey-server 2>/dev/null || true
systemctl start valkey-server 2>/dev/null || true
log_success "valkey/redis installed"

log_info "Installing minio..."
if [[ ! -f /usr/local/bin/minio ]]; then
    ARCH=$(dpkg --print-architecture)
    if [[ "$ARCH" == "amd64" ]]; then
        curl -fsSL -o /tmp/minio https://dl.min.io/server/minio/release/linux-amd64/minio
    elif [[ "$ARCH" == "arm64" ]]; then
        curl -fsSL -o /tmp/minio https://dl.min.io/server/minio/release/linux-arm64/minio
    else
        log_error "Unsupported architecture: $ARCH"
        exit 1
    fi
    chmod +x /tmp/minio
    mv /tmp/minio /usr/local/bin/
fi

mkdir -p /var/lib/minio/data
id -u minio-user &>/dev/null || useradd -r -s /sbin/nologin minio-user
chown -R minio-user:minio-user /var/lib/minio

cat > /etc/default/minio << EOF
MINIO_ROOT_USER=minioadmin
MINIO_ROOT_PASSWORD=${MINIO_PASSWORD}
MINIO_VOLUMES="/var/lib/minio/data"
MINIO_OPTS="--console-address :9001"
EOF
chmod 600 /etc/default/minio

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
log_success "minio installed"

log_info "Waiting for minio to start..."
sleep 5

log_info "Installing minio client and creating bucket..."
if [[ ! -f /usr/local/bin/mc ]]; then
    ARCH=$(dpkg --print-architecture)
    if [[ "$ARCH" == "amd64" ]]; then
        curl -fsSL -o /tmp/mc https://dl.min.io/client/mc/release/linux-amd64/mc
    elif [[ "$ARCH" == "arm64" ]]; then
        curl -fsSL -o /tmp/mc https://dl.min.io/client/mc/release/linux-arm64/mc
    fi
    chmod +x /tmp/mc
    mv /tmp/mc /usr/local/bin/
fi

mc alias remove local 2>/dev/null || true
mc alias set local http://localhost:9000 minioadmin "${MINIO_PASSWORD}" --api S3v4
mc mb local/pds-blobs --ignore-existing
log_success "minio bucket created"

log_info "Installing rust..."
if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi
if ! command -v rustc &>/dev/null; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi
log_success "rust installed"

log_info "Installing deno..."
export PATH="$HOME/.deno/bin:$PATH"
if ! command -v deno &>/dev/null && [[ ! -f "$HOME/.deno/bin/deno" ]]; then
    curl -fsSL https://deno.land/install.sh | sh
    grep -q 'deno/bin' ~/.bashrc 2>/dev/null || echo 'export PATH="$HOME/.deno/bin:$PATH"' >> ~/.bashrc
fi
log_success "deno installed"

log_info "Cloning BSPDS..."
if [[ ! -d /opt/bspds ]]; then
    git clone https://tangled.org/lewis.moe/bspds-sandbox /opt/bspds
else
    log_warn "/opt/bspds already exists, pulling latest..."
    cd /opt/bspds && git pull
fi
cd /opt/bspds
log_success "BSPDS cloned"

log_info "Building frontend..."
cd /opt/bspds/frontend
"$HOME/.deno/bin/deno" task build
cd /opt/bspds
log_success "Frontend built"

log_info "Building BSPDS (this may take a while)..."
source "$HOME/.cargo/env"
NPROC=$(nproc)
if [[ $TOTAL_MEM_KB -lt 4000000 ]]; then
    log_info "Low memory detected, limiting parallel jobs..."
    CARGO_BUILD_JOBS=1 cargo build --release
else
    cargo build --release
fi
log_success "BSPDS built"

log_info "Installing sqlx-cli and running migrations..."
cargo install sqlx-cli --no-default-features --features postgres
export DATABASE_URL="postgres://bspds:${DB_PASSWORD}@localhost:5432/pds"
"$HOME/.cargo/bin/sqlx" migrate run
log_success "Migrations complete"

log_info "Setting up mail trap for testing..."
mkdir -p /var/spool/bspds-mail
chown root:root /var/spool/bspds-mail
chmod 1777 /var/spool/bspds-mail

cat > /usr/local/bin/bspds-sendmail << 'SENDMAIL_EOF'
#!/bin/bash
MAIL_DIR="/var/spool/bspds-mail"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RANDOM_ID=$(head -c 4 /dev/urandom | xxd -p)
MAIL_FILE="${MAIL_DIR}/${TIMESTAMP}-${RANDOM_ID}.eml"

mkdir -p "$MAIL_DIR"

{
    echo "X-BSPDS-Received: $(date -Iseconds)"
    echo "X-BSPDS-Args: $*"
    echo ""
    cat
} > "$MAIL_FILE"

chmod 644 "$MAIL_FILE"
echo "Mail saved to: $MAIL_FILE" >&2
exit 0
SENDMAIL_EOF
chmod +x /usr/local/bin/bspds-sendmail

cat > /usr/local/bin/bspds-mailq << 'MAILQ_EOF'
#!/bin/bash
MAIL_DIR="/var/spool/bspds-mail"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

show_help() {
    echo "bspds-mailq - View captured emails from BSPDS mail trap"
    echo ""
    echo "Usage:"
    echo "  bspds-mailq              List all captured emails"
    echo "  bspds-mailq <number>     View email by number (from list)"
    echo "  bspds-mailq <filename>   View email by filename"
    echo "  bspds-mailq latest       View the most recent email"
    echo "  bspds-mailq clear        Delete all captured emails"
    echo "  bspds-mailq watch        Watch for new emails (tail -f style)"
    echo "  bspds-mailq count        Show count of emails in queue"
    echo ""
}

list_emails() {
    if [[ ! -d "$MAIL_DIR" ]] || [[ -z "$(ls -A "$MAIL_DIR" 2>/dev/null)" ]]; then
        echo -e "${YELLOW}No emails in queue.${NC}"
        return
    fi

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  BSPDS Mail Queue${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""

    local i=1
    for f in $(ls -t "$MAIL_DIR"/*.eml 2>/dev/null); do
        local filename=$(basename "$f")
        local received=$(grep "^X-BSPDS-Received:" "$f" 2>/dev/null | cut -d' ' -f2-)
        local to=$(grep -i "^To:" "$f" 2>/dev/null | head -1 | cut -d' ' -f2-)
        local subject=$(grep -i "^Subject:" "$f" 2>/dev/null | head -1 | sed 's/^Subject: *//')

        echo -e "${BLUE}[$i]${NC} ${filename}"
        echo -e "    To: ${GREEN}${to:-unknown}${NC}"
        echo -e "    Subject: ${YELLOW}${subject:-<no subject>}${NC}"
        echo -e "    Received: ${received:-unknown}"
        echo ""
        ((i++))
    done

    echo -e "${CYAN}Total: $((i-1)) email(s)${NC}"
}

view_email() {
    local target="$1"
    local file=""

    if [[ "$target" == "latest" ]]; then
        file=$(ls -t "$MAIL_DIR"/*.eml 2>/dev/null | head -1)
    elif [[ "$target" =~ ^[0-9]+$ ]]; then
        file=$(ls -t "$MAIL_DIR"/*.eml 2>/dev/null | sed -n "${target}p")
    elif [[ -f "$MAIL_DIR/$target" ]]; then
        file="$MAIL_DIR/$target"
    elif [[ -f "$target" ]]; then
        file="$target"
    fi

    if [[ -z "$file" ]] || [[ ! -f "$file" ]]; then
        echo -e "${RED}Email not found: $target${NC}"
        return 1
    fi

    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  $(basename "$file")${NC}"
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
    cat "$file"
    echo ""
    echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
}

clear_queue() {
    local count=$(ls -1 "$MAIL_DIR"/*.eml 2>/dev/null | wc -l)
    if [[ "$count" -eq 0 ]]; then
        echo -e "${YELLOW}Queue is already empty.${NC}"
        return
    fi

    rm -f "$MAIL_DIR"/*.eml
    echo -e "${GREEN}Cleared $count email(s) from queue.${NC}"
}

watch_queue() {
    echo -e "${CYAN}Watching for new emails... (Ctrl+C to stop)${NC}"
    echo ""

    local last_count=0
    while true; do
        local current_count=$(ls -1 "$MAIL_DIR"/*.eml 2>/dev/null | wc -l)
        if [[ "$current_count" -gt "$last_count" ]]; then
            echo -e "${GREEN}[$(date +%H:%M:%S)] New email received!${NC}"
            view_email latest
            last_count=$current_count
        fi
        sleep 1
    done
}

count_queue() {
    local count=$(ls -1 "$MAIL_DIR"/*.eml 2>/dev/null | wc -l)
    echo "$count"
}

case "${1:-}" in
    ""|list)
        list_emails
        ;;
    latest|[0-9]*)
        view_email "$1"
        ;;
    clear)
        clear_queue
        ;;
    watch)
        watch_queue
        ;;
    count)
        count_queue
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        if [[ -f "$MAIL_DIR/$1" ]] || [[ -f "$1" ]]; then
            view_email "$1"
        else
            echo -e "${RED}Unknown command: $1${NC}"
            show_help
            exit 1
        fi
        ;;
esac
MAILQ_EOF
chmod +x /usr/local/bin/bspds-mailq
log_success "Mail trap configured"

log_info "Creating BSPDS configuration..."
mkdir -p /etc/bspds

cat > /etc/bspds/bspds.env << EOF
SERVER_HOST=127.0.0.1
SERVER_PORT=3000
PDS_HOSTNAME=${PDS_DOMAIN}

DATABASE_URL=postgres://bspds:${DB_PASSWORD}@localhost:5432/pds
DATABASE_MAX_CONNECTIONS=100
DATABASE_MIN_CONNECTIONS=10

S3_ENDPOINT=http://localhost:9000
AWS_REGION=us-east-1
S3_BUCKET=pds-blobs
AWS_ACCESS_KEY_ID=minioadmin
AWS_SECRET_ACCESS_KEY=${MINIO_PASSWORD}

VALKEY_URL=redis://localhost:6379

JWT_SECRET=${JWT_SECRET}
DPOP_SECRET=${DPOP_SECRET}
MASTER_KEY=${MASTER_KEY}

PLC_DIRECTORY_URL=https://plc.directory
APPVIEW_URL=https://api.bsky.app
CRAWLERS=https://bsky.network

AVAILABLE_USER_DOMAINS=${PDS_DOMAIN}

MAIL_FROM_ADDRESS=noreply@${PDS_DOMAIN}
MAIL_FROM_NAME=BSPDS
SENDMAIL_PATH=/usr/local/bin/bspds-sendmail
EOF
chmod 600 /etc/bspds/bspds.env
log_success "Configuration created"

log_info "Creating BSPDS service user..."
id -u bspds &>/dev/null || useradd -r -s /sbin/nologin bspds

cp /opt/bspds/target/release/bspds /usr/local/bin/
mkdir -p /var/lib/bspds
cp -r /opt/bspds/frontend/dist /var/lib/bspds/frontend
chown -R bspds:bspds /var/lib/bspds
log_success "BSPDS binary installed"

log_info "Creating systemd service..."
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
log_success "BSPDS service created and started"

log_info "Installing nginx..."
apt install -y nginx certbot python3-certbot-nginx
log_success "nginx installed"

log_info "Configuring nginx..."
cat > /etc/nginx/sites-available/bspds << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${PDS_DOMAIN} *.${PDS_DOMAIN};

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

ln -sf /etc/nginx/sites-available/bspds /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx
log_success "nginx configured"

log_info "Configuring firewall (ufw)..."
apt install -y ufw
ufw --force reset

ufw default deny incoming
ufw default allow outgoing

ufw allow ssh comment 'SSH'
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

ufw --force enable
log_success "Firewall configured"

log_info "Obtaining SSL certificate..."
certbot --nginx -d "${PDS_DOMAIN}" -d "*.${PDS_DOMAIN}" --email "${CERTBOT_EMAIL}" --agree-tos --non-interactive || {
    log_warn "Wildcard cert failed (requires DNS challenge). Trying single domain..."
    certbot --nginx -d "${PDS_DOMAIN}" --email "${CERTBOT_EMAIL}" --agree-tos --non-interactive
}
log_success "SSL certificate obtained"

log_info "Verifying installation..."
sleep 3
if curl -s "http://localhost:3000/xrpc/_health" | grep -q "version"; then
    log_success "BSPDS is responding!"
else
    log_warn "BSPDS may still be starting up. Check: journalctl -u bspds -f"
fi

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}            INSTALLATION COMPLETE!${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "Your PDS is now running at: ${GREEN}https://${PDS_DOMAIN}${NC}"
echo ""
echo -e "${YELLOW}IMPORTANT: Save these credentials securely!${NC}"
echo ""
echo "Database password: ${DB_PASSWORD}"
echo "MinIO password:    ${MINIO_PASSWORD}"
echo ""
echo "Configuration file: /etc/bspds/bspds.env"
echo ""
echo -e "${CYAN}Useful commands:${NC}"
echo "  journalctl -u bspds -f          # View BSPDS logs"
echo "  systemctl status bspds          # Check BSPDS status"
echo "  systemctl restart bspds         # Restart BSPDS"
echo "  curl https://${PDS_DOMAIN}/xrpc/_health  # Health check"
echo ""
echo -e "${CYAN}Mail queue (for testing):${NC}"
echo "  bspds-mailq                     # List all captured emails"
echo "  bspds-mailq latest              # View most recent email"
echo "  bspds-mailq 1                   # View email #1 from list"
echo "  bspds-mailq watch               # Watch for new emails live"
echo "  bspds-mailq clear               # Clear all captured emails"
echo ""
echo "  Emails are saved to: /var/spool/bspds-mail/"
echo ""
echo -e "${CYAN}DNS Records Summary:${NC}"
echo ""
echo "  ${PDS_DOMAIN}        A      ${IPV4}"
if [[ "$IPV6" != "Not available" ]]; then
echo "  ${PDS_DOMAIN}        AAAA   ${IPV6}"
fi
echo "  *.${PDS_DOMAIN}      A      ${IPV4}"
if [[ "$IPV6" != "Not available" ]]; then
echo "  *.${PDS_DOMAIN}      AAAA   ${IPV6}"
fi
echo ""
echo -e "${GREEN}Enjoy your new AT Protocol PDS!${NC}"
