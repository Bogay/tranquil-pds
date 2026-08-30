DEV_DIR="${XDG_STATE_HOME:-$HOME/.local/state}/tranquil-dev-services"
ENV_FILE="$DEV_DIR/services.env"
PG_DIR="$DEV_DIR/pg"
PG_LOG="$DEV_DIR/pg.log"
PG_PORT=54329
PG_DATABASE=tranquil
GARAGE_DIR="$DEV_DIR/garage"
GARAGE_CONF="$GARAGE_DIR/garage.toml"
GARAGE_LOG="$DEV_DIR/garage.log"
GARAGE_PID_FILE="$DEV_DIR/garage.pid"
GARAGE_S3_PORT=3990
GARAGE_RPC_PORT=3901
GARAGE_RPC_SECRET=6465767365637265746465767365637265746465767365637265746465767365
S3_BUCKET=tranquil-dev
LOOPBACK="::1"

if [ "$(id -u)" = 0 ]; then
  echo "PostgreSQL won't run as root, use a lowerclass user" >&2
  exit 1
fi

write_garage_conf() {
  mkdir -p "$GARAGE_DIR/meta" "$GARAGE_DIR/data"
  cat > "$GARAGE_CONF" << EOF
metadata_dir = "$GARAGE_DIR/meta"
data_dir = "$GARAGE_DIR/data"
db_engine = "lmdb"
replication_factor = 1
rpc_bind_addr = "[$LOOPBACK]:$GARAGE_RPC_PORT"
rpc_public_addr = "[$LOOPBACK]:$GARAGE_RPC_PORT"
rpc_secret = "$GARAGE_RPC_SECRET"

[s3_api]
s3_region = "tranquil"
api_bind_addr = "[$LOOPBACK]:$GARAGE_S3_PORT"
root_domain = ".s3.tranquil.dev"
EOF
}

garage_cli() {
  garage -c "$GARAGE_CONF" "$@"
}

port_is_open() {
  echo 2>/dev/null > "/dev/tcp/$LOOPBACK/$1"
}

wait_for_port() {
  local port=$1
  for _ in $(seq 1 60); do
    if port_is_open "$port"; then
      return 0
    fi
    sleep 0.5
  done
  echo "Nothing spun up on [$LOOPBACK]:$port" >&2
  return 1
}

start_postgres() {
  if [ -f "$PG_DIR/postmaster.pid" ] && pg_ctl -D "$PG_DIR" status >/dev/null 2>&1; then
    echo "Postgres is already running"
    return
  fi
  if [ ! -f "$PG_DIR/PG_VERSION" ]; then
    mkdir -p "$PG_DIR"
    initdb -D "$PG_DIR" -U postgres --auth=trust >/dev/null
  fi
  if ! pg_ctl -D "$PG_DIR" -l "$PG_LOG" -w \
    -o "-p $PG_PORT -k $PG_DIR -c listen_addresses=$LOOPBACK" start >/dev/null; then
    echo "Postgres wouldn't start. Please inspect $PG_LOG" >&2
    exit 1
  fi
  wait_for_port "$PG_PORT"
  if ! psql -h "$LOOPBACK" -p "$PG_PORT" -U postgres -lqt 2>/dev/null | cut -d'|' -f1 | grep -qw "$PG_DATABASE"; then
    createdb -h "$LOOPBACK" -p "$PG_PORT" -U postgres "$PG_DATABASE"
  fi
  echo "PostgreSQL is up on [$LOOPBACK]:$PG_PORT"
}

layout_version() {
  garage_cli layout show 2>/dev/null |
    awk '/Current cluster layout version:/{print $NF; found=1} END{if (!found) print 0}'
}

start_garage() {
  if port_is_open "$GARAGE_S3_PORT"; then
    echo "Garage object storage is already running"
  else
    write_garage_conf
    garage -c "$GARAGE_CONF" server >> "$GARAGE_LOG" 2>&1 &
    echo $! > "$GARAGE_PID_FILE"
    wait_for_port "$GARAGE_S3_PORT"
  fi

  local node_id
  node_id=$(garage_cli node id 2>/dev/null |
    awk 'match($0, /^[0-9a-f]{64}/) {print substr($0, RSTART, RLENGTH); exit}')
  if [ -z "$node_id" ]; then
    echo "Couldn't read the garage node id, please inspect $GARAGE_LOG" >&2
    exit 1
  fi
  if ! garage_cli layout show 2>/dev/null | grep -q "${node_id:0:16}"; then
    garage_cli layout assign "$node_id" -z dev -c 1GB
    garage_cli layout apply --version "$(($(layout_version) + 1))"
  fi
  if ! garage_cli bucket list | grep -qw "$S3_BUCKET"; then
    garage_cli bucket create "$S3_BUCKET" >/dev/null
  fi
  if ! garage_cli key list | grep -qw "$S3_BUCKET"; then
    garage_cli key create "$S3_BUCKET" >/dev/null
  fi
  garage_cli bucket allow --read --write --owner "$S3_BUCKET" --key "$S3_BUCKET" >/dev/null
  echo "Garage is up on [$LOOPBACK]:$GARAGE_S3_PORT"
}

write_env() {
  local access_key secret_key
  access_key=$(garage_cli key info "$S3_BUCKET" | awk '/^Key ID:/{print $3}')
  secret_key=$(garage_cli key info --show-secret "$S3_BUCKET" | awk '/^Secret key:/{print $3}')
  if [ -z "$access_key" ] || [ -z "$secret_key" ]; then
    echo "Garage didn't show credentials for key $S3_BUCKET, please see $GARAGE_LOG" >&2
    exit 1
  fi
  cat > "$ENV_FILE" << EOF
export DATABASE_URL="postgres://postgres@[$LOOPBACK]:$PG_PORT/$PG_DATABASE"
export TRANQUIL_PDS_TEST_INFRA_READY="1"
export TRANQUIL_PDS_ALLOW_INSECURE_SECRETS="1"
export DISABLE_RATE_LIMITING="1"
export TRANQUIL_LEXICON_OFFLINE="1"
export SKIP_IMPORT_VERIFICATION="1"
export BLOB_STORAGE_BACKEND="s3"
export S3_ENDPOINT="http://[$LOOPBACK]:$GARAGE_S3_PORT"
export S3_BUCKET="$S3_BUCKET"
export AWS_ACCESS_KEY_ID="$access_key"
export AWS_SECRET_ACCESS_KEY="$secret_key"
export AWS_REGION="tranquil"
EOF
}

stop_services() {
  if [ -f "$PG_DIR/postmaster.pid" ]; then
    pg_ctl -D "$PG_DIR" -m fast -w stop >/dev/null 2>&1 || true
  fi
  if [ -f "$GARAGE_PID_FILE" ]; then
    local pid
    pid=$(cat "$GARAGE_PID_FILE")
    if [ "$(readlink "/proc/$pid/exe" 2>/dev/null)" = "$(command -v garage)" ]; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 60); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.5
      done
      kill -0 "$pid" 2>/dev/null && echo "Garage $pid is taking its sweet time to exit" >&2
    fi
    rm -f "$GARAGE_PID_FILE"
  fi
  if port_is_open "$GARAGE_S3_PORT"; then
    echo "Smth is still listening on [$LOOPBACK]:$GARAGE_S3_PORT, not to do with us" >&2
  fi
  echo "Services have been stopped"
}

case "${1:-}" in
  up)
    mkdir -p "$DEV_DIR"
    start_postgres
    start_garage
    write_env
    echo "env at $ENV_FILE"
    ;;
  down)
    stop_services
    ;;
  env)
    cat "$ENV_FILE"
    ;;
  *)
    echo "usage: tranquil-dev-services <up|down|env>" >&2
    exit 1
    ;;
esac
