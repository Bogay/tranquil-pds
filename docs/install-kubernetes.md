# Tranquil PDS on Kubernetes

If you're reaching for kubernetes for this app, you're experienced enough to know how to spin up:

- cloudnativepg (or your preferred postgres operator)
- valkey
- s3-compatible object storage (minio operator, or just use a managed service)
- the app itself (it's just a container with some env vars)

You'll need a wildcard TLS certificate for `*.your-pds-hostname.example.com`. User handles are served as subdomains.

The container image expects:
- `DATABASE_URL` - postgres connection string
- `S3_ENDPOINT`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `S3_BUCKET`
- `VALKEY_URL` - redis:// connection string
- `PDS_HOSTNAME` - your PDS hostname (without protocol)
- `JWT_SECRET`, `DPOP_SECRET`, `MASTER_KEY` - generate with `openssl rand -base64 48`
- `CRAWLERS` - typically `https://bsky.network`
and more, check the .env.example.

Health check: `GET /xrpc/_health`

