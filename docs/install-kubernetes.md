# Tranquil PDS on kubernetes

If you're reaching for kubernetes for this app, you're experienced enough to know how to spin up:

- cloudnativepg (or your preferred postgres operator)
- a PersistentVolume for blob storage
- the app itself (it's just a container with some env vars)

You'll need a wildcard TLS certificate for `*.your-pds-hostname.example.com`. User handles are served as subdomains.

The container image expects:
- `DATABASE_URL` - postgres connection string
- `BLOB_STORAGE_PATH` - path to blob storage (mount a PV here)
- `BACKUP_STORAGE_PATH` - path for repo backups (optional but recommended)
- `PDS_HOSTNAME` - your PDS hostname (without protocol)
- `JWT_SECRET`, `DPOP_SECRET`, `MASTER_KEY` - generate with `openssl rand -base64 48`
- `CRAWLERS` - typically `https://bsky.network`
and more, check the .env.example.

Health check: `GET /xrpc/_health`

## Custom homepage

Mount a ConfigMap with your `homepage.html` into the container's frontend directory and it becomes your landing page. Go nuts with it. Account dashboard is at `/app/` so you won't break anything.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: pds-homepage
data:
  homepage.html: |
    <!DOCTYPE html>
    <html>
    <head><title>Welcome to my PDS</title></head>
    <body>
      <h1>Welcome to my little evil secret lab!!!</h1>
      <p><a href="/app/">Sign in</a></p>
    </body>
    </html>
```
