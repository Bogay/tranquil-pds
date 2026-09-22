# Tranquil PDS production deployment on Alpine Linux

This guide covers installing Tranquil PDS on Alpine Linux with OpenRC via the upstream package.

## Prerequisites

- A server :p
- Disk space for blobs, around* 1GB per active user as a baseline
- A domain name pointing to your server's IP
- A **wildcard TLS certificate** for `*.pds.example.com`, since user handles are served as subdomains

> 🦪 Lewis**
>
> * "around" here meaning "at absolute least!"
>
> > 🍂 June
> >
> > ** hi Lewis !

## Installation

First, ensure you have the [testing repository](https://wiki.alpinelinux.org/wiki/Repositories#Using_testing_repository) enabled in your `/etc/apk/repositories`, with:
```
@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing
```

> 🍂 June
>
> There's a MR open to move the package to the community repository ([!108614](https://gitlab.alpinelinux.org/alpine/aports/-/merge_requests/108614))

Install the upstream package with:
```sh
apk add tranquil-pds@testing
```

This, by default, will:
- Install the server binary, as well as the frontend, default config, and OpenRC service files;
- Create and configure the `tranquil-pds` system user.

## Database Configuration

PostgreSQL is not a direct package dependency, so it needs to be installed and configured separately.
Install and start it with:
```sh
apk add postgresql
grep 'port=' /etc/conf.d/postgresql # check/configure the port
/etc/init.d/postgresql start
```

Create the PDS role and database (as the `postgres` user) with:
```sh
psql \
  -c 'CREATE ROLE "tranquil-pds" WITH LOGIN;' \
  -c 'CREATE DATABASE "tranquil-pds" OWNER "tranquil-pds";'
```

Set the following options in your config file (`/etc/tranquil-pds/config.toml`):
```toml
[server]
hostname = "pds.example.com"

[database]
url = "postgresql:///tranquil-pds?host=/run/postgresql"

[storage]
repo_backend = "postgres"

# as well as other required options in [secrets]
```

## Server Configuration

Optionally review the service options in `/etc/conf.d/tranquil-pds`.

Start the service with:
```sh
/etc/init.d/tranquil-pds start
```

The logs will be saved to `/var/log/tranquil-pds.log`.

## Reverse Proxy Configuration

You will probably also want to run a reverse proxy like [Nginx](https://wiki.alpinelinux.org/wiki/Nginx) or [Caddy](https://wiki.alpinelinux.org/wiki/Caddy).
Refer to their respective Alpine Wiki pages for instructions.

An example Nginx configuration for Tranquil can be found in [nginx.conf](https://tangled.org/tranquil.farm/tranquil-pds/blob/main/nginx.conf).
