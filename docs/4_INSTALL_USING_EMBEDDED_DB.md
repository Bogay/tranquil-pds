# Tranquil PDS deployment using its own embedded DB

Welcome, brave one.
So you're interested in leaving relational databases behind? Raw performance? Or... perhaps you simply want to run less services on your machine?

Tranquil's embedded DB is experimental.
Risk of total data loss.

## What's the difference?

tranquil-store replaces the entire repository layer. When it is selected the server opens no postgres connection at all. The postgres service, its password secret, and the `database.url` value are all unused. Blob storage is however untouched: filesystem or S3 applies exactly as in the base guide.

2 settings select and place the store:

- `repo_backend` under `[storage]`, environment variable `REPO_BACKEND`. Set it to `"tranquil-store"`. The default is `"postgres"`.
- `data_dir` under `[tranquil_store]`, environment variable `TRANQUIL_STORE_DATA_DIR`. This is optional. It defaults to `/var/lib/tranquil-pds/store`.

So the minimum config delta is one line:

```toml
[storage]
repo_backend = "tranquil-store"
```

## That being said, here are the facts:

- At time of writing, there's no way to transfer an existing Tranquil instance from PG-backed to embedded or vice-versa. If you have an instance and you want to move to embedded, you'll have to spin it up as a new instance and migrate as you would normally.
- You will absolutely want to take backups of all users' CAR files daily of not more frequently. As usual, you *really* should have rotation keys separately stored aside somewhere in case the DB explodes in an unrecoverable way.

## Installing: a patch on the existing guides

The procedure is the one in [2_INSTALL_CONTAINERS.md](2_INSTALL_CONTAINERS.md) or [2_INSTALL_NIX.md](2_INSTALL_NIX.md). Follow your chosen guide top to bottom and apply the deltas below, otherwise exactly the same!

### Containers

Both base guides assume postgres of course, and the units couple the app to it. Dropping the database means uncoupling that out too.

Shared, regardless of init system:

1. In `config.toml`, leave `database.url` unset and add the `[storage]` block shown above.
2. Skip the database secret. No need to create `tranquil-pds-db-password`.
3. The app unit already mounts the `store` directory, so `data_dir` needs no extra setup. The `postgres` directory in the guide's `mkdir` goes unused.
4. Backup section: `pg_dump` does not apply. Back up the `data_dir` instead, which holds the metastore, eventlog, and blockstore. CAR files and rotation keys still belong in your own backup as mentioned above.

**Debian (quadlets):** Do not copy `tranquil-pds-db.container`. Drop `tranquil-pds-db` from the `systemctl start` and `systemctl enable` commands. The `After=tranquil-pds-db.service` line in `tranquil-pds-app.container` becomes a no-op with the database gone. Remove it if you want.

**Alpine (OpenRC):** Do not copy the `tranquil-pds-db` init script. The app script hard-depends on it via `need tranquil-pds-db`, so edit `tranquil-pds-app`'s `depend()` to read `need tranquil-pds-pod` instead. Without this the app needs a service that no longer exists and refuses to start. Drop `tranquil-pds-db` from the `rc-update add` command too.

### Nix

1. Set `services.tranquil-pds.settings.storage.repo_backend = "tranquil-store";`.
2. Make sure all the postgres related options are left as their default. Otherwise you might end up with a useless running instance of postgres.

That's it!!

Please report anything wrong to us immediately, so that we can make our DB better, faster, stronger!
