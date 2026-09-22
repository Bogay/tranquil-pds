# Tranquil PDS deployment using its own embedded DB

Welcome, brave one.
So you're interested in leaving relational databases behind? Raw performance? Or... perhaps you simply want to run less services on your machine?

Tranquil's embedded DB is not necessarily experimental now that Mr Oyster has been running his just fine for about half a year, but still, just a *slight* risk of total data loss. Back up your data and we'd be able to nurse borked data back to health with some spit and polish.

## What's the difference?

`tranquil-store` is an alternative repository storage layer. When it's selected in the config, the server won't use postgres at all. However, blob storage won't be affected by this db-level choice, in that filesystem vs S3 will continue as a separate concern exactly as in the base guide.

Here are our settings that set up the store:

- `repo_backend` under `[storage]`, environment variable `REPO_BACKEND`. Set it to `"tranquil-store"`. (Default being `"postgres"`.)
- `data_dir` under `[tranquil_store]`, environment variable `TRANQUIL_STORE_DATA_DIR`. Optional if the above is picked! It defaults to `/var/lib/tranquil-pds/store`.

Thus the minimum config is as follows:

```toml
[storage]
repo_backend = "tranquil-store"
```

and voila!

## That being said, here are the facts:

- At time of writing, there's no way to transfer an existing Tranquil instance from PG-backed to embedded or vice-versa. If you have an instance and you want to move to embedded, you'll have to spin it up as a new instance and migrate as you would normally.
- You will absolutely want to take backups of all users' CAR files daily of not more frequently. As usual, you *really* should have rotation keys separately stored aside somewhere in case the DB explodes in an unrecoverable way.

## Installing: slight differences to existing guides

Choose-your-own-adventure based on your poison as per [2_INSTALL_CONTAINERS.md](2_INSTALL_CONTAINERS.md), [2_INSTALL_NIX.md](2_INSTALL_NIX.md), or [2_INSTALL_ALPINE.md](2_INSTALL_ALPINE.md). Follow your chosen guide top-to-bottom and apply the below changes, otherwise exactly the same!

### Containers

Both base guides assume postgres of course, and the units tie the app to pg running. Therefore, dropping the database means un-coupling those too.

Shared, regardless of init system:

1. In `config.toml`, leave `database.url` unset and add the `[storage]` block shown above.
2. Skip the database secret! No need to create `tranquil-pds-db-password`.
3. The app unit already mounts the `store` directory, so `data_dir` doesn't need any extra setup. The `postgres` dir in the guide's `mkdir` won't be used.
4. Backup section: `pg_dump` doesn't apply. Back up the `data_dir` instead, which contains the metastore, eventlog, and blockstore. CAR files and rotation keys still belong in your own separate high-level backup as mentioned above.

**Debian (quadlets):** Don't bother copying `tranquil-pds-db.container`. Drop `tranquil-pds-db` from the `systemctl start` and `systemctl enable` commands. The `After=tranquil-pds-db.service` line in `tranquil-pds-app.container` will be a no-op with the database gone. Remove it if you want!

**Alpine (OpenRC):** Don't bother copying the `tranquil-pds-db` init script. The app script hard-depends on it via `need tranquil-pds-db`, so edit `tranquil-pds-app`'s `depend()` to grab `need tranquil-pds-pod` instead. Without this, the app will need a service that doesn't actually exist anymore, and would abort at start. Leave out `tranquil-pds-db` from the `rc-update add` command too.

### Nix

1. Set `services.tranquil-pds.settings.storage.repo_backend = "tranquil-store";`.
2. Make sure all the postgres related options are left as their default. Otherwise you might end up with an unnecessarily-running instance of postgres.

That's it!!

Please report anything wrong to us immediately, so that we can make our DB better, faster, stronger!
