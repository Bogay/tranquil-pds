# Known Issues

## Account migration from bsky.social

Migrating your account from bsky.social to this PDS works, but Bluesky's appview may not recognize your new signing key. This means you can post and your followers will see it, but some authenticated requests might fail with "jwt signature does not match jwt issuer".

We've been trying hard to verify that our side is correct (PLC updated, signing keys match, relays have the account) but something about how we're emitting events isn't triggering Bluesky's appview to refresh its identity data. Still investigating.

No workaround yet.
