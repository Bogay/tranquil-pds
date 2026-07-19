-- The old insert path wrote for_account through without validating it
-- so an older row can contain any string at all
-- most often a handle or the literal 'admin' the column defaulted to
-- where the read path warns and drops whatever the Did newtype won't parse
-- so an unconverted row comes back with no for_account at all.
-- The first statement resolves the bare handles that still match a user
-- and the second covers every 'admin' row, since created_by_user is NOT NULL.
-- Nothing else converts
-- so a prefixed handle, a handle whose user has renamed since,
-- and anything that was never an identifier all stay as they are.
UPDATE invite_codes ic
SET for_account = u.did
FROM users u
WHERE LOWER(u.handle) = LOWER(ic.for_account)
  AND ic.for_account NOT LIKE 'did:%';

UPDATE invite_codes ic
SET for_account = u.did
FROM users u
WHERE u.id = ic.created_by_user
  AND ic.for_account = 'admin';
