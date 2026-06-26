UPDATE account_delegations
SET granted_scopes = 'atproto repo:* blob:*/* identity:* account:*?action=manage'
WHERE granted_scopes = 'atproto';

UPDATE account_delegations
SET granted_scopes = 'atproto repo:*?action=create repo:*?action=update repo:*?action=delete blob:*/*'
WHERE granted_scopes = 'repo:*?action=create repo:*?action=update repo:*?action=delete blob:*/*';
