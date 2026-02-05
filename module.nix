{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.services.tranquil-pds;

  optionalStr = lib.types.nullOr lib.types.str;
  optionalInt = lib.types.nullOr lib.types.int;
  optionalBool = lib.types.nullOr lib.types.bool;
  optionalPath = lib.types.nullOr lib.types.str;
  optionalPort = lib.types.nullOr lib.types.port;

  filterNulls = lib.filterAttrs (_: v: v != null);

  boolToStr = b:
    if b == true
    then "true"
    else if b == false
    then "false"
    else null;

  settingsToEnv = settings: let
    raw = {
      SERVER_HOST = settings.server.host;
      SERVER_PORT = settings.server.port;
      PDS_HOSTNAME = settings.server.pdsHostname;

      DATABASE_URL = settings.database.url;
      DATABASE_MAX_CONNECTIONS = settings.database.maxConnections;
      DATABASE_MIN_CONNECTIONS = settings.database.minConnections;
      DATABASE_ACQUIRE_TIMEOUT_SECS = settings.database.acquireTimeoutSecs;

      BLOB_STORAGE_BACKEND = settings.storage.blobBackend;
      BLOB_STORAGE_PATH = settings.storage.blobPath;
      S3_ENDPOINT = settings.storage.s3Endpoint;
      AWS_REGION = settings.storage.awsRegion;
      S3_BUCKET = settings.storage.s3Bucket;

      BACKUP_ENABLED = boolToStr settings.backup.enabled;
      BACKUP_STORAGE_BACKEND = settings.backup.backend;
      BACKUP_STORAGE_PATH = settings.backup.path;
      BACKUP_S3_BUCKET = settings.backup.s3Bucket;
      BACKUP_RETENTION_COUNT = settings.backup.retentionCount;
      BACKUP_INTERVAL_SECS = settings.backup.intervalSecs;

      VALKEY_URL = settings.cache.valkeyUrl;

      TRANQUIL_PDS_ALLOW_INSECURE_SECRETS = boolToStr settings.security.allowInsecureSecrets;

      PLC_DIRECTORY_URL = settings.plc.directoryUrl;
      PLC_TIMEOUT_SECS = settings.plc.timeoutSecs;
      PLC_CONNECT_TIMEOUT_SECS = settings.plc.connectTimeoutSecs;
      PLC_ROTATION_KEY = settings.plc.rotationKey;

      DID_CACHE_TTL_SECS = settings.did.cacheTtlSecs;

      CRAWLERS = settings.relay.crawlers;

      FIREHOSE_BUFFER_SIZE = settings.firehose.bufferSize;
      FIREHOSE_MAX_LAG = settings.firehose.maxLag;

      NOTIFICATION_BATCH_SIZE = settings.notifications.batchSize;
      NOTIFICATION_POLL_INTERVAL_MS = settings.notifications.pollIntervalMs;
      MAIL_FROM_ADDRESS = settings.notifications.mailFromAddress;
      MAIL_FROM_NAME = settings.notifications.mailFromName;
      SENDMAIL_PATH = settings.notifications.sendmailPath;
      SIGNAL_CLI_PATH = settings.notifications.signalCliPath;
      SIGNAL_SENDER_NUMBER = settings.notifications.signalSenderNumber;

      MAX_BLOB_SIZE = settings.limits.maxBlobSize;

      ACCEPTING_REPO_IMPORTS = boolToStr settings.import.accepting;
      MAX_IMPORT_SIZE = settings.import.maxSize;
      MAX_IMPORT_BLOCKS = settings.import.maxBlocks;
      SKIP_IMPORT_VERIFICATION = boolToStr settings.import.skipVerification;

      INVITE_CODE_REQUIRED = boolToStr settings.registration.inviteCodeRequired;
      AVAILABLE_USER_DOMAINS = settings.registration.availableUserDomains;
      ENABLE_SELF_HOSTED_DID_WEB = boolToStr settings.registration.enableSelfHostedDidWeb;

      PRIVACY_POLICY_URL = settings.metadata.privacyPolicyUrl;
      TERMS_OF_SERVICE_URL = settings.metadata.termsOfServiceUrl;
      CONTACT_EMAIL = settings.metadata.contactEmail;

      DISABLE_RATE_LIMITING = boolToStr settings.rateLimiting.disable;

      SCHEDULED_DELETE_CHECK_INTERVAL_SECS = settings.scheduling.deleteCheckIntervalSecs;

      REPORT_SERVICE_URL = settings.moderation.reportServiceUrl;
      REPORT_SERVICE_DID = settings.moderation.reportServiceDid;

      PDS_AGE_ASSURANCE_OVERRIDE = boolToStr settings.misc.ageAssuranceOverride;
      ALLOW_HTTP_PROXY = boolToStr settings.misc.allowHttpProxy;

      SSO_GITHUB_ENABLED = boolToStr settings.sso.github.enabled;
      SSO_GITHUB_CLIENT_ID = settings.sso.github.clientId;

      SSO_DISCORD_ENABLED = boolToStr settings.sso.discord.enabled;
      SSO_DISCORD_CLIENT_ID = settings.sso.discord.clientId;

      SSO_GOOGLE_ENABLED = boolToStr settings.sso.google.enabled;
      SSO_GOOGLE_CLIENT_ID = settings.sso.google.clientId;

      SSO_GITLAB_ENABLED = boolToStr settings.sso.gitlab.enabled;
      SSO_GITLAB_CLIENT_ID = settings.sso.gitlab.clientId;
      SSO_GITLAB_ISSUER = settings.sso.gitlab.issuer;

      SSO_OIDC_ENABLED = boolToStr settings.sso.oidc.enabled;
      SSO_OIDC_CLIENT_ID = settings.sso.oidc.clientId;
      SSO_OIDC_ISSUER = settings.sso.oidc.issuer;
      SSO_OIDC_NAME = settings.sso.oidc.name;

      SSO_APPLE_ENABLED = boolToStr settings.sso.apple.enabled;
      SSO_APPLE_CLIENT_ID = settings.sso.apple.clientId;
      SSO_APPLE_TEAM_ID = settings.sso.apple.teamId;
      SSO_APPLE_KEY_ID = settings.sso.apple.keyId;
    };
  in
    lib.mapAttrs (_: v: toString v) (filterNulls raw);
in {
  options.services.tranquil-pds = {
    enable = lib.mkEnableOption "tranquil-pds AT Protocol personal data server";

    package = lib.mkPackageOption pkgs "tranquil-pds" {};

    user = lib.mkOption {
      type = lib.types.str;
      default = "tranquil-pds";
      description = "User under which tranquil-pds runs";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "tranquil-pds";
      description = "Group under which tranquil-pds runs";
    };

    dataDir = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/tranquil-pds";
      description = "Directory for tranquil-pds data (blobs, backups)";
    };

    secretsFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Path to a file containing secrets in EnvironmentFile format.
        Should contain: JWT_SECRET, DPOP_SECRET, MASTER_KEY
        May also contain: DISCORD_BOT_TOKEN, TELEGRAM_BOT_TOKEN,
        TELEGRAM_WEBHOOK_SECRET, SSO_*_CLIENT_SECRET, SSO_APPLE_PRIVATE_KEY,
        AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
      '';
    };

    settings = {
      server = {
        host = lib.mkOption {
          type = lib.types.str;
          default = "127.0.0.1";
          description = "Address to bind the server to";
        };

        port = lib.mkOption {
          type = lib.types.port;
          default = 3000;
          description = "Port to bind the server to";
        };

        pdsHostname = lib.mkOption {
          type = lib.types.str;
          description = "Public-facing hostname of the PDS (used in DID documents, JWTs, etc)";
        };
      };

      database = {
        url = lib.mkOption {
          type = lib.types.str;
          description = "PostgreSQL connection string";
        };

        maxConnections = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Maximum database connections";
        };

        minConnections = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Minimum database connections";
        };

        acquireTimeoutSecs = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Connection acquire timeout in seconds";
        };
      };

      storage = {
        blobBackend = lib.mkOption {
          type = lib.types.enum ["filesystem" "s3"];
          default = "filesystem";
          description = "Backend for blob storage";
        };

        blobPath = lib.mkOption {
          type = optionalPath;
          default = null;
          description = "Path for filesystem blob storage";
        };

        s3Endpoint = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "S3 endpoint URL (for object storage)";
        };

        awsRegion = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Region for objsto";
        };

        s3Bucket = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Bucket name for objsto";
        };
      };

      backup = {
        enabled = lib.mkOption {
          type = optionalBool;
          default = null;
          description = "Enable automatic repo backups";
        };

        backend = lib.mkOption {
          type = lib.types.enum ["filesystem" "s3"];
          default = "filesystem";
          description = "Backend for backup storage";
        };

        path = lib.mkOption {
          type = optionalPath;
          default = null;
          description = "Path for filesystem backup storage";
        };

        s3Bucket = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Object storage bucket name for backups";
        };

        retentionCount = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Number of backups to retain";
        };

        intervalSecs = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Backup interval in seconds";
        };
      };

      cache = {
        valkeyUrl = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Valkey URL for caching";
        };
      };

      security = {
        allowInsecureSecrets = lib.mkOption {
          type = optionalBool;
          default = null;
          description = "Allow default/weak secrets (development only, NEVER in production ofc)";
        };
      };

      plc = {
        directoryUrl = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "PLC directory URL";
        };

        timeoutSecs = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "PLC request timeout in seconds";
        };

        connectTimeoutSecs = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "PLC connection timeout in seconds";
        };

        rotationKey = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Rotation key for PLC operations (did:key:xyz)";
        };
      };

      did = {
        cacheTtlSecs = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "DID document cache TTL in seconds";
        };
      };

      relay = {
        crawlers = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Comma-separated list of relay URLs to notify via requestCrawl";
        };
      };

      firehose = {
        bufferSize = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Firehose broadcast channel buffer size";
        };

        maxLag = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Disconnect slow consumers after this many events of lag";
        };
      };

      notifications = {
        batchSize = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Notification queue batch size";
        };

        pollIntervalMs = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Notification queue poll interval in ms";
        };

        mailFromAddress = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Email from address for notifications";
        };

        mailFromName = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Email from name for notifications";
        };

        sendmailPath = lib.mkOption {
          type = optionalPath;
          default = null;
          description = "Path to sendmail binary";
        };

        signalCliPath = lib.mkOption {
          type = optionalPath;
          default = null;
          description = "Path to signal-cli binary";
        };

        signalSenderNumber = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Signal sender phone number";
        };
      };

      limits = {
        maxBlobSize = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Maximum blob size in bytes";
        };
      };

      import = {
        accepting = lib.mkOption {
          type = optionalBool;
          default = null;
          description = "Accept repository imports";
        };

        maxSize = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Maximum import size in bytes";
        };

        maxBlocks = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Maximum blocks per import";
        };

        skipVerification = lib.mkOption {
          type = optionalBool;
          default = null;
          description = "Skip verification during import (testing only)";
        };
      };

      registration = {
        inviteCodeRequired = lib.mkOption {
          type = optionalBool;
          default = null;
          description = "Require invite codes for registration";
        };

        availableUserDomains = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Comma-separated list of available user domains";
        };

        enableSelfHostedDidWeb = lib.mkOption {
          type = optionalBool;
          default = null;
          description = "Enable self-hosted did:web identities";
        };
      };

      metadata = {
        privacyPolicyUrl = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Privacy policy URL";
        };

        termsOfServiceUrl = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Terms of service URL";
        };

        contactEmail = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Contact email address";
        };
      };

      rateLimiting = {
        disable = lib.mkOption {
          type = optionalBool;
          default = null;
          description = "Disable rate limiting (testing only, NEVER in production you naughty!)";
        };
      };

      scheduling = {
        deleteCheckIntervalSecs = lib.mkOption {
          type = optionalInt;
          default = null;
          description = "Scheduled deletion check interval in seconds";
        };
      };

      moderation = {
        reportServiceUrl = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Moderation report service URL (like ozone)";
        };

        reportServiceDid = lib.mkOption {
          type = optionalStr;
          default = null;
          description = "Moderation report service DID";
        };
      };

      misc = {
        ageAssuranceOverride = lib.mkOption {
          type = optionalBool;
          default = null;
          description = "Override age assurance checks";
        };

        allowHttpProxy = lib.mkOption {
          type = optionalBool;
          default = null;
          description = "Allow HTTP for proxy requests (development only)";
        };
      };

      sso = {
        github = {
          enabled = lib.mkOption {
            type = optionalBool;
            default = null;
            description = "Enable GitHub SSO";
          };

          clientId = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "GitHub OAuth client ID";
          };
        };

        discord = {
          enabled = lib.mkOption {
            type = optionalBool;
            default = null;
            description = "Enable Discord SSO";
          };

          clientId = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "Discord OAuth client ID";
          };
        };

        google = {
          enabled = lib.mkOption {
            type = optionalBool;
            default = null;
            description = "Enable Google SSO";
          };

          clientId = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "Google OAuth client ID";
          };
        };

        gitlab = {
          enabled = lib.mkOption {
            type = optionalBool;
            default = null;
            description = "Enable GitLab SSO";
          };

          clientId = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "GitLab OAuth client ID";
          };

          issuer = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "GitLab issuer URL";
          };
        };

        oidc = {
          enabled = lib.mkOption {
            type = optionalBool;
            default = null;
            description = "Enable generic OIDC SSO";
          };

          clientId = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "OIDC client ID";
          };

          issuer = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "OIDC issuer URL";
          };

          name = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "OIDC provider display name";
          };
        };

        apple = {
          enabled = lib.mkOption {
            type = optionalBool;
            default = null;
            description = "Enable Apple Sign-in";
          };

          clientId = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "Apple Services ID";
          };

          teamId = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "Apple Team ID";
          };

          keyId = lib.mkOption {
            type = optionalStr;
            default = null;
            description = "Apple Key ID";
          };
        };
      };
    };
  };

  config = let
    effectiveBlobPath =
      if cfg.settings.storage.blobPath != null
      then cfg.settings.storage.blobPath
      else "${cfg.dataDir}/blobs";
    effectiveBackupPath =
      if cfg.settings.backup.path != null
      then cfg.settings.backup.path
      else "${cfg.dataDir}/backups";
    envVars =
      (settingsToEnv cfg.settings)
      // {
        BLOB_STORAGE_PATH = effectiveBlobPath;
        BACKUP_STORAGE_PATH = effectiveBackupPath;
      };
  in
    lib.mkIf cfg.enable {
      assertions = [
        {
          assertion = config.systemd.enable or true;
          message = "services.tranquil-pds requires systemd";
        }
      ];

      users.users.${cfg.user} = {
        isSystemUser = true;
        inherit (cfg) group;
        home = cfg.dataDir;
      };

      users.groups.${cfg.group} = {};

      systemd.tmpfiles.rules = [
        "d ${cfg.dataDir} 0750 ${cfg.user} ${cfg.group} -"
        "d ${effectiveBlobPath} 0750 ${cfg.user} ${cfg.group} -"
        "d ${effectiveBackupPath} 0750 ${cfg.user} ${cfg.group} -"
      ];

      systemd.services.tranquil-pds = {
        description = "Tranquil PDS - AT Protocol Personal Data Server";
        after = ["network.target" "postgresql.service"];
        wants = ["network.target"];
        wantedBy = ["multi-user.target"];

        environment = envVars;

        serviceConfig = {
          Type = "exec";
          User = cfg.user;
          Group = cfg.group;
          ExecStart = "${cfg.package}/bin/tranquil-pds";
          Restart = "on-failure";
          RestartSec = 5;

          WorkingDirectory = cfg.dataDir;
          StateDirectory = "tranquil-pds";

          EnvironmentFile = lib.mkIf (cfg.secretsFile != null) cfg.secretsFile;

          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectControlGroups = true;
          RestrictAddressFamilies = ["AF_INET" "AF_INET6" "AF_UNIX"];
          RestrictNamespaces = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          RemoveIPC = true;

          ReadWritePaths = [
            effectiveBlobPath
            effectiveBackupPath
          ];
        };
      };
    };
}
