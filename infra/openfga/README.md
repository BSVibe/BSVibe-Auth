# OpenFGA Deployment Infrastructure

Production OpenFGA + dedicated Postgres datastore, packaged as a single
docker-compose stack. Deploys to the BSVibe Mac Mini and is consumed by
`bsvibe-authz` (and indirectly by every product backend).

References:
- `BSVibe_Auth_Design.md` §3 (authorization model) and §10 (deployment topology)
- Decision #6 (`BSVibe_Execution_Lockin.md`): single-node OpenFGA, docker-compose

## Layout

```
infra/openfga/
├── docker-compose.yml      # 3 services: openfga + openfga-postgres + openfga-migrate
├── bsvibe.fga              # Authorization model (DSL). Drift-checked vs SoT.
├── .env.example            # Environment template; copy to .env (gitignored)
├── .bootstrap.json         # Generated after first bootstrap (gitignored, mode 600)
└── scripts/
    ├── up.sh               # Idempotent docker compose up -d wrapper
    ├── bootstrap.sh        # Apply bsvibe.fga to running OpenFGA (idempotent)
    └── status.sh           # Health + applied schema summary
```

## Schema Single Source of Truth

The OpenFGA authorization model lives canonically in
[`bsvibe-python/packages/bsvibe-authz/schema/bsvibe.fga`](https://github.com/BSVibe/bsvibe-python/blob/main/packages/bsvibe-authz/schema/bsvibe.fga)
(BSVibe Auth Design Phase 0 P0.4).

`infra/openfga/bsvibe.fga` here is a **byte-identical copy** so the Mac Mini
deployment can boot without a build-time fetch. Drift is enforced by
`.github/workflows/openfga-schema.yml` — the `drift-guard` job fails any PR
where the two files diverge.

When updating the schema:
1. Edit `bsvibe-python/packages/bsvibe-authz/schema/bsvibe.fga` first (SoT).
2. Copy the resulting file verbatim to `BSVibe-Auth/infra/openfga/bsvibe.fga`.
3. Open one PR per repo and coordinate the merge order (bsvibe-python first
   so the SoT release is what BSVibe-Auth picks up).
4. After merge, on the Mac Mini run
   `./infra/openfga/scripts/bootstrap.sh` to apply the new model.

## First-time setup (Mac Mini)

```bash
cd ~/Works/BSVibe-Auth/main/infra/openfga       # adjust path as needed

# 1) Secrets
cp .env.example .env
chmod 600 .env
# Edit .env and fill in:
#   OPENFGA_PG_PASSWORD            (openssl rand -hex 32)
#   OPENFGA_AUTHN_PRESHARED_KEYS   (CSV; openssl rand -hex 32 for each entry)

# 2) Start the stack
./scripts/up.sh

# 3) Apply the authorization model
./scripts/bootstrap.sh
# → writes infra/openfga/.bootstrap.json with store_id + auth_model_id

# 4) Verify
./scripts/status.sh
# endpoint    http://127.0.0.1:8765
# health      OK
# store_id    01H...
# model_id    01H...
# schema_sha  e5c8...
# applied_at  2026-04-28T...
# remote      OK
```

After step 3, hand the secrets to the products:

```bash
OPENFGA_API_URL=http://host.docker.internal:8765
OPENFGA_STORE_ID=<store_id from .bootstrap.json>
OPENFGA_AUTH_MODEL_ID=<auth_model_id from .bootstrap.json>
OPENFGA_AUTH_TOKEN=<one of OPENFGA_AUTHN_PRESHARED_KEYS>
```

These four variables go into each product's `.env.production` (BSNexus,
BSGateway, BSupervisor, BSage). They are read by the `bsvibe-authz` client.

## Day-to-day operations

```bash
cd infra/openfga

# Bring up / restart
./scripts/up.sh
docker compose --env-file .env restart

# Logs
docker compose --env-file .env logs -f openfga
docker compose --env-file .env logs -f openfga-postgres

# Tear down (data persists in named volume openfga-postgres-data)
docker compose --env-file .env down

# Tear down + nuke data (DANGEROUS — invalidates store_id / model_id)
docker compose --env-file .env down -v

# Re-apply schema after editing bsvibe.fga (idempotent; no-op if unchanged)
./scripts/bootstrap.sh

# Force re-apply (rotates auth_model_id)
./scripts/bootstrap.sh --force

# Health + applied schema
./scripts/status.sh
```

## Ports

All ports bind to `127.0.0.1` only. Reverse proxy (Caddy on the Mac Mini) is
responsible for any external exposure.

| Variable             | Default | Purpose                                   |
| -------------------- | ------- | ----------------------------------------- |
| `OPENFGA_HTTP_PORT`  | 8765    | HTTP API consumed by `bsvibe-authz`       |
| `OPENFGA_GRPC_PORT`  | 8766    | gRPC API (optional clients)               |
| `OPENFGA_PLAY_PORT`  | 3030    | Playground UI (dev / debugging)           |
| `OPENFGA_PG_PORT`    | 5440    | Postgres datastore (loopback only)        |

## Secret rotation

The preshared keys are CSV — supply two during rotation, retire the old one
afterwards. No service restart is required to add new keys (read at startup;
restart `openfga` to pick up changes):

```bash
# 1) Generate new key
NEW=$(openssl rand -hex 32)

# 2) Append to OPENFGA_AUTHN_PRESHARED_KEYS in .env (comma separated):
#    OPENFGA_AUTHN_PRESHARED_KEYS=<old>,<new>

# 3) Restart OpenFGA
docker compose --env-file .env up -d --force-recreate openfga

# 4) Roll OPENFGA_AUTH_TOKEN in every consumer (.env.production for products).

# 5) Once consumers are migrated, remove <old> from .env and restart again.
```

Quarterly rotation cadence is documented in `BSVibe_Auth_Design.md` §10.3.

## launchd auto-start (Mac Mini, optional)

The OpenFGA stack runs continuously on the Mac Mini. To start it automatically
at login, create a per-user launchd plist (this file is **not** kept in the
repo because the file paths and `Label` are user-specific):

```bash
mkdir -p ~/Library/LaunchAgents
cat > ~/Library/LaunchAgents/com.<your-user>.openfga.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.<your-user>.openfga</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/bash</string>
        <string>/Users/<your-user>/Works/BSVibe-Auth/main/infra/openfga/scripts/up.sh</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>/Users/<your-user>/Works/BSVibe-Auth/main/infra/openfga/logs/openfga.log</string>
    <key>StandardErrorPath</key>
    <string>/Users/<your-user>/Works/BSVibe-Auth/main/infra/openfga/logs/openfga.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
    </dict>
</dict>
</plist>
EOF

launchctl load ~/Library/LaunchAgents/com.<your-user>.openfga.plist
launchctl start com.<your-user>.openfga
```

Replace `<your-user>` with your local username. The plist intentionally lives
outside this repo because Label collisions and absolute paths are
user-specific.

## CI

`.github/workflows/openfga-schema.yml` runs three jobs on changes to this
directory:

1. **drift-guard** — fetches the SoT `bsvibe.fga` from
   `bsvibe-python` and compares SHA-256 with the local copy. Fails on drift.
2. **validate** — `openfga/cli model validate` and `model transform` against
   the local DSL.
3. **smoke-apply** (main only) — spins up disposable OpenFGA + Postgres, runs
   `bootstrap.sh` twice (second run must short-circuit with
   `schema unchanged`), then `status.sh`.

Production application against the Mac Mini happens only via manual
`./scripts/bootstrap.sh` (Auth_Design.md §10.2 — schema is code-PR-only, no
remote write from CI).
