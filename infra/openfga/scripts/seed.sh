#!/usr/bin/env bash
#
# OpenFGA tuple seed — idempotent. Writes the platform-wide tuples that
# every BSVibe deploy needs:
#
#   - admin user owns the BSVibe Admin tenant
#   - admin tenant subscribes to plan:team (default platform plan)
#   - plan:pro / plan:team / plan:enterprise have feature flags enabled
#
# OpenFGA's ``write`` endpoint is idempotent if the same tuple is
# already present (returns ``write_failed_due_to_invalid_input`` on
# duplicates). We swallow that specific class of error so a re-run
# after partial completion is safe.
#
# Inputs:
#   - infra/openfga/.bootstrap.json  (store_id + auth_model_id)
#   - infra/openfga/.env             (OPENFGA_AUTHN_PRESHARED_KEYS)
#   - SUPABASE_ADMIN_USER_ID env (default: admin@bsvibe.dev's user_id)
#   - SUPABASE_ADMIN_TENANT_ID env (default: BSVibe Admin tenant_id)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENFGA_DIR="${OPENFGA_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
STATE_FILE="$OPENFGA_DIR/.bootstrap.json"
ENV_FILE="$OPENFGA_DIR/.env"

err()  { echo "[openfga-seed] ERROR: $*" >&2; exit 1; }
info() { echo "[openfga-seed] $*"; }

[ -f "$STATE_FILE" ] || err "missing $STATE_FILE — run bootstrap.sh first"
[ -f "$ENV_FILE" ] || err "missing $ENV_FILE"
command -v jq >/dev/null || err "jq required (brew install jq)"

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

API="$(jq -r .api "$STATE_FILE")"
STORE_ID="$(jq -r .store_id "$STATE_FILE")"
MODEL_ID="$(jq -r .auth_model_id "$STATE_FILE")"
AUTH_KEY="${OPENFGA_AUTHN_PRESHARED_KEYS%%,*}"

# Hardcoded for the platform admin (see BSVibe_Production_Hardening_Handoff_2026-05-03.md §5.5).
ADMIN_USER_ID="${SUPABASE_ADMIN_USER_ID:-67a49e60-8882-4a38-a544-4efa7c7f9d5a}"
ADMIN_TENANT_ID="${SUPABASE_ADMIN_TENANT_ID:-98aafacf-ac62-479f-b8ab-21c0fe4e113e}"

info "API=$API store=$STORE_ID model=$MODEL_ID"
info "admin user=$ADMIN_USER_ID tenant=$ADMIN_TENANT_ID"

# Plain bash array of tuple-key triples (user, relation, object).
TUPLES=(
  # Admin user → BSVibe Admin tenant (owner — implies admin/member/viewer).
  "user:$ADMIN_USER_ID|owner|tenant:$ADMIN_TENANT_ID"
  # Tenant ⇄ plan:team (default plan for the bootstrap admin tenant).
  "plan:team|plan|tenant:$ADMIN_TENANT_ID"
  "tenant:$ADMIN_TENANT_ID|subscriber|plan:team"
  # Feature flags (Auth_Design §2.5 + bsvibe.fga comment).
  "plan:pro|enabled_for|feature:agent_execute"
  "plan:team|enabled_for|feature:agent_execute"
  "plan:enterprise|enabled_for|feature:agent_execute"
  "plan:team|enabled_for|feature:multi_tenant_admin"
  "plan:enterprise|enabled_for|feature:multi_tenant_admin"
  "plan:enterprise|enabled_for|feature:audit_log"
)

write_tuple() {
  local user="$1" relation="$2" object="$3"
  local body
  body=$(jq -nc \
    --arg user "$user" --arg relation "$relation" --arg object "$object" \
    --arg model_id "$MODEL_ID" \
    '{
      authorization_model_id: $model_id,
      writes: {
        tuple_keys: [{user: $user, relation: $relation, object: $object}]
      }
    }')

  local resp
  resp=$(curl -sS -X POST \
    -H "Authorization: Bearer $AUTH_KEY" \
    -H "Content-Type: application/json" \
    -d "$body" \
    "$API/stores/$STORE_ID/write")

  if echo "$resp" | jq -e '.code' >/dev/null 2>&1; then
    local code
    code=$(echo "$resp" | jq -r '.code')
    # ``write_failed_due_to_invalid_input`` is the only "already exists"
    # error code. Treat as idempotent success.
    if [ "$code" = "write_failed_due_to_invalid_input" ]; then
      info "  · already exists: $user $relation $object"
      return 0
    fi
    err "write failed for $user $relation $object: $resp"
  fi
  info "  ✓ wrote: $user $relation $object"
}

for triple in "${TUPLES[@]}"; do
  IFS='|' read -r u r o <<<"$triple"
  write_tuple "$u" "$r" "$o"
done

info "OK — seed complete"
