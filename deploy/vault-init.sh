#!/usr/bin/env bash
# Prepares a development Vault (dev mode, root token dev-root) for warden:
# KV v2 mount "warden", policy "warden" (contracts/vault-layout.md), AppRole
# "warden", and the role_id / secret_id files the service reads. Idempotent.
set -euo pipefail
ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"; TOKEN="${VAULT_TOKEN:-dev-root}"
OUT="$(dirname "$0")/.vault"; mkdir -p "$OUT"; chmod 700 "$OUT"
api() { curl -sS -H "X-Vault-Token: $TOKEN" -X "$1" "$ADDR/v1/$2" ${3:+-d "$3"}; }
for i in $(seq 1 30); do curl -sf "$ADDR/v1/sys/health" >/dev/null && break; sleep 1; done
api POST sys/mounts/warden '{"type":"kv","options":{"version":"2"}}' >/dev/null 2>&1 || true
api PUT sys/policies/acl/warden '{"policy":"path \"warden/data/*\" { capabilities = [\"create\",\"read\",\"update\",\"delete\"] }\npath \"warden/metadata/*\" { capabilities = [\"read\",\"delete\",\"list\"] }\npath \"auth/token/renew-self\" { capabilities = [\"update\"] }"}' >/dev/null
api POST sys/auth/approle '{"type":"approle"}' >/dev/null 2>&1 || true
api POST auth/approle/role/warden '{"token_policies":["warden"],"token_ttl":"1h","token_max_ttl":"24h","secret_id_num_uses":0}' >/dev/null
api GET auth/approle/role/warden/role-id | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["role_id"], end="")' > "$OUT/role_id"
api POST auth/approle/role/warden/secret-id | python3 -c 'import sys,json; print(json.load(sys.stdin)["data"]["secret_id"], end="")' > "$OUT/secret_id"
chmod 600 "$OUT/role_id" "$OUT/secret_id"
echo "vault-init: mount warden, policy warden, approle warden -> $OUT/{role_id,secret_id}"
