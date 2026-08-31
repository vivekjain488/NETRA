#!/usr/bin/env bash
#
# Sets passwords for the imported NETRA demo users.
#
# The realm import deliberately contains no credentials: committing a password,
# even a development one, trains the wrong habit and ends up copied into a real
# deployment. Passwords are applied here from the environment instead.
#
#   NETRA_DEMO_PASSWORD=... ./deployment/keycloak/set-demo-passwords.sh

set -euo pipefail

CONTAINER="${KEYCLOAK_CONTAINER:-netra-keycloak}"
REALM="${KEYCLOAK_REALM:-netra}"
ADMIN_USER="${KEYCLOAK_ADMIN:-admin}"
USERS=(alice ravi priya arun)

if [[ -z "${NETRA_DEMO_PASSWORD:-}" ]]; then
  echo "NETRA_DEMO_PASSWORD is not set. Refusing to apply a default password." >&2
  exit 1
fi
if [[ -z "${KEYCLOAK_ADMIN_PASSWORD:-}" ]]; then
  echo "KEYCLOAK_ADMIN_PASSWORD is not set." >&2
  exit 1
fi

kc() { docker exec -i "$CONTAINER" /opt/keycloak/bin/kcadm.sh "$@"; }

kc config credentials \
  --server http://localhost:8080 \
  --realm master \
  --user "$ADMIN_USER" \
  --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null

for username in "${USERS[@]}"; do
  kc set-password -r "$REALM" --username "$username" --new-password "$NETRA_DEMO_PASSWORD"
  echo "password set for ${username}"
done
