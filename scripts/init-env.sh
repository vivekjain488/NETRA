#!/usr/bin/env bash
#
# Creates .env from .env.example, generating a random value for every secret
# left blank in the template.
#
# The template ships those fields empty on purpose. A committed development
# password is a habit that ends up copied into a real deployment, and a shared
# default is the first thing an attacker tries.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="${ROOT}/.env.example"
TARGET="${ROOT}/.env"

# Fields generated when blank.
SECRETS=(POSTGRES_PASSWORD KEYCLOAK_ADMIN_PASSWORD NETRA_DEMO_PASSWORD)

if [[ -f "$TARGET" ]]; then
  echo ".env already exists; leaving it untouched"
  exit 0
fi
if [[ ! -f "$TEMPLATE" ]]; then
  echo "missing $TEMPLATE" >&2
  exit 1
fi

generate() {
  # URL-safe: the database password is interpolated into a connection URL.
  #
  # `head` reads a bounded amount first so that `tr` sees end-of-input rather
  # than being killed by SIGPIPE, which would abort the script under pipefail.
  head -c 256 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | cut -c1-32
}

cp "$TEMPLATE" "$TARGET"

for key in "${SECRETS[@]}"; do
  current="$(grep -E "^${key}=" "$TARGET" | head -1 | cut -d= -f2- || true)"
  if [[ -z "$current" ]]; then
    value="$(generate)"
    # Portable in-place edit across GNU and BSD sed.
    sed "s|^${key}=.*|${key}=${value}|" "$TARGET" > "${TARGET}.tmp"
    mv "${TARGET}.tmp" "$TARGET"
    echo "generated ${key}"
  fi
done

# Keep the native-run connection URL consistent with the generated password.
db_password="$(grep -E '^POSTGRES_PASSWORD=' "$TARGET" | cut -d= -f2-)"
db_user="$(grep -E '^POSTGRES_USER=' "$TARGET" | cut -d= -f2-)"
db_name="$(grep -E '^POSTGRES_DB=' "$TARGET" | cut -d= -f2-)"
db_port="$(grep -E '^NETRA_POSTGRES_PORT=' "$TARGET" | cut -d= -f2-)"

sed "s|^NETRA_DATABASE_URL=.*|NETRA_DATABASE_URL=postgres://${db_user}:${db_password}@localhost:${db_port}/${db_name}?sslmode=disable|" \
  "$TARGET" > "${TARGET}.tmp"
mv "${TARGET}.tmp" "$TARGET"

chmod 600 "$TARGET"
echo "wrote .env (mode 600)"
