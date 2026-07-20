#!/usr/bin/env bash
#
# Store Avanza credentials in the macOS Keychain.
#
# Run once. Nothing is written to disk, to your shell history, or to any process
# argument list:
#
#   * Secrets are read with `read -rs`, so they are never echoed to the terminal.
#   * They are handed to `security` over stdin via `security -i`, never as a
#     command-line argument. (Verified: values passed with `-w <value>` on argv
#     ARE visible to `ps` for the lifetime of the call.)
#   * They are stored base64-encoded, because `security find-generic-password -w`
#     hex-encodes any value that is not pure ASCII -- which a Swedish password
#     containing a/o/a-with-diacritics would trigger, and which is ambiguous to
#     decode. Base64 keeps the stored form ASCII and the readback deterministic.
#
set -euo pipefail

SERVICE="avanza-mcp"

die() { printf 'Error: %s\n' "$1" >&2; exit 1; }

command -v security >/dev/null 2>&1 || die "'security' not found. This script is macOS-only."

cat <<'BANNER'
Avanza MCP -- credential setup
==============================

Stores your Avanza username, password and TOTP secret in the macOS Keychain.
Input is hidden and never written to disk or shell history.

To find your TOTP secret: log in to Avanza -> Min ekonomi -> Installningar ->
Sakerhet -> Tvafaktorsinloggning -> "Annan app for tvafaktorsinloggning".
Reveal the secret there (a ~16-32 character string, not the 6-digit code).

NOTE: the TOTP secret is a permanent second factor. Anyone holding it plus your
password has full access to your Avanza account, including the ability to trade.
This server cannot trade -- but the credentials themselves are not so limited.

BANNER

read_secret() {
  # $1 = prompt. Echoes the value on stdout; caller captures it.
  local prompt="$1" value=""
  printf '%s: ' "$prompt" >&2
  IFS= read -rs value </dev/tty || die "could not read from terminal"
  printf '\n' >&2
  [[ -n "$value" ]] || die "empty value, aborting"
  printf '%s' "$value"
}

store() {
  # $1 = keychain account name, $2 = secret value
  local account="$1" value="$2" encoded
  encoded=$(printf '%s' "$value" | base64 | tr -d '\n')

  # -U updates an existing item instead of failing.
  # -T /usr/bin/security scopes access to the security binary the launcher uses,
  #    rather than -A which would grant every application access.
  # The command goes over stdin, so the secret never reaches argv.
  if ! printf 'add-generic-password -U -s "%s" -a "%s" -T /usr/bin/security -w "%s"\n' \
        "$SERVICE" "$account" "$encoded" | security -i >/dev/null 2>&1; then
    die "failed to write '$account' to the Keychain"
  fi

  # Read it back and confirm it survived the round trip.
  local readback
  readback=$(security find-generic-password -w -s "$SERVICE" -a "$account" 2>/dev/null | base64 -d 2>/dev/null || true)
  [[ "$readback" == "$value" ]] || die "verification failed for '$account' (stored value did not match)"
  printf '  stored and verified: %s\n' "$account" >&2
}

username=$(read_secret "Avanza username")
password=$(read_secret "Avanza password")
totp=$(read_secret "TOTP secret")

# Strip whitespace from the TOTP secret -- Avanza displays it in spaced groups.
totp="${totp//[[:space:]]/}"

printf '\nWriting to Keychain (service: %s)...\n' "$SERVICE" >&2
store username "$username"
store password "$password"
store totp_secret "$totp"

unset username password totp

cat >&2 <<BANNER

Done. Credentials are in your login Keychain under the service "$SERVICE".

Next:
  1. Build the image:   docker build -t avanza-mcp:latest .
  2. Register the server with your MCP client, pointing at:
         $(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/avanza-mcp-launcher.sh
     The client config holds no secrets.

To revoke: delete the three items from Keychain Access, or run
  security delete-generic-password -s $SERVICE -a username
  security delete-generic-password -s $SERVICE -a password
  security delete-generic-password -s $SERVICE -a totp_secret
BANNER
