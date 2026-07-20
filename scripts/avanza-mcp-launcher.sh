#!/usr/bin/env bash
#
# Launch the Avanza MCP server. This is the command your MCP client runs.
#
# Reads credentials from the macOS Keychain at spawn time and passes them to the
# container via `--env-file <(...)`, i.e. a process-substitution file descriptor.
# Nothing is written to disk, and nothing appears in any process argument list.
#
# Requires bash or zsh (process substitution); it will not work under plain sh.
#
set -euo pipefail

SERVICE="avanza-mcp"
IMAGE="${AVANZA_MCP_IMAGE:-avanza-mcp:latest}"

die() { printf 'avanza-mcp: %s\n' "$1" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || die "docker not found in PATH"
docker image inspect "$IMAGE" >/dev/null 2>&1 \
  || die "image '$IMAGE' not found. Build it with: docker build -t $IMAGE ."

fetch() {
  # $1 = keychain account name. Decodes the base64 stored by setup-credentials.sh.
  local account="$1" raw
  if ! raw=$(security find-generic-password -w -s "$SERVICE" -a "$account" 2>/dev/null); then
    die "credential '$account' not found in Keychain. Run scripts/setup-credentials.sh first."
  fi
  printf '%s' "$raw" | base64 -d 2>/dev/null \
    || die "could not decode credential '$account'. Re-run scripts/setup-credentials.sh."
}

username=$(fetch username)
password=$(fetch password)
totp=$(fetch totp_secret)

# --env-file reads from /dev/fd/N: the values exist only in a pipe, never on disk
# and never in argv. printf is a shell builtin, so it forks no visible process.
#
# Container hardening:
#   --rm                        ephemeral; dies with the client session
#   --read-only                 immutable root filesystem
#   --tmpfs /tmp                the only writable location
#   --cap-drop ALL              no Linux capabilities
#   --security-opt no-new-...   cannot gain privileges via setuid
#   -i                          stdin/stdout carry the MCP protocol
#
# Residual exposure: while the container runs, `docker inspect` (and root) can
# read these environment variables. See the security notes in README.md.
exec docker run \
  --rm -i \
  --env-file <(printf 'AVANZA_USERNAME=%s\nAVANZA_PASSWORD=%s\nAVANZA_TOTP_SECRET=%s\n' \
                 "$username" "$password" "$totp") \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --name "avanza-mcp-$$" \
  "$IMAGE"
