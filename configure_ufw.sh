#!/usr/bin/env bash
set -euo pipefail

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  echo "This script must be run as root (use sudo)." >&2
  exit 1
fi

echo "=== Update package lists and install ufw (if missing) ==="
apt update -y
if ! command -v ufw >/dev/null 2>&1; then
  apt install -y ufw
else
  echo "ufw already installed"
fi

echo
echo "=== Ensure SSH allowed and rate-limited ==="
ufw allow ssh || true
ufw limit ssh || true

echo
echo "=== Set default policies: deny incoming, allow outgoing ==="
ufw default deny incoming
ufw default allow outgoing

echo
echo "=== Allow HTTP (80) and HTTPS (443) ==="
ufw allow 80/tcp
ufw allow 443/tcp

echo
echo "=== Example deny rules ==="
ufw deny 23 || true
ufw deny from 203.0.113.0/24 || true

echo
echo "=== Enable logging ==="
ufw logging on || true

echo
echo "=== Enable UFW (force) ==="
ufw --force enable

echo
echo "=== Final UFW status ==="
ufw status verbose

echo
echo "Demo complete. Use 'ufw status verbose' and 'ufw show raw' to inspect rules."
