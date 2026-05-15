#!/usr/bin/env bash
set -euo pipefail

MODULE="github.com/kalmbach/keys"

if [ -t 1 ] && command -v tput >/dev/null 2>&1; then
  tred=$(tput setaf 1 2>/dev/null)
  tgrn=$(tput setaf 2 2>/dev/null)
  tylw=$(tput setaf 3 2>/dev/null)
  trst=$(tput sgr0 2>/dev/null)
else
  tred=""; tylw=""; tgrn=""; trst=""
fi

info() { printf '%s==>%s %s\n' "$tgrn" "$trst" "$*"; }
warn() { printf '%s!!%s %s\n' "$tylw" "$trst" "$*" >&2; }
err()  { printf '%sxx%s %s\n' "$tred" "$trst" "$*" >&2; }

if ! command -v go >/dev/null 2>&1; then
  err "Go toolchain not found. Install Go from https://go.dev/dl/ and re-run this script."
  exit 1
fi

for cmd in gpg ssh-keygen; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    warn "$cmd is not on PATH; features that rely on it will fail until it is installed."
  fi
done

info "Running: go install ${MODULE}@latest"
go install "${MODULE}@latest"

bindir="$(go env GOBIN)"
if [ -z "$bindir" ]; then
  bindir="$(go env GOPATH)/bin"
fi

if [ ! -x "$bindir/keys" ]; then
  err "Expected binary not found at $bindir/keys"
  exit 1
fi

info "Installed: $bindir/keys"

case ":$PATH:" in
  *":$bindir:"*) ;;
  *)
    warn "$bindir is not in your PATH."
    printf '    Add this to your shell rc:  export PATH="%s:$PATH"\n' "$bindir" >&2
    ;;
esac
