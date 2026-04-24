#!/usr/bin/env bash
set -euo pipefail

MODULE="github.com/kalmbach/keys"
APT_PACKAGE="libgpgme-dev"

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

prompt_to_install() {
  local yn prompt="Install now? (y/n): "

  if [ -t 0 ]; then
    read -p "$prompt" -n 1 -r yn
  elif [ -r /dev/tty ]; then
    read -p "$prompt" -n 1 -r yn </dev/tty
  else
    return 1
  fi
  echo

  [[ $yn == [yY] ]]
}

if [ "$(uname -s)" != "Linux" ] || ! command -v apt-get >/dev/null 2>&1; then
  err "Only Ubuntu/Debian (apt-get) is supported right now."
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  err "Go toolchain not found. Install Go from https://go.dev/dl/ and re-run this script."
  exit 1
fi

has_gpgme=0
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists gpgme; then
  has_gpgme=1
elif [ -f /usr/include/gpgme.h ]; then
  has_gpgme=1
fi

if [ "$has_gpgme" -eq 0 ]; then
  warn "$APT_PACKAGE is required and not installed."
  info "Install with: sudo apt-get update && sudo apt-get install -y $APT_PACKAGE"

  if prompt_to_install; then
    sudo apt-get update
    sudo apt-get install -y "$APT_PACKAGE"
  else
    err "Run the command above manually and re-run this installer."
    exit 1
  fi
fi

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
