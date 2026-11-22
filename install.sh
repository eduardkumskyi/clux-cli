#!/bin/sh
# Install the clux BYOC host agent without a Go toolchain.
#
#   curl -fsSL https://clux.space/install.sh | sh
#
# Two byte-identical copies of this script exist and MUST stay in sync:
#   - clux-cli repo: install.sh         (canonical; tested here)
#   - clux repo:     landing/install.sh (served at https://clux.space/install.sh
#                                        via Cloudflare Workers Static Assets)
# Edit one, copy it verbatim to the other; `diff` of the two must be empty.
#
# Env overrides:
#   CLUX_VERSION   release tag to install (default: latest)
#   CLUX_INSTALL_DIR  install directory (default: /usr/local/bin, falls back to ~/.local/bin)
set -eu

REPO="eduardkumskyi/clux-cli"
VERSION="${CLUX_VERSION:-latest}"

err() { echo "clux-install: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || err "required command not found: $1"; }

need uname
need tar
if command -v curl >/dev/null 2>&1; then
  DL="curl -fsSL"
elif command -v wget >/dev/null 2>&1; then
  DL="wget -qO-"
else
  err "need curl or wget"
fi

os=$(uname -s)
case "$os" in
  Linux)  OS=linux ;;
  Darwin) OS=darwin ;;
  *) err "unsupported OS: $os (Windows: download the zip from https://github.com/$REPO/releases)" ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64)  ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) err "unsupported architecture: $arch" ;;
esac

if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/$REPO/releases/latest/download"
else
  BASE="https://github.com/$REPO/releases/download/$VERSION"
fi

ASSET="clux_${OS}_${ARCH}.tar.gz"
URL="$BASE/$ASSET"
# Published by the release workflow (goreleaser) next to the archives:
# "<sha256>  <file>" per line.
SUMS_URL="$BASE/checksums.txt"

# SHA-256 of a file, with whichever tool this OS ships.
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  err "need sha256sum or shasum to verify the download"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "clux-install: downloading $ASSET ($VERSION)..."
if ! $DL "$URL" > "$tmp/$ASSET"; then
  err "download failed: $URL"
fi
if ! $DL "$SUMS_URL" > "$tmp/checksums.txt"; then
  err "download failed: $SUMS_URL (refusing to install an unverified binary)"
fi

# Verify before anything touches the archive. Fail closed: no matching line,
# or a different hash, stops the install.
expected=$(awk -v f="$ASSET" '$2 == f || $2 == "*" f { print $1; exit }' "$tmp/checksums.txt")
[ -n "$expected" ] || err "no checksum for $ASSET in $SUMS_URL (refusing to install an unverified binary)"
case "$expected" in
  *[!0-9a-f]*) err "malformed checksum for $ASSET in $SUMS_URL" ;;
esac
[ "${#expected}" -eq 64 ] || err "malformed checksum for $ASSET in $SUMS_URL"
actual=$(sha256 "$tmp/$ASSET")
if [ "$actual" != "$expected" ]; then
  err "checksum mismatch for $ASSET (expected $expected, got $actual); not installing"
fi
echo "clux-install: checksum verified"

# A 404 from GitHub is served as a tiny HTML body, not a gzip stream.
if ! tar -tzf "$tmp/$ASSET" >/dev/null 2>&1; then
  err "no release asset for $OS/$ARCH at $URL (has a release been published?)"
fi

tar -xzf "$tmp/$ASSET" -C "$tmp"
[ -f "$tmp/clux" ] || err "archive did not contain a clux binary"
chmod +x "$tmp/clux"

if [ -n "${CLUX_INSTALL_DIR:-}" ]; then
  # Explicit choice always wins: create it and install there, no fallback.
  DIR="$CLUX_INSTALL_DIR"
  mkdir -p "$DIR"
  mv "$tmp/clux" "$DIR/clux"
elif [ -w /usr/local/bin ] 2>/dev/null; then
  DIR=/usr/local/bin
  mv "$tmp/clux" "$DIR/clux"
elif command -v sudo >/dev/null 2>&1; then
  DIR=/usr/local/bin
  echo "clux-install: installing to $DIR (needs sudo)"
  sudo mv "$tmp/clux" "$DIR/clux"
else
  DIR="$HOME/.local/bin"
  mkdir -p "$DIR"
  mv "$tmp/clux" "$DIR/clux"
fi

case ":$PATH:" in
  *":$DIR:"*) ;;
  *) echo "clux-install: add $DIR to your PATH (e.g. export PATH=\"$DIR:\$PATH\")" ;;
esac

echo "clux-install: installed to $DIR/clux"
"$DIR/clux" version || true

# The native macOS runtime (if set up) follows the CLI. `clux update` brings
# it along; one installed before self-updating daemons is replaced once
# (macOS asks for the password). Needs a terminal for that password.
if [ "$(uname -s)" = Darwin ] && [ -f /Library/LaunchDaemons/space.clux.native.pf.plist ] && [ -r /dev/tty ]; then
  "$DIR/clux" update </dev/tty || true
fi
