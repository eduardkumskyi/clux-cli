#!/bin/sh
# Install the clux BYOC host agent without a Go toolchain.
#
#   curl -fsSL https://clux.space/install.sh | sh
#
# This is the canonical, tested source. The copy served at https://clux.space/install.sh
# lives in the clux repo at landing/install.sh and MUST be kept byte-identical to this file.
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

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "clux-install: downloading $ASSET ($VERSION)..."
if ! $DL "$URL" > "$tmp/$ASSET"; then
  err "download failed: $URL"
fi
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
