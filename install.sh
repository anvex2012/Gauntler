#!/bin/sh
# Created by anvex2012
# Installs the latest version of Gauntler (desktop app + "gauntler" command) with a single command:
#
#   curl -fsSL https://raw.githubusercontent.com/anvex2012/Gauntler/main/install.sh | sh
#
# Files downloaded with curl are not quarantined by macOS: the app opens right away, without the
# "Apple cannot verify…" block shown for apps downloaded from the browser.
# Optional variables: GAUNTLER_DEST (installation folder), GAUNTLER_NO_OPEN=1 (do not open the app).
set -eu

REPO="anvex2012/Gauntler"
API="https://api.github.com/repos/$REPO/releases/latest"

say()  { printf '\033[1;34m▸\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✔\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m✖\033[0m %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "curl is required."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS" in
  Darwin)
    [ "$ARCH" = "arm64" ] || fail "The app is for Macs with Apple silicon (M1 and later). On an Intel Mac use the terminal version: https://github.com/$REPO/blob/main/INSTRUCTIONS.md"
    PATTERN='macOS-arm64\.zip' ;;
  Linux)
    [ "$ARCH" = "x86_64" ] || fail "The Linux package is for x86_64. Use the terminal version: https://github.com/$REPO/blob/main/INSTRUCTIONS.md"
    PATTERN='Linux-x64\.tar\.gz' ;;
  *) fail "System not supported by this script ($OS). On Windows download the zip from https://github.com/$REPO/releases/latest" ;;
esac

say "Looking for the latest version of Gauntler…"
JSON=$(curl -fsSL -H 'Accept: application/vnd.github+json' "$API") || fail "Unable to reach GitHub."
URL=$(printf '%s' "$JSON" | grep -o '"browser_download_url": *"[^"]*"' | sed 's/.*"\(https[^"]*\)"/\1/' | grep -E "$PATTERN" | head -n 1)
SUMS=$(printf '%s' "$JSON" | grep -o '"browser_download_url": *"[^"]*SHA256SUMS.txt"' | sed 's/.*"\(https[^"]*\)"/\1/' | head -n 1)
[ -n "$URL" ] || fail "Package not found in the latest release."
FILE=$(basename "$URL")

say "Downloading ${FILE}…"
curl -fL --progress-bar -o "$TMP/$FILE" "$URL" || fail "Download failed."
if [ -n "$SUMS" ] && curl -fsSL -o "$TMP/SHA256SUMS.txt" "$SUMS"; then
  EXPECTED=$(grep " $FILE\$" "$TMP/SHA256SUMS.txt" | cut -d' ' -f1)
  if command -v shasum >/dev/null 2>&1; then ACTUAL=$(shasum -a 256 "$TMP/$FILE" | cut -d' ' -f1); else ACTUAL=$(sha256sum "$TMP/$FILE" | cut -d' ' -f1); fi
  [ -z "$EXPECTED" ] || [ "$EXPECTED" = "$ACTUAL" ] || fail "SHA-256 fingerprint does not match: damaged file."
  ok "File verified (SHA-256)"
fi

if [ "$OS" = "Darwin" ]; then
  DEST=${GAUNTLER_DEST:-/Applications}
  if [ ! -w "$DEST" ]; then DEST="$HOME/Applications"; mkdir -p "$DEST"; fi
  say "Installing Gauntler in ${DEST}…"
  ditto -x -k "$TMP/$FILE" "$TMP/app"
  [ -d "$TMP/app/Gauntler.app" ] || fail "Invalid archive."
  pkill -x Gauntler 2>/dev/null || true
  rm -rf "$DEST/Gauntler.app"
  ditto "$TMP/app/Gauntler.app" "$DEST/Gauntler.app"
  xattr -dr com.apple.quarantine "$DEST/Gauntler.app" 2>/dev/null || true
  ok "Gauntler installed: $DEST/Gauntler.app"
  if [ -z "${GAUNTLER_NO_OPEN:-}" ]; then
    open "$DEST/Gauntler.app"
    ok "App opened: on first launch it installs the \"gauntler\" command, ClamAV and bsdtar by itself."
  fi
else
  DEST=${GAUNTLER_DEST:-$HOME/.local/share/gauntler}
  say "Installing Gauntler in ${DEST}…"
  mkdir -p "$TMP/x"
  tar -xzf "$TMP/$FILE" -C "$TMP/x"
  SRC=$(find "$TMP/x" -mindepth 1 -maxdepth 1 -type d | head -n 1)
  rm -rf "$DEST"
  mkdir -p "$(dirname "$DEST")"
  mv "$SRC" "$DEST"
  if [ -x "$DEST/install.sh" ]; then "$DEST/install.sh"; else "$DEST/installa.sh"; fi
  ok "Gauntler installed: $DEST"
  [ -n "${GAUNTLER_NO_OPEN:-}" ] || { "$DEST/gauntler" >/dev/null 2>&1 & }
fi

echo
ok "Done. Open a new terminal window and type: gauntler"
