#!/bin/sh
# Creato da anvex2012
# Installa l'ultima versione di Gauntler (app desktop + comando "gauntler") con un solo comando:
#
#   curl -fsSL https://raw.githubusercontent.com/anvex2012/Gauntler/main/install.sh | sh
#
# I file scaricati con curl non vengono messi in quarantena da macOS: l'app si apre subito,
# senza il blocco "Apple non può verificare…" che compare per le app scaricate dal browser.
# Variabili facoltative: GAUNTLER_DEST (cartella di installazione), GAUNTLER_NO_OPEN=1 (non aprire l'app).
set -eu

REPO="anvex2012/Gauntler"
API="https://api.github.com/repos/$REPO/releases/latest"

say()  { printf '\033[1;34m▸\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m✔\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31m✖\033[0m %s\n' "$*" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || fail "Serve curl."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT INT TERM

OS=$(uname -s)
ARCH=$(uname -m)
case "$OS" in
  Darwin)
    [ "$ARCH" = "arm64" ] || fail "L'app è per i Mac con processore Apple (M1 e successivi). Su un Mac Intel usa la versione da terminale: https://github.com/$REPO/blob/main/ISTRUZIONI.md"
    PATTERN='macOS-arm64\.zip' ;;
  Linux)
    [ "$ARCH" = "x86_64" ] || fail "Il pacchetto Linux è per x86_64. Usa la versione da terminale: https://github.com/$REPO/blob/main/ISTRUZIONI.md"
    PATTERN='Linux-x64\.tar\.gz' ;;
  *) fail "Sistema non supportato da questo script ($OS). Su Windows scarica lo zip da https://github.com/$REPO/releases/latest" ;;
esac

say "Cerco l'ultima versione di Gauntler…"
JSON=$(curl -fsSL -H 'Accept: application/vnd.github+json' "$API") || fail "Impossibile contattare GitHub."
URL=$(printf '%s' "$JSON" | grep -o '"browser_download_url": *"[^"]*"' | sed 's/.*"\(https[^"]*\)"/\1/' | grep -E "$PATTERN" | head -n 1)
SUMS=$(printf '%s' "$JSON" | grep -o '"browser_download_url": *"[^"]*SHA256SUMS.txt"' | sed 's/.*"\(https[^"]*\)"/\1/' | head -n 1)
[ -n "$URL" ] || fail "Pacchetto non trovato nell'ultima release."
FILE=$(basename "$URL")

say "Scarico ${FILE}…"
curl -fL --progress-bar -o "$TMP/$FILE" "$URL" || fail "Download non riuscito."
if [ -n "$SUMS" ] && curl -fsSL -o "$TMP/SHA256SUMS.txt" "$SUMS"; then
  EXPECTED=$(grep " $FILE\$" "$TMP/SHA256SUMS.txt" | cut -d' ' -f1)
  if command -v shasum >/dev/null 2>&1; then ACTUAL=$(shasum -a 256 "$TMP/$FILE" | cut -d' ' -f1); else ACTUAL=$(sha256sum "$TMP/$FILE" | cut -d' ' -f1); fi
  [ -z "$EXPECTED" ] || [ "$EXPECTED" = "$ACTUAL" ] || fail "Impronta SHA-256 non corrispondente: file danneggiato."
  ok "File verificato (SHA-256)"
fi

if [ "$OS" = "Darwin" ]; then
  DEST=${GAUNTLER_DEST:-/Applications}
  if [ ! -w "$DEST" ]; then DEST="$HOME/Applications"; mkdir -p "$DEST"; fi
  say "Installo Gauntler in ${DEST}…"
  ditto -x -k "$TMP/$FILE" "$TMP/app"
  [ -d "$TMP/app/Gauntler.app" ] || fail "Archivio non valido."
  pkill -x Gauntler 2>/dev/null || true
  rm -rf "$DEST/Gauntler.app"
  ditto "$TMP/app/Gauntler.app" "$DEST/Gauntler.app"
  xattr -dr com.apple.quarantine "$DEST/Gauntler.app" 2>/dev/null || true
  ok "Gauntler installato: $DEST/Gauntler.app"
  if [ -z "${GAUNTLER_NO_OPEN:-}" ]; then
    open "$DEST/Gauntler.app"
    ok "App aperta: al primo avvio installa da sola il comando \"gauntler\", ClamAV e bsdtar."
  fi
else
  DEST=${GAUNTLER_DEST:-$HOME/.local/share/gauntler}
  say "Installo Gauntler in ${DEST}…"
  mkdir -p "$TMP/x"
  tar -xzf "$TMP/$FILE" -C "$TMP/x"
  SRC=$(find "$TMP/x" -mindepth 1 -maxdepth 1 -type d | head -n 1)
  rm -rf "$DEST"
  mkdir -p "$(dirname "$DEST")"
  mv "$SRC" "$DEST"
  "$DEST/installa.sh"
  ok "Gauntler installato: $DEST"
  [ -n "${GAUNTLER_NO_OPEN:-}" ] || { "$DEST/gauntler" >/dev/null 2>&1 & }
fi

echo
ok "Fatto. Apri una nuova finestra del terminale e scrivi: gauntler"
