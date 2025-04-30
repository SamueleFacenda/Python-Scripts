#!/usr/bin/env bash
set -e

PASSFILE=".gpg_pass"
if [ ! -f "$PASSFILE" ]; then
  echo "Passphrase file '$PASSFILE' not found."
  exit 1
fi

export PINENTRY_PROGRAM=""

find olicyber/cyberchallenge/ -type f -name "*.age" | while read -r f; do
  OUT_FILE="${f%.age}"
  echo "Decrypting $f to $OUT_FILE..."
  gpg --decrypt --batch --yes \
        --passphrase-file "$PASSFILE" \
        -o "$OUT_FILE" "$f"
done
