#!/usr/bin/env bash
set -e

PASSFILE=".gpg_pass"
if [ ! -f "$PASSFILE" ]; then
  echo "Passphrase file '$PASSFILE' not found."
  exit 1
fi

ALLOWED_EXTENSIONS=("py" "sage")

should_encrypt() {
  local ext="${1##*.}"
  for allowed in "${ALLOWED_EXTENSIONS[@]}"; do
    if [[ "$ext" == "$allowed" ]]; then
      return 0
    fi
  done
  return 1
}

SRC_DIR="olicyber/cyberchallenge"


find "$SRC_DIR" -type f | while read -r f; do
  if should_encrypt "$f"; then
    gpg_file="$f.gpg"

    # Encrypt if .gpg does not exist, or source is newer
    if [[ ! -f "$gpg_file" || "$f" -nt "$gpg_file" ]]; then
      echo "Encrypting $f -> $gpg_file"
      gpg --symmetric --batch --yes --cipher-algo AES256 \
          --passphrase-file "$PASSFILE" \
          -o "$gpg_file" "$f"
      # rm "$f"   # uncomment if you want to remove the plaintext
    else
      # echo "Skipping $f (already up-to-date)"
      true
    fi
  fi
done
