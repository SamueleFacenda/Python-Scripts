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

changed_files=$(git status --porcelain | awk '{print $2}' | grep "^olicyber/cyberchallenge/")

for f in $changed_files; do
  if [[ -f "$f" ]] && should_encrypt "$f"; then
    # echo "Encrypting $f..."
    gpg --symmetric --batch --yes --cipher-algo AES256 \
            --passphrase-file "$PASSFILE" \
            -o "$f.gpg" "$f"
    # rm "$f"
  # else
  #   echo "Skipping $f (not in allowed extensions)"
  fi
done
