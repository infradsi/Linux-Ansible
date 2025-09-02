#!/bin/bash
set -euo pipefail

HOSTS_FILE="servers.txt"
USERNAME="fr-726-ansible"

TIMEOUT=5
SSH_OPTS=(
  -n                                   # NE PAS lire sur stdin
  -o ConnectTimeout=${TIMEOUT}
  -o BatchMode=no
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o NumberOfPasswordPrompts=1
  -o ConnectionAttempts=1
)

[[ -f "$HOSTS_FILE" ]] || { echo "❌ $HOSTS_FILE introuvable"; exit 1; }
command -v sshpass >/dev/null || { echo "❌ sshpass manquant"; exit 1; }

read -s -p "Mot de passe pour '$USERNAME' : " PASSWORD; echo

: > ssh_access_success.log
: > ssh_access_failed.log

CLEAN_HOSTS="$(mktemp)"
sed 's/\r$//' "$HOSTS_FILE" \
 | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
 | awk 'NF>0 && $0 !~ /^[#]/' > "$CLEAN_HOSTS"

while IFS= read -r host; do
  [[ -z "$host" ]] && continue
  echo "Test SSH sur $host ..."
  if sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USERNAME@$host" "echo OK" </dev/null >/dev/null 2>&1; then
    echo "[✅ SUCCESS] $host"; echo "$host" >> ssh_access_success.log
  else
    echo "[❌ FAILURE] $host"; echo "$host" >> ssh_access_failed.log
  fi
  echo
done < "$CLEAN_HOSTS"

echo "Résumé :"
echo "  Succès : $(wc -l < ssh_access_success.log 2>/dev/null || echo 0)"
echo "  Échecs : $(wc -l < ssh_access_failed.log 2>/dev/null || echo 0)"
rm -f "$CLEAN_HOSTS"
