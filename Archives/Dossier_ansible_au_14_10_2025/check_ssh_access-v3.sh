#!/bin/bash
#
# check_ssh_access-v3.sh — lit servers.txt au format:
#   - CSV: host1,host2,host3,...
#   - OU un hôte par ligne
# Il normalise les deux formats, enlève CRLF/BOM/espaces, déduplique, puis teste l'accès SSH (mot de passe).

set -Eeuo pipefail

HOSTS_FILE="servers.txt"
USERNAME="fr-726-ansible"
TIMEOUT=5

SSH_OPTS=(
  -n                                 # ne lit pas sur stdin
  -T                                 # pas de pty
  -o ConnectTimeout=${TIMEOUT}
  -o PreferredAuthentications=password
  -o KbdInteractiveAuthentication=no
  -o PubkeyAuthentication=no
  -o BatchMode=no
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o NumberOfPasswordPrompts=1
  -o ConnectionAttempts=1
  -o LogLevel=ERROR
)

need() { command -v "$1" >/dev/null 2>&1 || { echo "❌ '$1' requis"; exit 1; }; }
trim() { local s="$1"; s="${s#"${s%%[![:space:]]*}"}"; s="${s%"${s##*[![:space:]]}"}"; printf '%s' "$s"; }

[[ -f "$HOSTS_FILE" ]] || { echo "❌ $HOSTS_FILE introuvable"; exit 1; }
need sshpass
need ssh

# Mot de passe (on évite qu'il apparaisse dans 'ps' en utilisant SSHPASS avec sshpass -e)
read -s -p "Mot de passe pour '$USERNAME' : " PASSWORD; echo
export SSHPASS="$PASSWORD"

# Logs propres
: > ssh_access_success.log
: > ssh_access_failed.log

# --- Normalisation de servers.txt ---
# 1) lit tout le fichier
raw="$(cat "$HOSTS_FILE")"
# 2) enlève BOM et CR
raw="${raw//$'\xef\xbb\xbf'/}"
raw="${raw//$'\r'/}"
# 3) remplace virgules ET retours ligne par des séparateurs uniformes '\n'
#    -> supporte CSV sur une ou plusieurs lignes ET format "un host par ligne"
norm="$(printf '%s' "$raw" | tr ',\n' '\n\n' )"
# 4) trim, filtre vides et commentaires, déduplique
#    (on évite awk/sed multiples; awk fait trim + filtre + uniq)
mapfile -t HOSTS < <(
  awk '
    BEGIN{FS=OFS="";}
    {
      # trim début/fin
      gsub(/^[ \t]+|[ \t]+$/,"",$0);
      if ($0 == "" || $0 ~ /^#/) next;
      if (!seen[$0]++) print $0;
    }
  ' <<< "$norm"
)

count="${#HOSTS[@]}"
if (( count == 0 )); then
  echo "❌ Aucun hôte valide trouvé dans $HOSTS_FILE."
  exit 1
fi

echo "==================================================================="
echo " Vérification SSH (mot de passe) – utilisateur: '$USERNAME'"
echo " Fichier: $HOSTS_FILE | Hôtes détectés: $count"
printf '  -> %s\n' "${HOSTS[@]}"
echo " Timeout: ${TIMEOUT}s"
echo "==================================================================="

# --- Tests SSH ---
for host in "${HOSTS[@]}"; do
  echo -e "\nTest SSH sur $host ..."
  if sshpass -e ssh "${SSH_OPTS[@]}" "$USERNAME@$host" "echo OK" </dev/null >/dev/null 2>&1; then
    echo "[✅ SUCCESS] $host"
    echo "$host" >> ssh_access_success.log
  else
    rc=$?
    echo "[❌ FAILURE] $host (rc=$rc)"
    echo "$host" >> ssh_access_failed.log
  fi
done

# Résumé
ok=$(wc -l < ssh_access_success.log 2>/dev/null || echo 0)
ko=$(wc -l < ssh_access_failed.log 2>/dev/null || echo 0)
echo -e "\nRésumé :"
echo "  Succès : $ok"
echo "  Échecs : $ko"
[[ -s ssh_access_success.log ]] && echo "  → OK   : $(pwd)/ssh_access_success.log"
[[ -s ssh_access_failed.log  ]] && echo "  → FAIL : $(pwd)/ssh_access_failed.log"
