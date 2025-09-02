#!/bin/bash
# check_ssh_access_csv.sh – Test d'accès SSH par mot de passe depuis un servers.txt au format CSV
# Format attendu de servers.txt : host1,host2,host3,... (espaces optionnels, CRLF/retours ligne acceptés)

set -euo pipefail

#=== CONFIG ===============================================================
HOSTS_FILE="servers.txt"
USERNAME="fr-726-ansible"
TIMEOUT=5

SSH_OPTS=(
  -n                                   # ne lit pas sur stdin (important)
  -T                                   # pas de pseudo-tty
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
#==========================================================================
# Fonctions utilitaires
trim() { # trim espaces (début/fin)
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

need() { command -v "$1" >/dev/null 2>&1 || { echo "❌ '$1' requis"; exit 1; }; }

[[ -f "$HOSTS_FILE" ]] || { echo "❌ $HOSTS_FILE introuvable"; exit 1; }
need sshpass
need ssh

read -s -p "Mot de passe pour '$USERNAME' : " PASSWORD; echo

# Logs propres
: > ssh_access_success.log
: > ssh_access_failed.log

#--- Lecture + normalisation CSV ------------------------------------------
# - accepte CRLF, plusieurs lignes, espaces, virgules multiples
# - supprime BOM éventuel
# - construit un tableau bash: HOSTS[@]
raw_csv="$(cat "$HOSTS_FILE")"
# supprime BOM éventuel
raw_csv="${raw_csv//$'\xef\xbb\xbf'/}"
# remplace retours par des virgules, enlève \r, compresse les virgules multiples
raw_csv="$(printf '%s' "$raw_csv" | tr '\r\n' ',,' | sed 's/,,*/,/g')"

IFS=',' read -r -a HOSTS <<< "$raw_csv"

# Filtrage/trim
clean_hosts=()
for h in "${HOSTS[@]}"; do
  h="$(trim "$h")"
  [[ -z "$h" ]] && continue
  [[ "$h" =~ ^# ]] && continue
  clean_hosts+=("$h")
done

if ((${#clean_hosts[@]}==0)); then
  echo "❌ Aucun hôte valide trouvé dans $HOSTS_FILE (format CSV attendu)."
  exit 1
fi

echo "==================================================================="
echo " Vérification SSH (mot de passe) pour l'utilisateur '$USERNAME'"
echo " Fichier: $HOSTS_FILE | Hôtes détectés: ${#clean_hosts[@]}"
echo " Timeout: ${TIMEOUT}s"
echo "==================================================================="

#--- Boucle de tests -------------------------------------------------------
for host in "${clean_hosts[@]}"; do
  echo -e "\nTest SSH sur $host ..."
  if sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USERNAME@$host" "echo OK" </dev/null >/dev/null 2>&1; then
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
