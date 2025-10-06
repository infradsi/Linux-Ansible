#!/usr/bin/env bash
# ssh_access_check.sh - Teste l'accès SSH par mot de passe sur une liste d'hôtes
# Usage:
#   ./ssh_access_check.sh -u <user> -f <hosts.txt> [-p <password>] [-P <port>] [-t <timeout>] [-o <csv>]
#
# Exemple:
#   ./ssh_access_check.sh -u audit -f hosts.txt -P 22 -t 5 -o report.csv
#
# Le fichier hosts.txt contient un hôte par ligne (commentaires # et lignes vides ignorés)

set -euo pipefail

USER_NAME=""
HOSTS_FILE=""
PASSWORD="${PASSWORD:-}"         # Permet d'utiliser la variable d'env PASSWORD si définie
PORT="22"
TIMEOUT="5"
CSV_OUT="ssh_access_report.csv"

while getopts ":u:f:p:P:t:o:" opt; do
  case "$opt" in
    u) USER_NAME="$OPTARG" ;;
    f) HOSTS_FILE="$OPTARG" ;;
    p) PASSWORD="$OPTARG" ;;
    P) PORT="$OPTARG" ;;
    t) TIMEOUT="$OPTARG" ;;
    o) CSV_OUT="$OPTARG" ;;
    \?) echo "Option invalide: -$OPTARG" >&2; exit 2 ;;
    :)  echo "Option -$OPTARG requiert un argument." >&2; exit 2 ;;
  esac
done

[[ -z "$USER_NAME" || -z "$HOSTS_FILE" ]] && { echo "Usage: $0 -u <user> -f <hosts.txt> [-p <password>] [-P <port>] [-t <timeout>] [-o <csv>]"; exit 2; }
command -v sshpass >/dev/null 2>&1 || { echo "ERREUR: sshpass est requis."; exit 3; }
[[ -r "$HOSTS_FILE" ]] || { echo "ERREUR: fichier d'hôtes introuvable: $HOSTS_FILE"; exit 4; }

if [[ -z "$PASSWORD" ]]; then
  read -r -s -p "Mot de passe pour l'utilisateur '$USER_NAME': " PASSWORD
  echo
fi

# En-tête CSV
echo "host,port,user,reachable,latency_ms,rc,reason" > "$CSV_OUT"

# Test GNU date ms
ms_now() {
  if date +%s%3N >/dev/null 2>&1; then date +%s%3N; else
    # Fallback approx en ms
    echo $(( $(date +%s) * 1000 ))
  fi
}

while IFS= read -r host || [[ -n "$host" ]]; do
  host="${host%%[[:space:]]*}"
  [[ -z "$host" || "${host:0:1}" == "#" ]] && continue

  start_ms="$(ms_now)"
  set +e
  out="$(
    sshpass -p "$PASSWORD" ssh \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o PreferredAuthentications=password \
      -o PubkeyAuthentication=no \
      -o ConnectTimeout="$TIMEOUT" \
      -p "$PORT" \
      -tt "${USER_NAME}@${host}" \
      'echo OK' 2>&1
  )"
  rc=$?
  set -e
  end_ms="$(ms_now)"
  latency=$(( end_ms - start_ms ))

  if [[ $rc -eq 0 && "$out" == *"OK"* ]]; then
    echo "${host},${PORT},${USER_NAME},yes,${latency},0,OK" | tee -a "$CSV_OUT" >/dev/null
  else
    # Raison courte (première ligne de l'erreur)
    reason="$(echo "$out" | head -n1 | tr ',' ';')"
    echo "${host},${PORT},${USER_NAME},no,${latency},${rc},${reason}" | tee -a "$CSV_OUT" >/dev/null
  fi
done < "$HOSTS_FILE"

echo "Rapport écrit: $CSV_OUT"
