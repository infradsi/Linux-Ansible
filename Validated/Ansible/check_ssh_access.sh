#!/bin/bash
# check_ssh_access.sh – test d'accès SSH par mot de passe sur une liste d'hôtes
# Usage: ./check_ssh_access.sh

set -euo pipefail


touch ./ssh_access_failed.log
touch ./ssh_access_success.log

#=== CONFIGURATION ========================================================
HOSTS_FILE="servers.txt"           # Fichier contenant la liste des hôtes (1 par ligne)
USERNAME="fr-726-ansible"          # Compte à tester
TIMEOUT=5                          # Timeout SSH en secondes
SSH_OPTS=(
  -o ConnectTimeout=${TIMEOUT}
  -o BatchMode=no
  -o PreferredAuthentications=password
  -o PubkeyAuthentication=no
  -o StrictHostKeyChecking=no             # éviter le prompt d’empreinte
  -o UserKnownHostsFile=/dev/null         # ne pas polluer known_hosts
  -o NumberOfPasswordPrompts=1
  -o ConnectionAttempts=1
)
#========================================================================

# Vérifs préalables
if [[ ! -f "$HOSTS_FILE" ]]; then
  echo "❌ Fichier $HOSTS_FILE introuvable."
  exit 1
fi
if ! command -v sshpass >/dev/null 2>&1; then
  echo "❌ sshpass n'est pas installé. Installe-le (ex: 'sudo dnf/apt/yum install sshpass')."
  exit 1
fi

# Demande du mot de passe avec masquage
read -s -p "Entrez le mot de passe pour l'utilisateur '$USERNAME' : " PASSWORD
echo

# Nettoyage des anciens logs
: > ssh_access_success.log
: > ssh_access_failed.log

# Nettoyage/normalisation des hôtes
CLEAN_HOSTS="$(mktemp)"
# 1) supprime CR Windows, 2) trim espaces début/fin, 3) enlève vides, 4) enlève commentaires (#) après trim
sed 's/\r$//' "$HOSTS_FILE" \
  | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
  | awk 'NF>0 && $0 !~ /^[#]/' \
  > "$CLEAN_HOSTS"
  

echo "==================================================================="
echo " Vérification de l'accès SSH pour l'utilisateur '$USERNAME'"
echo " Liste d'hôtes : $HOSTS_FILE (nettoyée -> $CLEAN_HOSTS)"
echo " Timeout: ${TIMEOUT}s"
echo "==================================================================="
echo

<<<<<<< HEAD
# Boucle sur chaque hôte
while IFS= read -r host || [[ -n "$host" ]]; do
    [[ -z "$host" || "$host" == \#* ]] && continue  # ignorer lignes vides ou commentées - qui commencent par # ou *

    echo "Test SSH sur $host ..."

    sshpass -p "$PASSWORD" ssh -o ConnectTimeout=$TIMEOUT "$USERNAME@$host" "echo OK" >/dev/null 2>&1

    if [[ $? -eq 0 ]]; then
        echo "[✅ SUCCESS] $host"
        echo "$host" >> ssh_access_success.log
    else
        echo "[❌ FAILURE] $host"
        echo "$host" >> ssh_access_failed.log
    fi

    echo
done < "$HOSTS_FILE"

=======
# Boucle sur chaque hôte nettoyé
while IFS= read -r host; do
  [[ -z "$host" ]] && continue

  echo "Test SSH sur $host ..."
  if sshpass -p "$PASSWORD" ssh "${SSH_OPTS[@]}" "$USERNAME@$host" "echo OK" >/dev/null 2>&1; then
    echo "[✅ SUCCESS] $host"
    echo "$host" >> ssh_access_success.log
  else
    echo "[❌ FAILURE] $host"
    echo "$host" >> ssh_access_failed.log
  fi
  echo
done < "$CLEAN_HOSTS"

>>>>>>> 23580856bfbc8667068436e8bf5ca3c679c2aa05
# Résumé
success_count=$(wc -l < ssh_access_success.log 2>/dev/null || echo 0)
fail_count=$(wc -l < ssh_access_failed.log 2>/dev/null || echo 0)

echo "Résumé :"
<<<<<<< HEAD
#echo "Succès : $(wc -l < ssh_access_success.log 2>/dev/null || echo 0)"
#echo "Échecs : $(wc -l < ssh_access_failed.log 2>/dev/null || echo 0)"
=======
echo "  Succès : ${success_count}"
echo "  Échecs : ${fail_count}"
[[ -s ssh_access_success.log ]] && echo "  → Détails OK   : $(pwd)/ssh_access_success.log"
[[ -s ssh_access_failed.log  ]] && echo "  → Détails FAIL : $(pwd)/ssh_access_failed.log"

# Nettoyage
rm -f "$CLEAN_HOSTS"
>>>>>>> 23580856bfbc8667068436e8bf5ca3c679c2aa05
