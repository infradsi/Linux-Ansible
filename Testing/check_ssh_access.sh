#!/bin/bash

#=== CONFIGURATION ========================================================
HOSTS_FILE="servers.txt"           # Fichier contenant la liste des hôtes (1 par ligne)
USERNAME="fr-726-ansible"          # Compte à tester
TIMEOUT=5                          # Timeout SSH en secondes
NonASCIIChars-OK  = "🟢"
NonASCIIChars-NOK = "🔴"
#========================================================================

# Demande du mot de passe avec masquage
read -s -p "🔐 Entrez le mot de passe pour l'utilisateur '$USERNAME' : " PASSWORD
echo

# Vérification fichier
if [[ ! -f "$HOSTS_FILE" ]]; then
    echo "❌ Fichier $HOSTS_FILE introuvable."
    exit 1
fi

# Nettoyage des anciens logs
rm -f ssh_access_success.log ssh_access_failed.log

echo "==================================================================="
echo "🔍 Vérification de l'accès SSH pour l'utilisateur '$USERNAME'"
echo "📁 Liste d'hôtes : $HOSTS_FILE"
echo "==================================================================="
echo

# Boucle sur chaque hôte
while IFS= read -r host || [[ -n "$host" ]]; do
    [[ -z "$host" || "$host" == \#* ]] && continue  # ignorer lignes vides ou commentées

    echo "👉 Test SSH sur $host ..."

    sshpass -p "$PASSWORD" ssh -o ConnectTimeout=$TIMEOUT \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        "$USERNAME@$host" "echo OK" >/dev/null 2>&1

    if [[ $? -eq 0 ]]; then
        echo "[✅ SUCCESS] $host"
        echo "$host" >> ssh_access_success.log
    else
        echo "[❌ FAILURE] $host"
        echo "$host" >> ssh_access_failed.log
    fi

    echo
done < "$HOSTS_FILE"

# Résumé
echo "🟢🟢🟢 Résumé :"
echo "🟢 Succès : $(wc -l < ssh_access_success.log 2>/dev/null || echo 0)"
echo "🔴 Échecs : $(wc -l < ssh_access_failed.log 2>/dev/null || echo 0)"
