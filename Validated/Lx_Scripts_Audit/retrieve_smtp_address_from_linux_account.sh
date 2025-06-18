#!/bin/bash

# Paramètres LDAP
LDAP_SERVER="ldap://YPH010GADXU101.user.adxrt.com"
LDAP_BASE_DN="OU=users,DC=user,DC=adxrt,DC=com"
BIND_USER="C95059561@adxuser.com"
BIND_PASS=""

# Fichier CSV d'entrée généré par l'audit
INPUT_FILE="./review_all_accounts.csv"

# Fichier de sortie
OUTPUT_FILE="./audit_emails.csv"

# Initialiser le fichier de sortie
echo "server,user,email" > "$OUTPUT_FILE"

# Lire chaque ligne du fichier (ignorer la 1ère ligne entête)
tail -n +2 "$INPUT_FILE" | while IFS=',' read -r server user type source group; do
  # On ignore les groupes
  if [[ "$type" == "domain-user" || "$type" == "local-user" || "$type" == "ssh-user" ]]; then
    # Nettoyer user si besoin (ex: DOMAIN\\user)
    clean_user=$(echo "$user" | sed 's/.*\\//')
    
    # Faire la recherche LDAP
    email=$(ldapsearch -LLL -x -H "$LDAP_SERVER" -D "$BIND_USER" -w "$BIND_PASS" \
      -b "$LDAP_BASE_DN" "(sAMAccountName=${clean_user})" mail | grep "^mail:" | awk '{print $2}')

    # Ajouter au fichier résultat
    echo "${server},${user},${email}" >> "$OUTPUT_FILE"
    
    echo "✔️ $user -> $email"
  fi
done

echo "✅ Emails extraits dans : $OUTPUT_FILE"
