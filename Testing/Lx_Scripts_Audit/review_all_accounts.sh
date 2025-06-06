#!/bin/bash

# Fichiers de sortie
CSV_FILE="review_all_accounts.csv"
JSON_FILE="review_all_accounts.json"

echo "user,type,source,group" > "$CSV_FILE"
echo "[" > "$JSON_FILE"
first_json=true

# Fonction ajout CSV + JSON
add_account() {
  local user=$1
  local type=$2
  local source=$3
  local group=$4

  echo "${user},${type},${source},${group}" >> "$CSV_FILE"

  if [ "$first_json" = true ]; then
    first_json=false
  else
    echo "," >> "$JSON_FILE"
  fi
  echo "  {\"user\": \"${user}\", \"type\": \"${type}\", \"source\": \"${source}\", \"group\": \"${group}\"}" >> "$JSON_FILE"
}

# Fonction pour lister membres d'un groupe
search_group_members() {
  local group=$1
  members=$(getent group "$group" | awk -F: '{print $4}' | tr ',' ' ')
  for user in $members; do
    if [ -n "$user" ]; then
      add_account "$user" "local-user" "group:$group" "$group"
    fi
  done
}

# --- Comptes locaux (/etc/passwd) ---
echo "📂 Comptes locaux (/etc/passwd)..."
awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | while read -r user; do
  add_account "$user" "local-user" "passwd" "none"
done

# --- Tous les groupes locaux (/etc/group) ---
echo "👥 Groupes locaux (/etc/group)..."
getent group | awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' | while read -r group; do
  search_group_members "$group"
done

# --- Sudoers permissions ---
echo "🛡️  Droits sudo (/etc/sudoers)..."
if [ -f /etc/sudoers ]; then
  grep -Ev '^#|^$' /etc/sudoers | grep -E '(ALL|NOPASSWD)' | while read -r line; do
    user=$(echo "$line" | awk '{print $1}')
    if [ -n "$user" ]; then
      add_account "$user" "local-user" "sudoers" "sudoers"
    fi
  done
fi

if [ -d /etc/sudoers.d ]; then
  grep -rhE '^[^#].*(ALL|NOPASSWD)' /etc/sudoers.d/ | while read -r line; do
    user=$(echo "$line" | awk '{print $1}')
    if [ -n "$user" ]; then
      add_account "$user" "local-user" "sudoers.d" "sudoers"
    fi
  done
fi

# --- Accès SSH AllowGroups / AllowUsers ---
echo "🔐 Vérification SSH (AllowGroups/AllowUsers)..."
if [ -f /etc/ssh/sshd_config ]; then
  grep -Ei '^(AllowUsers|AllowGroups)' /etc/ssh/sshd_config | while read -r line; do
    for entry in $(echo "$line" | cut -d' ' -f2-); do
      if [[ "$line" =~ AllowUsers ]]; then
        add_account "$entry" "ssh-user" "sshd_config" "ssh-allowuser"
      else
        add_account "$entry" "ssh-group" "sshd_config" "ssh-allowgroup"
      fi
    done
  done
fi

# --- Comptes liés au domaine via Realm ---
echo "🌐 Comptes configurés via Realm..."
if command -v realm >/dev/null 2>&1; then
  realm list | awk '
    BEGIN {RS="\n\n"; FS="\n"}
    {
      for (i=1; i<=NF; i++) {
        if ($i ~ /^domain-name:/) domain=substr($i, index($i,$2));
        if ($i ~ /^configured-users:/) users=$i;
        if ($i ~ /^configured-groups:/) groups=$i;
      }
      if (users) {
        split(users, a, ": ");
        split(a[2], userlist, " ");
        for (u in userlist) print "user:" userlist[u];
      }
      if (groups) {
        split(groups, a, ": ");
        split(a[2], grouplist, " ");
        for (g in grouplist) print "group:" grouplist[g];
      }
    }
  ' | while read -r line; do
    if [[ "$line" == user:* ]]; then
      user=${line#user:}
      add_account "$user" "domain-user" "realm" "realm-user"
    elif [[ "$line" == group:* ]]; then
      group=${line#group:}
      add_account "$group" "domain-group" "realm" "realm-group"
    fi
  done
else
  echo "❌ Realm non disponible."
fi

# Fermeture JSON
echo "]" >> "$JSON_FILE"

echo
echo "✅ Export terminé :"
echo "  - $CSV_FILE"
echo "  - $JSON_FILE"

