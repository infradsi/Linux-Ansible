#!/bin/bash

# Fichiers de sortie
CSV_FILE="audit_user_access.csv"
JSON_FILE="audit_user_access.json"
GROUPS_CSV_FILE="audit_groups_access.csv"
GROUPS_JSON_FILE="audit_groups_access.json"

# Initialisation CSV/JSON
echo "user,uid,gid,shell,source" > "$CSV_FILE"
echo "[" > "$JSON_FILE"
echo "group_name,members,source" > "$GROUPS_CSV_FILE"
echo "[" > "$GROUPS_JSON_FILE"

first_json_entry=true
first_group_json=true

# Détection de la distribution
distro=$(awk -F= '/^ID=/{print $2}' /etc/os-release | tr -d '"')
echo "🔍 Distribution : $distro"

case "$distro" in
  ubuntu|debian)
    UID_MIN=1000
    AD_UID_MIN=20000
    SUDO_GROUP="sudo"
    ;;
  rhel|centos|fedora|rocky|almalinux)
    UID_MIN=1000
    AD_UID_MIN=10000
    SUDO_GROUP="wheel"
    ;;
  *)
    UID_MIN=1000
    AD_UID_MIN=10000
    SUDO_GROUP="wheel"
    ;;
esac

# Fonction pour ajouter un utilisateur
add_user() {
  local user=$1
  local uid=$2
  local gid=$3
  local shell=$4
  local source=$5

  echo "${user},${uid},${gid},${shell},${source}" >> "$CSV_FILE"

  if [ "$first_json_entry" = true ]; then
    first_json_entry=false
  else
    echo "," >> "$JSON_FILE"
  fi

  echo "  {\"user\": \"${user}\", \"uid\": ${uid}, \"gid\": ${gid}, \"shell\": \"${shell}\", \"source\": \"${source}\"}" >> "$JSON_FILE"
}

# Fonction pour ajouter un groupe
add_group() {
  local group_name=$1
  local members=$2
  local source=$3

  echo "${group_name},\"${members}\",${source}" >> "$GROUPS_CSV_FILE"

  if [ "$first_group_json" = true ]; then
    first_group_json=false
  else
    echo "," >> "$GROUPS_JSON_FILE"
  fi

  echo "  {\"group\": \"${group_name}\", \"members\": \"${members}\", \"source\": \"${source}\"}" >> "$GROUPS_JSON_FILE"
}

# Extraction utilisateurs
echo "📂 Liste des utilisateurs..."
getent passwd | while IFS=: read -r user x uid gid desc home shell; do
  if [[ $uid -ge $UID_MIN && $uid -lt 65534 ]]; then
    if [[ $uid -ge $AD_UID_MIN ]]; then
      add_user "$user" "$uid" "$gid" "$shell" "AD"
    else
      add_user "$user" "$uid" "$gid" "$shell" "local"
    fi
  fi
done

# Extraction groupes sensibles (sudo / wheel)
echo "🛡️  Membres du groupe $SUDO_GROUP..."
if getent group "$SUDO_GROUP" >/dev/null 2>&1; then
  members=$(getent group "$SUDO_GROUP" | awk -F: '{ print $4 }' | tr ',' ' ')
  add_group "$SUDO_GROUP" "$members" "local"
fi

# Extraction AllowGroups SSH
echo "🔐 Vérification AllowGroups SSH..."
if [ -f /etc/ssh/sshd_config ]; then
  ssh_groups=$(grep -Ei '^AllowGroups' /etc/ssh/sshd_config | awk '{$1=""; print $0}' | xargs)
  if [ -n "$ssh_groups" ]; then
    for group in $ssh_groups; do
      if getent group "$group" >/dev/null 2>&1; then
        members=$(getent group "$group" | awk -F: '{ print $4 }' | tr ',' ' ')
        add_group "$group" "$members" "ssh"
      else
        add_group "$group" "No members found" "ssh"
      fi
    done
  fi
fi

# Fermeture JSON
echo "]" >> "$JSON_FILE"
echo "]" >> "$GROUPS_JSON_FILE"

echo
echo "✅ Exports terminés :"
echo "  - $CSV_FILE"
echo "  - $JSON_FILE"
echo "  - $GROUPS_CSV_FILE"
echo "  - $GROUPS_JSON_FILE"
