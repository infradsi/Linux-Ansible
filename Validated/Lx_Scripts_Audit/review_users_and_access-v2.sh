#!/bin/bash

echo "🔍 Analyse des accès utilisateurs (local + AD)"
echo "==============================================="

# Détection de la distribution
distro=$(awk -F= '/^ID=/{print $2}' /etc/os-release | tr -d '"')
echo "➡️  Distribution détectée : $distro"
echo "Date : $(date)"
echo "Hostname : $(hostname)"
echo

violation_found=false

# Détection des chemins et UID/GID min selon la distro
case "$distro" in
  ubuntu|debian)
    UID_MIN=1000
    SUDO_GROUP="sudo"
    ;;
  rhel|centos|fedora|rocky|almalinux)
    UID_MIN=1000
    SUDO_GROUP="wheel"
    ;;
  *)
    echo "⚠️ Distribution non reconnue. Valeurs par défaut utilisées."
    UID_MIN=1000
    SUDO_GROUP="wheel"
    ;;
esac

# --- Utilisateurs locaux ---
echo "📂 Utilisateurs locaux (UID >= $UID_MIN) :"
getent passwd | awk -F: -v min="$UID_MIN" '$3 >= min && $3 < 65534 { print $1 " (UID: " $3 ")" }'
echo

# --- Groupes locaux ---
echo "👥 Groupes locaux (GID >= $UID_MIN) :"
getent group | awk -F: -v min="$UID_MIN" '$3 >= min && $3 < 65534 { print $1 " (GID: " $3 ")" }'
echo

# --- Connexion Active Directory ---
echo "🌐 Détection de la connexion à Active Directory..."
domain_connected=false

if systemctl is-active sssd >/dev/null 2>&1 && getent passwd | grep -qE '\@'; then
  echo "✅ Connecté via SSSD"
  domain_connected=true
elif command -v wbinfo >/dev/null 2>&1 && wbinfo -t >/dev/null 2>&1; then
  echo "✅ Connecté via Winbind"
  domain_connected=true
else
  echo "ℹ️  Pas de connexion AD détectée (ou méthode non standard)"
fi
echo

# --- Utilisateurs AD (si connectés) ---
if [ "$domain_connected" = true ]; then
  echo "📂 Utilisateurs AD avec shell actif :"
  getent passwd | grep -E '\@|\\\\' | awk -F: '$7 !~ "/nologin" && $7 !~ "/false" { print $1 " (UID: " $3 ")" }' | head -20
  echo

  echo "👥 Groupes AD (échantillon) :"
  getent group | grep -E '\@|\\\\' | awk -F: '{ print $1 " (GID: " $3 ")" }' | head -20
  echo
fi

# --- Accès SSH ---
echo "🔐 Accès SSH (/etc/ssh/sshd_config) :"
if [ -f /etc/ssh/sshd_config ]; then
  grep -Ei '^(AllowUsers|AllowGroups|DenyUsers|DenyGroups)' /etc/ssh/sshd_config | sed 's/^/  /'
else
  echo "⚠️  Fichier sshd_config introuvable."
fi
echo

# --- Droits sudo ---
echo "🧑‍💻 Droits sudo :"

echo "- Membres du groupe sudo ($SUDO_GROUP) :"
getent group "$SUDO_GROUP" | awk -F: '{ print $4 }' | tr ',' '\n' | sed 's/^/  - /'

echo
echo "- Déclarations dans /etc/sudoers :"
grep -Ev '^#|^$' /etc/sudoers | sed 's/^/  /'

if [ -d /etc/sudoers.d ]; then
  echo
  echo "- Fichiers dans /etc/sudoers.d/ :"
  for f in /etc/sudoers.d/*; do
    [ -f "$f" ] && echo "--- $f ---" && grep -Ev '^#|^$' "$f"
  done
else
  echo "ℹ️  Aucun répertoire /etc/sudoers.d/ trouvé."
fi
echo

# --- Shells valides ---
echo "✅ Utilisateurs avec un shell de connexion actif :"
getent passwd | awk -F: '$7 !~ "/nologin" && $7 !~ "/false" { print $1 ": " $7 }'
echo

echo "✅ Fin de l'analyse."
