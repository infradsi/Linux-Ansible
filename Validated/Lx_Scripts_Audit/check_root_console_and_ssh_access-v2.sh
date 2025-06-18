#!/bin/bash

# Define allowed console TTYs
ALLOWED_TTYS=("tty1" "tty2" "tty3" "tty4" "tty5" "tty6")
securetty_file="/etc/securetty"
sshd_config_file="/etc/ssh/sshd_config"

echo "🔍 Vérification des restrictions de connexion root..."

violation_found=false

# --- Vérification de /etc/securetty (présent uniquement sur certaines distros) ---
if [ -f "$securetty_file" ]; then
  echo "✔️  Fichier $securetty_file trouvé, vérification des TTY autorisés..."
  mapfile -t current_ttys < "$securetty_file"

  for tty in "${current_ttys[@]}"; do
    if [[ ! " ${ALLOWED_TTYS[*]} " =~ " ${tty} " ]]; then
      echo "⚠️  Root peut se connecter via un TTY non console : $tty"
      violation_found=true
    fi
  done
else
  echo "ℹ️  $securetty_file non trouvé (normal sur Ubuntu/Debian). Vérification ignorée."
fi

# --- Vérification de la config SSH ---
if [ ! -f "$sshd_config_file" ]; then
  echo "❌ ERREUR : $sshd_config_file introuvable. Impossible de vérifier l'accès SSH."
  exit 1
fi

ssh_root_login_setting=$(grep -Ei '^PermitRootLogin' "$sshd_config_file" | tail -1)

if [[ -z "$ssh_root_login_setting" ]]; then
  echo "⚠️  'PermitRootLogin' non défini explicitement dans $sshd_config_file."
  violation_found=true
elif [[ "$ssh_root_login_setting" =~ [Nn][Oo] ]]; then
  echo "✅ SSH : connexion root désactivée (PermitRootLogin no)."
else
  echo "❌ SSH : connexion root AUTORISÉE : $ssh_root_login_setting"
  violation_found=true
fi

# --- Vérification de l'état du compte root ---
echo "🔐 Vérification de l'état du compte root..."
root_status=$(passwd -S root 2>/dev/null)

if [[ $? -ne 0 ]]; then
  echo "❌ Impossible de déterminer l'état du compte root."
  violation_found=true
else
  if echo "$root_status" | grep -qE 'L'; then
    echo "✅ Le compte root est verrouillé (mot de passe désactivé)."
  else
    echo "⚠️  Le compte root est actif : $root_status"
    violation_found=true
  fi
fi

# --- Résultat final ---
if [ "$violation_found" = false ]; then
  echo -e "\n✅ SUCCESS : La connexion root est correctement restreinte."
  exit 0
else
  echo -e "\n❌ ÉCHEC : Certaines restrictions root ne sont pas appliquées correctement."
  exit 2
fi
