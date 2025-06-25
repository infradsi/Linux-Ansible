#!/bin/bash

sshd_config_file="/etc/ssh/sshd_config"
pam_login_file="/etc/pam.d/login"
securetty_file="/etc/securetty"

echo "🔍 Détection de la distribution..."
distro=$(grep -Ei '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')

echo "➡️  Distribution détectée : $distro"

violation_found=false

# --- Ubuntu/Debian ---
if [[ "$distro" =~ (ubuntu|debian) ]]; then
  echo "✔️ Comportement adapté pour $distro"

  # Pas de /etc/securetty par défaut
  echo "ℹ️  /etc/securetty est ignoré sur $distro"

# --- RHEL/CentOS/Fedora ---
elif [[ "$distro" =~ (rhel|centos|fedora|rocky|almalinux) ]]; then
  echo "✔️ Comportement adapté pour $distro"

  # Vérifie si pam_securetty.so est activé
  if grep -q "pam_securetty.so" "$pam_login_file" 2>/dev/null; then
    if grep -qE '^\s*#.*pam_securetty.so' "$pam_login_file"; then
      echo "⚠️  pam_securetty.so est COMMENTÉ — /etc/securetty inactif."
    else
      echo "✅ pam_securetty.so est actif."
      if [ -f "$securetty_file" ]; then
        echo "🔍 Vérification de /etc/securetty..."
        mapfile -t current_ttys < "$securetty_file"
        allowed_ttys=("tty1" "tty2" "tty3" "tty4" "tty5" "tty6")
        for tty in "${current_ttys[@]}"; do
          if [[ ! " ${allowed_ttys[*]} " =~ " ${tty} " ]]; then
            echo "⚠️  Root peut se connecter via un TTY non console : $tty"
            violation_found=true
          fi
        done
      else
        echo "⚠️  pam_securetty.so est actif mais /etc/securetty est manquant."
        violation_found=true
      fi
    fi
  else
    echo "ℹ️  pam_securetty.so non trouvé — pas de contrôle TTY appliqué."
  fi

else
  echo "❓ Distribution non prise en charge directement. Comportement par défaut appliqué."
fi

# --- Vérification SSH ---
echo "🔐 Vérification SSH (PermitRootLogin)..."

if [ ! -f "$sshd_config_file" ]; then
  echo "❌ ERREUR : $sshd_config_file introuvable."
  exit 1
fi

ssh_root_login_setting=$(grep -Ei '^PermitRootLogin' "$sshd_config_file" | tail -1)

if [[ -z "$ssh_root_login_setting" ]]; then
  echo "⚠️  PermitRootLogin non défini — comportement par défaut peut permettre root."
  violation_found=true
elif [[ "$ssh_root_login_setting" =~ [Nn][Oo] ]]; then
  echo "✅ SSH : root désactivé (PermitRootLogin no)."
else
  echo "❌ SSH : root autorisé : $ssh_root_login_setting"
  violation_found=true
fi

# --- Vérification de l’état du compte root ---
echo "👤 Vérification de l’état du compte root..."
root_status=$(passwd -S root 2>/dev/null)

if [[ $? -ne 0 ]]; then
  echo "❌ Impossible de lire l’état du compte root."
  violation_found=true
else
  if echo "$root_status" | grep -qE 'L'; then
    echo "✅ Le compte root est verrouillé (password lock)."
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
  echo -e "\n❌ ÉCHEC : Des restrictions root sont manquantes ou non appliquées."
  exit 2
fi
