#!/bin/bash

# --- Paramètres ---
UTILISATEUR="$1"
OPTION="$2"
BACKUP_DIR="/root/backup_sudo_ssh_$(date +%Y%m%d_%H%M%S)"
SUDOERS_D="/etc/sudoers.d"
SSHD_CONFIG="/etc/ssh/sshd_config"

# --- Fonctions ---
function detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    else
        echo "Impossible de détecter l'OS."
        exit 1
    fi
}

function backup_file() {
    local file="$1"
    mkdir -p "$BACKUP_DIR"
    cp "$file" "$BACKUP_DIR/"
    echo "Backup de $file -> $BACKUP_DIR/"
}

function create_user_if_needed() {
    if id "$UTILISATEUR" >/dev/null 2>&1; then
        echo "Utilisateur $UTILISATEUR déjà existant."
    else
        if [ "$OPTION" == "--no-create" ]; then
            echo "Erreur : l'utilisateur $UTILISATEUR n'existe pas et --no-create est spécifié."
            exit 2
        else
            echo "Création de l'utilisateur $UTILISATEUR..."
            useradd -m -s /bin/bash "$UTILISATEUR"
            echo "Utilisateur $UTILISATEUR créé. Veuillez définir son mot de passe :"
            passwd "$UTILISATEUR"
        fi
    fi
}

function grant_sudo_via_sudoersd() {
    mkdir -p "$SUDOERS_D"
    local sudoers_file="$SUDOERS_D/$UTILISATEUR"
    if [ -f "$sudoers_file" ]; then
        echo "L'utilisateur dispose déjà d'un fichier sudoers : $sudoers_file"
        backup_file "$sudoers_file"
    fi
    echo "$UTILISATEUR ALL=(ALL) NOPASSWD:ALL" > "$sudoers_file"
    chmod 440 "$sudoers_file"
    echo "Droits sudo accordés à $UTILISATEUR via $sudoers_file"
}

function allow_ssh() {
    if [ ! -f "$SSHD_CONFIG" ]; then
        echo "Fichier $SSHD_CONFIG introuvable."
        return
    fi

    backup_file "$SSHD_CONFIG"

    if grep -q "^AllowUsers" "$SSHD_CONFIG"; then
        if grep -q "^AllowUsers.*\b$UTILISATEUR\b" "$SSHD_CONFIG"; then
            echo "Utilisateur déjà autorisé en SSH."
        else
            echo "Ajout de $UTILISATEUR à la directive AllowUsers."
            sed -i "/^AllowUsers/ s/$/ $UTILISATEUR/" "$SSHD_CONFIG"
        fi
    else
        echo "AllowUsers $UTILISATEUR" >> "$SSHD_CONFIG"
        echo "Directive AllowUsers ajoutée."
    fi

    # Relancer SSHD
    if systemctl is-active sshd >/dev/null 2>&1; then
        echo "Redémarrage du service SSH..."
        systemctl restart sshd
    else
        echo "Service SSH non trouvé ou inactif."
    fi
}

function usage() {
    echo "Utilisation : $0 utilisateur [--no-create]"
    echo "  --no-create : n'essaye pas de créer l'utilisateur s'il n'existe pas."
}

# --- Exécution ---

if [ "$(id -u)" -ne 0 ]; then
    echo "Ce script doit être exécuté en root."
    exit 99
fi

if [ -z "$UTILISATEUR" ]; then
    usage
    exit 1
fi

if [ -n "$OPTION" ] && [ "$OPTION" != "--no-create" ]; then
    echo "Option inconnue : $OPTION"
    usage
    exit 1
fi

detect_os
create_user_if_needed
grant_sudo_via_sudoersd
allow_ssh

echo "Opération terminée. Backup dans : $BACKUP_DIR"
