#!/bin/bash

#=== CONFIGURATION ========================================================
INVENTORY_FILE="inventaire-ok.yml"     # Ansible inventory file
USERNAME="fr-726-ansible"          # User to test SSH access
SSH_KEY=""                         # Optional: path to SSH private key (e.g., ~/.ssh/id_rsa)
TIMEOUT=5                          # SSH timeout in seconds
#========================================================================

#=== FUNCTIONS ===========================================================
print_header() {
    echo "==================================================================="
    echo "🔍 SSH Access Check for User: $USERNAME"
    echo "📁 Using Inventory: $INVENTORY_FILE"
    echo "==================================================================="
}

parse_inventory() {
    # Get all non-empty, non-comment, non-group lines (support for INI format)
    grep -Ev '^\s*(#|$|\[)' "$INVENTORY_FILE" | awk '{print $1}' | sort -u
}

check_ssh_access() {
    local host="$1"
    local ssh_cmd="ssh -o ConnectTimeout=$TIMEOUT -o BatchMode=yes -o StrictHostKeyChecking=no"

    [[ -n "$SSH_KEY" ]] && ssh_cmd="$ssh_cmd -i $SSH_KEY"

    local full_cmd="$ssh_cmd $USERNAME@$host \"exit\""
    echo "👉 Testing: $full_cmd"

    eval $full_cmd >/dev/null 2>&1
    if [[ $? -eq 0 ]]; then
        echo "[✅ SUCCESS] $host"
        echo "$host" >> ssh_access_success.log
    else
        echo "[❌ FAILURE] $host"
        echo "$host" >> ssh_access_failed.log
    fi
    echo
}

#=== MAIN =================================================================
print_header
rm -f ssh_access_success.log ssh_access_failed.log

HOSTS=$(parse_inventory)
if [[ -z "$HOSTS" ]]; then
    echo "❗ No valid hosts found in inventory. Exiting."
    exit 1
fi

for host in $HOSTS; do
    check_ssh_access "$host"
done

#=== SUMMARY ==============================================================
echo "✅ SSH Access Check Completed."
echo "------------------------------"
echo "🟢 Successes: $(wc -l < ssh_access_success.log 2>/dev/null || echo 0)"
echo "🔴 Failures : $(wc -l < ssh_access_failed.log 2>/dev/null || echo 0)"
