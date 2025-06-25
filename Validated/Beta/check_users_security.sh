#!/bin/bash

echo "===== Linux Security Account Audit ====="
echo

# 1. Check per-user password minimum age, maximum age, and inactivity
echo "1. Checking per-user password policy (min age, max age, inactive)..."

while IFS=: read -r user _ uid gid _ home shell; do
    # Ignore system accounts (UID < 1000), but keep service accounts (UID >= 100, < 1000) for special handling
    if [ "$uid" -ge 1000 ] || { [ "$uid" -ge 100 ] && [ "$uid" -lt 1000 ]; }; then
        # Get aging info
        aging_info=$(chage -l "$user")
        minage=$(echo "$aging_info" | awk -F': ' '/Minimum/ {print $2}')
        maxage=$(echo "$aging_info" | awk -F': ' '/Maximum/ {print $2}')
        inactivedays=$(echo "$aging_info" | awk -F': ' '/Inactive/ {print $2}')
        if [ "$uid" -ge 1000 ]; then
            # Regular user
            echo "User: $user (UID $uid)"
            [[ "$minage" == "0" || "$minage" == "never" ]] && echo "  [!] Min password age NOT set" || echo "  [OK] Min password age: $minage"
            [[ "$maxage" == "never" ]] && echo "  [!] Max password age NOT set" || echo "  [OK] Max password age: $maxage"
            [[ "$inactivedays" == "never" || "$inactivedays" -gt 90 ]] && echo "  [!] Inactive > 90 days (value: $inactivedays)" || echo "  [OK] Inactive days: $inactivedays"
        else
            # Service account
            echo "Service Account: $user (UID $uid)"
            # 5. Service account must have no interactive shell
            if [[ "$shell" =~ (nologin|false) ]]; then
                echo "  [OK] No interactive shell ($shell)"
            else
                echo "  [!] Interactive shell detected: $shell"
            fi
        fi
    fi
done < /etc/passwd

echo
echo "2. Checking global password complexity settings (PAM)..."

# 4. Check password complexity (pam_pwquality or pam_cracklib)
PAM_FILE="/etc/security/pwquality.conf"
PAM_PWQUALITY=$(grep -E "pam_pwquality|pam_cracklib" /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null)
PWQUALITY_CONF=$(grep -vE '^\s*#' $PAM_FILE 2>/dev/null | grep -E "minlen|dcredit|ucredit|lcredit|ocredit")
if [ -n "$PAM_PWQUALITY" ]; then
    echo "[OK] PAM password quality module is configured:"
    echo "$PAM_PWQUALITY"
    if [ -n "$PWQUALITY_CONF" ]; then
        echo "[OK] pwquality.conf settings:"
        echo "$PWQUALITY_CONF"
    else
        echo "[!] No pwquality.conf or missing settings."
    fi
else
    echo "[!] No PAM password quality module (pwquality or cracklib) found in PAM."
fi

echo
echo "3. Checking default useradd password inactivity setting..."

USERADD_DEF=$(grep INACTIVE /etc/default/useradd)
if echo "$USERADD_DEF" | grep -q "INACTIVE=90"; then
    echo "[OK] /etc/default/useradd: $USERADD_DEF"
else
    echo "[!] /etc/default/useradd: $USERADD_DEF (should be INACTIVE=90)"
fi

echo
echo "===== Audit Complete ====="
