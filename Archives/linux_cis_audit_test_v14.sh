#!/bin/bash
# CIS Linux Audit Script - VERSION FIABLE (aucun eval, aucun bash -c)

LOG_FILE="cis_audit_report_$(date +%F).log"
echo "Starting CIS audit on $(date)" > "$LOG_FILE"
echo "=========================================" >> "$LOG_FILE"
echo "Auditing: 1.10 Ensure system-wide crypto policy is not legacy" >> "$LOG_FILE"
RESULT=$(grep -q '^LEGACY' /etc/crypto-policies/config && echo NOT COMPLIANT || echo OK)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.10 Ensure noexec option set on /var/tmp partition" >> "$LOG_FILE"
RESULT=$(mount | grep /var/tmp | grep -q noexec && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.1.1 Ensure mounting of cramfs filesystems is disabled" >> "$LOG_FILE"
RESULT=$(modprobe -n -v cramfs | grep -q 'install /bin/true' && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.11 Ensure separate partition exists for /var/log" >> "$LOG_FILE"
RESULT=$(findmnt /var/log >/dev/null && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.1.2 Ensure mounting of vFAT filesystems is limited" >> "$LOG_FILE"
RESULT=$(modprobe -n -v vfat | grep -q 'install /bin/true' && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.12 Ensure separate partition exists for /var/log/audit" >> "$LOG_FILE"
RESULT=$(findmnt /var/log/audit >/dev/null && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.1.3 Ensure mounting of squashfs filesystems is disabled" >> "$LOG_FILE"
RESULT=$(modprobe -n -v squashfs | grep -q 'install /bin/true' && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.13 Ensure separate partition exists for /home" >> "$LOG_FILE"
RESULT=$(findmnt /home >/dev/null && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.1.4 Ensure mounting of udf filesystems is disabled" >> "$LOG_FILE"
RESULT=$(modprobe -n -v udf | grep -q 'install /bin/true' && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.14 Ensure nodev option set on /home partition" >> "$LOG_FILE"
RESULT=$(mount | grep /home | grep -q nodev && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.15 Ensure nodev option set on /dev/shm partition" >> "$LOG_FILE"
RESULT=$(mount | grep /dev/shm | grep -q nodev && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.16 Ensure nosuid option set on /dev/shm partition" >> "$LOG_FILE"
RESULT=$(mount | grep /dev/shm | grep -q nosuid && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.17 Ensure noexec option set on /dev/shm partition" >> "$LOG_FILE"
RESULT=$(mount | grep /dev/shm | grep -q noexec && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.18 Ensure nodev option set on removable media partitions" >> "$LOG_FILE"
RESULT="OK"

# Détection des points de montage amovibles
REMOVABLE_MOUNTS=$(lsblk -o MOUNTPOINT,RM | awk '$2 == 1 && $1 ~ /^\// {print $1}')
if [ -z "$REMOVABLE_MOUNTS" ]; then
    REMOVABLE_MOUNTS=$(find /media /run/media -mindepth 1 -maxdepth 2 -type d 2>/dev/null)
fi

for mp in $REMOVABLE_MOUNTS; do
    if mount | grep -E "\s$mp\s" | grep -vq nodev; then
        echo "❌ $mp is mounted without nodev" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $mp has nodev option set" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.1.19 Ensure nosuid option set on removable media partitions" >> "$LOG_FILE"
RESULT="OK"

# Détection des points de montage amovibles
REMOVABLE_MOUNTS=$(lsblk -o MOUNTPOINT,RM | awk '$2 == 1 && $1 ~ /^\// {print $1}')
if [ -z "$REMOVABLE_MOUNTS" ]; then
    REMOVABLE_MOUNTS=$(find /media /run/media -mindepth 1 -maxdepth 2 -type d 2>/dev/null)
fi

for mp in $REMOVABLE_MOUNTS; do
    if mount | grep -E "\s$mp\s" | grep -vq nosuid; then
        echo "❌ $mp is mounted without nosuid" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $mp has nosuid option set" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.11 Ensure system-wide crypto policy is FUTURE or FIPS" >> "$LOG_FILE"
RESULT=$([ -f /etc/crypto-policies/config ] && grep -Eq 'FUTURE|FIPS' /etc/crypto-policies/config && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.20 Ensure noexec option set on removable media partitions" >> "$LOG_FILE"
RESULT="OK"

# Détection des points de montage amovibles
REMOVABLE_MOUNTS=$(lsblk -o MOUNTPOINT,RM | awk '$2 == 1 && $1 ~ /^\// {print $1}')
if [ -z "$REMOVABLE_MOUNTS" ]; then
    REMOVABLE_MOUNTS=$(find /media /run/media -mindepth 1 -maxdepth 2 -type d 2>/dev/null)
fi

for mp in $REMOVABLE_MOUNTS; do
    if mount | grep -E "\s$mp\s" | grep -vq noexec; then
        echo "❌ $mp is mounted without noexec" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $mp has noexec option set" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.1.21 Ensure sticky bit is set on all world-writable directories" >> "$LOG_FILE"
RESULT=$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -type d -perm -0002 ! -perm -1000 | grep -q . && echo NOT COMPLIANT || echo OK)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.22 Disable Automounting" >> "$LOG_FILE"
RESULT=$(systemctl is-enabled autofs 2>/dev/null | grep -q disabled && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.23 Disable USB Storage" >> "$LOG_FILE"
RESULT=$(lsmod | grep -q usb_storage && echo NOT COMPLIANT || echo OK)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.2 Ensure /tmp is configured" >> "$LOG_FILE"
RESULT="OK"

if ! findmnt /tmp >/dev/null; then
    echo "❌ /tmp is not on a separate partition" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

# Vérifie que /tmp est monté avec les bonnes options
TMP_MOUNT_OPTS=$(mount | grep "on /tmp " | grep -Eo '\(.*\)' | tr -d '()')

for opt in nodev noexec nosuid; do
    if ! echo "$TMP_MOUNT_OPTS" | grep -qw "$opt"; then
        echo "❌ /tmp is missing $opt option" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  /tmp has $opt option" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.1.6 Ensure separate partition exists for /var" >> "$LOG_FILE"
if findmnt /var >/dev/null 2>&1; then
    echo "✔️  /var is on a separate partition" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ /var is NOT on a separate partition" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.1.7 Ensure separate partition exists for /var/tmp" >> "$LOG_FILE"
if findmnt /var/tmp >/dev/null 2>&1; then
    echo "✔️  /var/tmp is on a separate partition" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ /var/tmp is NOT on a separate partition" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.2.1 Ensure Red Hat Subscription Manager connection is configured" >> "$LOG_FILE"
if command -v subscription-manager >/dev/null 2>&1; then
    if subscription-manager status 2>/dev/null | grep -q "Overall Status: Current"; then
        echo "✔️  System is properly registered with Red Hat Subscription Manager" >> "$LOG_FILE"
        echo "Result: OK" >> "$LOG_FILE"
    else
        echo "❌ System is NOT registered or not current with Red Hat" >> "$LOG_FILE"
        echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
    fi
else
    echo "❌ subscription-manager is not installed" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.2.2 Disable the rhnsd Daemon" >> "$LOG_FILE"
if systemctl list-unit-files | grep -q "^rhnsd.service"; then
    if systemctl is-enabled rhnsd 2>/dev/null | grep -q disabled; then
        echo "✔️  rhnsd service is disabled" >> "$LOG_FILE"
        echo "Result: OK" >> "$LOG_FILE"
    else
        echo "❌ rhnsd service is enabled" >> "$LOG_FILE"
        echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
    fi
else
    echo "✔️  rhnsd service not present" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.2.3 Ensure GPG keys are configured" >> "$LOG_FILE"
if rpm -q gpg-pubkey >/dev/null 2>&1; then
    echo "✔️  GPG public keys are installed" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ No GPG keys installed in RPM DB" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.2.4 Ensure gpgcheck is globally activated" >> "$LOG_FILE"
if grep -Prs '^gpgcheck\s*=\s*1' /etc/yum.conf /etc/yum.repos.d/ >/dev/null; then
    echo "✔️  gpgcheck is enabled in yum/dnf configuration" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ gpgcheck is not enabled globally" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.2.5 Ensure package manager repositories are configured" >> "$LOG_FILE"
MISSING_REPOS=$(dnf repolist 2>/dev/null | grep -E 'repolist: 0')
if [ -z "$MISSING_REPOS" ]; then
    echo "✔️  Package manager repositories are correctly configured" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ Some repositories may be misconfigured or unavailable" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.3.1 Ensure sudo is installed" >> "$LOG_FILE"
RESULT=$(command -v sudo >/dev/null && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.3.2 Ensure sudo commands use pty" >> "$LOG_FILE"
RESULT=$(grep -E 'Defaults\s+use_pty' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -q use_pty && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.3.3 Ensure sudo log file exists" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Recherche dans les fichiers sudoers les directives de journalisation
SUDO_LOG_FILE=$(grep -E 'Defaults\s+logfile\s*=' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | awk -F= '{print $2}' | tr -d ' ' | head -n 1)

if [ -n "$SUDO_LOG_FILE" ]; then
    if [ -f "$SUDO_LOG_FILE" ]; then
        echo "✔️  sudo log file exists at $SUDO_LOG_FILE" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ sudo log file path defined as $SUDO_LOG_FILE but file does not exist" >> "$LOG_FILE"
    fi
else
    echo "❌ No sudo log file defined in sudoers configuration" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.4.1 Ensure AIDE is installed" >> "$LOG_FILE"
RESULT=$(command -v aide >/dev/null && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.4.2 Ensure filesystem integrity is regularly checked" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Vérifie si aide est installé
if ! command -v aide >/dev/null 2>&1; then
    echo "❌ AIDE is not installed" >> "$LOG_FILE"
else
    # Vérifie si aide est planifié via systemd timer
    if systemctl list-timers aidecheck.timer 2>/dev/null | grep -q aidecheck; then
        echo "✔️  aidecheck.timer is active" >> "$LOG_FILE"
        RESULT="OK"
    # Sinon, vérifie si une tâche cron aide existe
    elif grep -qr aide /etc/cron* 2>/dev/null; then
        echo "✔️  AIDE check is scheduled via cron" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ No scheduled AIDE check found (neither cron nor systemd timer)" >> "$LOG_FILE"
    fi
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.5.1 Ensure permissions on bootloader config are configured" >> "$LOG_FILE"
RESULT="OK"

# Fichiers GRUB possibles (BIOS vs UEFI)
GRUB_FILES=(
  "/boot/grub2/grub.cfg"
  "/boot/efi/EFI/redhat/grub.cfg"
)

for file in "${GRUB_FILES[@]}"; do
    if [ -f "$file" ]; then
        OWNER=$(stat -c %u "$file")
        GROUP=$(stat -c %g "$file")
        PERM=$(stat -c %a "$file")

        if [ "$OWNER" -ne 0 ] || [ "$GROUP" -ne 0 ]; then
            echo "❌ $file is not owned by root:root" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi

        if [ "$PERM" -gt 600 ]; then
            echo "❌ $file permissions are $PERM, should be 600 or more restrictive" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi

        if [ "$OWNER" -eq 0 ] && [ "$GROUP" -eq 0 ] && [ "$PERM" -le 600 ]; then
            echo "✔️  $file is correctly owned and permissioned" >> "$LOG_FILE"
        fi
    else
        echo "⚠️  $file not found (possibly not used on this system)" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.5.2 Ensure bootloader password is set" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

GRUB_CFG="/boot/grub2/grub.cfg"
if [ -d /sys/firmware/efi ]; then
    GRUB_CFG="/boot/efi/EFI/redhat/grub.cfg"
fi

if [ -f "$GRUB_CFG" ]; then
    if grep -Eq "^\s*set superuser=" "$GRUB_CFG" && grep -Eq "^\s*password_pbkdf2" "$GRUB_CFG"; then
        echo "✔️  GRUB password is configured in $GRUB_CFG" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ GRUB password is NOT configured in $GRUB_CFG" >> "$LOG_FILE"
    fi
else
    echo "❌ GRUB config file not found at expected location: $GRUB_CFG" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.5.3 Ensure authentication required for single user mode" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Vérifie que sulogin est exigé en mode rescue/single-user
FILES_TO_CHECK=(
  "/usr/lib/systemd/system/rescue.service"
  "/usr/lib/systemd/system/emergency.service"
)

for f in "${FILES_TO_CHECK[@]}"; do
    if [ -f "$f" ]; then
        if grep -Eq 'ExecStart=-?/usr/lib/systemd/systemd-sulogin-shell' "$f"; then
            echo "✔️  $f requires sulogin for authentication" >> "$LOG_FILE"
        elif grep -Eq 'ExecStart=.*systemd.* --unit=rescue.target' "$f"; then
            echo "❌ $f uses systemd unit without sulogin (fallback to shell)" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        elif grep -Eq 'ExecStart=-?/bin/sh' "$f"; then
            echo "❌ $f allows shell access without authentication" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        else
            echo "✔️  $f appears to be configured properly" >> "$LOG_FILE"
        fi
    else
        echo "⚠️  $f not found, skipping" >> "$LOG_FILE"
    fi
done

# Confirme que sulogin.conf requiert auth
if [ -f /etc/sysconfig/init ]; then
    if grep -q "^SINGLE=/sbin/sulogin" /etc/sysconfig/init; then
        echo "✔️  /etc/sysconfig/init forces sulogin in single-user mode" >> "$LOG_FILE"
    else
        echo "❌ /etc/sysconfig/init does not enforce sulogin for single-user mode" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.6.1 Ensure core dumps are restricted" >> "$LOG_FILE"
RESULT="OK"

# Vérifie sysctl fs.suid_dumpable
DUMPABLE=$(sysctl -n fs.suid_dumpable 2>/dev/null)
if [ "$DUMPABLE" != "0" ]; then
    echo "❌ fs.suid_dumpable is set to $DUMPABLE (should be 0)" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  fs.suid_dumpable is set to 0" >> "$LOG_FILE"
fi

# Vérifie limites dans /etc/security/limits.conf ou .d/
LIMITS_CORE=$(grep -R "^\*\s\+hard\s\+core\s\+0" /etc/security/limits.conf /etc/security/limits.d/ 2>/dev/null | grep -v '^#')
if [ -z "$LIMITS_CORE" ]; then
    echo "❌ No 'hard core 0' found in limits.conf or limits.d/*" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  Core dump limit is set to 0 in PAM limits" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.6.2 Ensure address space layout randomization (ASLR) is enabled" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

ASLR=$(sysctl -n kernel.randomize_va_space 2>/dev/null)
if [ "$ASLR" = "2" ]; then
    echo "✔️  ASLR is fully enabled (kernel.randomize_va_space = 2)" >> "$LOG_FILE"
    RESULT="OK"
elif [ "$ASLR" = "1" ]; then
    echo "⚠️  ASLR is partially enabled (kernel.randomize_va_space = 1)" >> "$LOG_FILE"
else
    echo "❌ ASLR is disabled (kernel.randomize_va_space = $ASLR)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.7.1.1 Ensure SELinux is installed" >> "$LOG_FILE"
if rpm -q libselinux >/dev/null 2>&1; then
    echo "✔️  SELinux package is installed (libselinux)" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ SELinux is not installed (libselinux package missing)" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.7.1.2 Ensure SELinux is not disabled in bootloader configuration" >> "$LOG_FILE"
GRUB_CFG="/boot/grub2/grub.cfg"
[ -d /sys/firmware/efi ] && GRUB_CFG="/boot/efi/EFI/redhat/grub.cfg"

if grep -E "selinux=0|enforcing=0" "$GRUB_CFG" >/dev/null 2>&1; then
    echo "❌ SELinux is disabled or set to permissive in $GRUB_CFG" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
else
    echo "✔️  SELinux is not disabled in GRUB config" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.7.1.3 Ensure SELinux policy is configured" >> "$LOG_FILE"
if grep -E '^SELINUXTYPE=' /etc/selinux/config | grep -qE 'targeted|mls'; then
    echo "✔️  SELinux policy is set (targeted or mls)" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ SELinux policy is not properly set in /etc/selinux/config" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.7.1.4 Ensure the SELinux state is enforcing" >> "$LOG_FILE"
STATE=$(getenforce 2>/dev/null)
CONFIG_STATE=$(grep -E '^SELINUX=' /etc/selinux/config | cut -d= -f2)

if [ "$STATE" = "Enforcing" ] && [ "$CONFIG_STATE" = "enforcing" ]; then
    echo "✔️  SELinux is in enforcing mode (runtime and config)" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ SELinux is not enforcing (runtime: $STATE / config: $CONFIG_STATE)" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.7.1.5 Ensure no unconfined services exist" >> "$LOG_FILE"
if command -v ps >/dev/null && command -v awk >/dev/null; then
    UNCONFINED=$(ps -eZ | awk '$1 ~ /^unconfined_u/ {print $0}')
    if [ -z "$UNCONFINED" ]; then
        echo "✔️  No unconfined services running" >> "$LOG_FILE"
        echo "Result: OK" >> "$LOG_FILE"
    else
        echo "❌ Unconfined services found:" >> "$LOG_FILE"
        echo "$UNCONFINED" >> "$LOG_FILE"
        echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
    fi
else
    echo "⚠️  Could not check unconfined services" >> "$LOG_FILE"
    echo "Result: MANUAL CHECK REQUIRED" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.7.1.6 Ensure SETroubleshoot is not installed" >> "$LOG_FILE"
if rpm -q setroubleshoot >/dev/null 2>&1; then
    echo "❌ setroubleshoot package is installed" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
else
    echo "✔️  setroubleshoot is not installed" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.7.1.7 Ensure the MCS Translation Service (mcstrans) is not installed" >> "$LOG_FILE"
if rpm -q mcstrans >/dev/null 2>&1; then
    echo "❌ mcstrans package is installed" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
else
    echo "✔️  mcstrans is not installed" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.8.1.1 Ensure message of the day is configured properly" >> "$LOG_FILE"
if grep -Eq "(\\v|\\r|\\m|\\s)" /etc/motd; then
    echo "❌ /etc/motd contains system information variables (\\v, \\r, \\m, \\s)" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
else
    echo "✔️  /etc/motd is properly configured (no system info disclosure)" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.8.1.2 Ensure local login warning banner is configured properly" >> "$LOG_FILE"
if grep -Eq "(\\v|\\r|\\m|\\s)" /etc/issue; then
    echo "❌ /etc/issue contains system information variables (\\v, \\r, \\m, \\s)" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
else
    echo "✔️  /etc/issue is properly configured (no system info disclosure)" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.8.1.3 Ensure remote login warning banner is configured properly" >> "$LOG_FILE"
if grep -Eq "(\\v|\\r|\\m|\\s)" /etc/issue.net; then
    echo "❌ /etc/issue.net contains system information variables (\\v, \\r, \\m, \\s)" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
else
    echo "✔️  /etc/issue.net is properly configured (no system info disclosure)" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.8.1.4 Ensure permissions on /etc/motd are configured" >> "$LOG_FILE"
PERM=$(stat -c %a /etc/motd)
OWNER=$(stat -c %u /etc/motd)
GROUP=$(stat -c %g /etc/motd)

if [ "$PERM" -le 644 ] && [ "$OWNER" -eq 0 ] && [ "$GROUP" -eq 0 ]; then
    echo "✔️  /etc/motd permissions are secure ($PERM, owned by root:root)" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ /etc/motd permissions are too open or wrong owner ($PERM, uid=$OWNER, gid=$GROUP)" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.8.1.5 Ensure permissions on /etc/issue are configured" >> "$LOG_FILE"
PERM=$(stat -c %a /etc/issue)
OWNER=$(stat -c %u /etc/issue)
GROUP=$(stat -c %g /etc/issue)

if [ "$PERM" -le 644 ] && [ "$OWNER" -eq 0 ] && [ "$GROUP" -eq 0 ]; then
    echo "✔️  /etc/issue permissions are secure ($PERM, owned by root:root)" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ /etc/issue permissions are too open or wrong owner ($PERM, uid=$OWNER, gid=$GROUP)" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.8.1.6 Ensure permissions on /etc/issue.net are configured" >> "$LOG_FILE"
PERM=$(stat -c %a /etc/issue.net)
OWNER=$(stat -c %u /etc/issue.net)
GROUP=$(stat -c %g /etc/issue.net)

if [ "$PERM" -le 644 ] && [ "$OWNER" -eq 0 ] && [ "$GROUP" -eq 0 ]; then
    echo "✔️  /etc/issue.net permissions are secure ($PERM, owned by root:root)" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
else
    echo "❌ /etc/issue.net permissions are too open or wrong owner ($PERM, uid=$OWNER, gid=$GROUP)" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.8.2 Ensure GDM login banner is configured" >> "$LOG_FILE"
RESULT="OK"

if rpm -q gdm >/dev/null 2>&1; then
    CONFIG_FILE="/etc/dconf/db/gdm.d/01-banner-message"
    if [ -f "$CONFIG_FILE" ]; then
        if grep -q "^banner-message-enable=true" "$CONFIG_FILE"; then
            echo "✔️  GDM banner-message is enabled in $CONFIG_FILE" >> "$LOG_FILE"
        else
            echo "❌ GDM banner-message-enable not set to true" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi

        if grep -q "^banner-message-text=" "$CONFIG_FILE"; then
            echo "✔️  GDM banner-message-text is configured" >> "$LOG_FILE"
        else
            echo "❌ GDM banner-message-text is missing" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi
    else
        echo "❌ GDM config file not found: $CONFIG_FILE" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "✔️  GDM is not installed — not applicable" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 1.9 Ensure updates, patches, and additional security software are installed" >> "$LOG_FILE"
RESULT="OK"

# Vérifie si les mises à jour de sécurité sont disponibles
if command -v dnf >/dev/null 2>&1; then
    UPDATES=$(dnf check-update --security 2>/dev/null | grep -E 'Important|Moderate|Critical')
    if [ -n "$UPDATES" ]; then
        echo "❌ Security updates are available but not yet applied:" >> "$LOG_FILE"
        echo "$UPDATES" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  No pending security updates" >> "$LOG_FILE"
    fi
elif command -v yum >/dev/null 2>&1; then
    UPDATES=$(yum updateinfo list security all 2>/dev/null | grep -E 'Important|Moderate|Critical')
    if [ -n "$UPDATES" ]; then
        echo "❌ Security updates are available but not yet applied:" >> "$LOG_FILE"
        echo "$UPDATES" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  No pending security updates" >> "$LOG_FILE"
    fi
else
    echo "⚠️  Neither dnf nor yum found. Cannot check for updates." >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.1.1 Ensure xinetd is not installed" >> "$LOG_FILE"
if rpm -q xinetd >/dev/null 2>&1; then
    echo "❌ xinetd is installed" >> "$LOG_FILE"
    echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
else
    echo "✔️  xinetd is not installed" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 2.2.10 Ensure FTP Server is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q vsftpd >/dev/null 2>&1; then
    if systemctl is-enabled vsftpd 2>/dev/null | grep -q enabled; then
        echo "❌ vsftpd is installed and enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  vsftpd is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  vsftpd is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 2.2.1.1 Ensure time synchronization is in use" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if rpm -q chrony >/dev/null 2>&1; then
    if systemctl is-enabled chronyd 2>/dev/null | grep -q enabled; then
        echo "✔️  chronyd is installed and enabled" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ chronyd is installed but not enabled" >> "$LOG_FILE"
    fi
elif systemctl list-unit-files | grep -q systemd-timesyncd.service; then
    if systemctl is-enabled systemd-timesyncd 2>/dev/null | grep -q enabled; then
        echo "✔️  systemd-timesyncd is enabled" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ systemd-timesyncd is present but not enabled" >> "$LOG_FILE"
    fi
else
    echo "❌ No time synchronization service found (chronyd or systemd-timesyncd)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 2.2.11 Ensure DNS Server is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q bind >/dev/null 2>&1; then
    if systemctl is-enabled named 2>/dev/null | grep -q enabled; then
        echo "❌ named (bind) is installed and enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  named (bind) is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  bind is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.12 Ensure NFS is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q nfs-utils >/dev/null 2>&1; then
    if systemctl is-enabled nfs-server 2>/dev/null | grep -q enabled; then
        echo "❌ nfs-server is installed and enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  nfs-server is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  NFS is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.13 Ensure RPC is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q rpcbind >/dev/null 2>&1; then
    if systemctl is-enabled rpcbind 2>/dev/null | grep -q enabled; then
        echo "❌ rpcbind is installed and enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  rpcbind is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  rpcbind is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.14 Ensure LDAP server is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q openldap-servers >/dev/null 2>&1; then
    if systemctl is-enabled slapd 2>/dev/null | grep -q enabled; then
        echo "❌ slapd (LDAP server) is installed and enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  slapd is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  LDAP server is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.15 Ensure DHCP Server is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q dhcp-server >/dev/null 2>&1 || rpm -q dhcp >/dev/null 2>&1; then
    if systemctl is-enabled dhcpd 2>/dev/null | grep -q enabled; then
        echo "❌ dhcpd is installed and enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  dhcpd is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  DHCP server is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.16 Ensure CUPS is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q cups >/dev/null 2>&1; then
    if systemctl is-enabled cups 2>/dev/null | grep -q enabled; then
        echo "❌ cups is installed and enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  cups is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  cups is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.17 Ensure NIS Server is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q ypserv >/dev/null 2>&1; then
    if systemctl is-enabled ypserv 2>/dev/null | grep -q enabled; then
        echo "❌ ypserv is installed and enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  ypserv is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  ypserv is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.18 Ensure mail transfer agent is configured for local-only mode" >> "$LOG_FILE"
if rpm -q postfix >/dev/null 2>&1; then
    if ss -tuln | grep -q ':25' && ! ss -tuln | grep -q '127.0.0.1:25'; then
        echo "❌ Postfix is listening on external interface" >> "$LOG_FILE"
        echo "Result: NOT COMPLIANT" >> "$LOG_FILE"
    else
        echo "✔️  Postfix is restricted to localhost or not running" >> "$LOG_FILE"
        echo "Result: OK" >> "$LOG_FILE"
    fi
else
    echo "✔️  Postfix not installed" >> "$LOG_FILE"
    echo "Result: OK" >> "$LOG_FILE"
fi
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 2.2.2 Ensure X Window System is not installed" >> "$LOG_FILE"
RESULT="OK"

if rpm -qa | grep -E '^xorg-x11-server-' >/dev/null 2>&1; then
    echo "❌ X Window System packages are installed (xorg-x11-server-*)" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  X Window System is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.3 Ensure rsync service is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q rsync >/dev/null 2>&1; then
    if systemctl is-enabled rsyncd 2>/dev/null | grep -q enabled; then
        echo "❌ rsyncd service is enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  rsync is installed but rsyncd is disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  rsync is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.4 Ensure Avahi Server is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q avahi >/dev/null 2>&1; then
    if systemctl is-enabled avahi-daemon 2>/dev/null | grep -q enabled; then
        echo "❌ avahi-daemon is enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  avahi-daemon is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  avahi is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.5 Ensure SNMP Server is not enabled (if not required)" >> "$LOG_FILE"
RESULT="OK"

if rpm -q net-snmp >/dev/null 2>&1; then
    if systemctl is-enabled snmpd 2>/dev/null | grep -q enabled; then
        echo "❌ snmpd is enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  snmpd is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  SNMP server not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.6 Ensure HTTP Proxy Server is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q squid >/dev/null 2>&1; then
    if systemctl is-enabled squid 2>/dev/null | grep -q enabled; then
        echo "❌ squid proxy service is enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  squid is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  squid is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.7 Ensure Samba is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q samba >/dev/null 2>&1; then
    if systemctl is-enabled smb 2>/dev/null | grep -q enabled; then
        echo "❌ Samba (smb) service is enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  Samba is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  Samba is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.8 Ensure IMAP and POP3 server is not enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q dovecot >/dev/null 2>&1; then
    if systemctl is-enabled dovecot 2>/dev/null | grep -q enabled; then
        echo "❌ dovecot is enabled (IMAP/POP3)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  dovecot is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  IMAP/POP3 server not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.2.9 Ensure HTTP server is not enabled (if not web server)" >> "$LOG_FILE"
RESULT="OK"

if rpm -q httpd >/dev/null 2>&1; then
    if systemctl is-enabled httpd 2>/dev/null | grep -q enabled; then
        echo "❌ httpd is enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  httpd is installed but disabled" >> "$LOG_FILE"
    fi
else
    echo "✔️  httpd is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.3.1 Ensure NIS client is not installed" >> "$LOG_FILE"
RESULT="OK"

if rpm -q ypbind >/dev/null 2>&1; then
    echo "❌ ypbind (NIS client) is installed" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  ypbind (NIS client) is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.3.2 Ensure rsh client is not installed" >> "$LOG_FILE"
RESULT="OK"

if rpm -q rsh >/dev/null 2>&1; then
    echo "❌ rsh client is installed" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  rsh client is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 2.3.3 Ensure talk client is not installed" >> "$LOG_FILE"
RESULT="OK"

if rpm -q talk >/dev/null 2>&1; then
    echo "❌ talk client is installed" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  talk client is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.1.1 Ensure IP forwarding is disabled" >> "$LOG_FILE"
RESULT="OK"

if [ "$(sysctl -n net.ipv4.ip_forward 2>/dev/null)" = "0" ]; then
    echo "✔️  IPv4 forwarding is disabled" >> "$LOG_FILE"
else
    echo "❌ net.ipv4.ip_forward is enabled" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

if [ "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null)" = "0" ]; then
    echo "✔️  IPv6 forwarding is disabled" >> "$LOG_FILE"
else
    echo "❌ net.ipv6.conf.all.forwarding is enabled" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.1.2 Ensure packet redirect sending is disabled" >> "$LOG_FILE"
RESULT="OK"
PARAMS=(
  "net.ipv4.conf.all.send_redirects"
  "net.ipv4.conf.default.send_redirects"
)

for param in "${PARAMS[@]}"; do
    if [ "$(sysctl -n $param 2>/dev/null)" != "0" ]; then
        echo "❌ $param is not set to 0" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $param is set to 0" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.2.1 Ensure wireless interfaces are disabled (if not used)" >> "$LOG_FILE"
RESULT="OK"
WIFI_IFS=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')

if [ -z "$WIFI_IFS" ]; then
    echo "✔️  No wireless interfaces detected" >> "$LOG_FILE"
else
    for iface in $WIFI_IFS; do
        if ip link show "$iface" | grep -q "state UP"; then
            echo "❌ Wireless interface $iface is UP" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        else
            echo "✔️  Wireless interface $iface is DOWN" >> "$LOG_FILE"
        fi
    done
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.2.2 Ensure IPv6 router advertisements are not accepted" >> "$LOG_FILE"
RESULT="OK"

PARAMS=(
  "net.ipv6.conf.all.accept_ra"
  "net.ipv6.conf.default.accept_ra"
)

for param in "${PARAMS[@]}"; do
    val=$(sysctl -n "$param" 2>/dev/null)
    if [ "$val" != "0" ]; then
        echo "❌ $param is set to $val (should be 0)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $param is set to 0" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.2.3 Ensure IPv6 redirects are not accepted" >> "$LOG_FILE"
RESULT="OK"

PARAMS=(
  "net.ipv6.conf.all.accept_redirects"
  "net.ipv6.conf.default.accept_redirects"
)

for param in "${PARAMS[@]}"; do
    val=$(sysctl -n "$param" 2>/dev/null)
    if [ "$val" != "0" ]; then
        echo "❌ $param is set to $val (should be 0)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $param is set to 0" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.2.4 Ensure suspicious packets are logged" >> "$LOG_FILE"
RESULT="OK"

if [ "$(sysctl -n net.ipv4.conf.all.log_martians 2>/dev/null)" = "1" ] &&
   [ "$(sysctl -n net.ipv4.conf.default.log_martians 2>/dev/null)" = "1" ]; then
    echo "✔️  log_martians is enabled for all and default" >> "$LOG_FILE"
else
    echo "❌ log_martians is not fully enabled" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.2.5 Ensure broadcast ICMP requests are ignored" >> "$LOG_FILE"
RESULT="OK"

if [ "$(sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null)" = "1" ]; then
    echo "✔️  Broadcast ICMP requests are ignored" >> "$LOG_FILE"
else
    echo "❌ net.ipv4.icmp_echo_ignore_broadcasts is not set to 1" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.2.6 Ensure bogus ICMP responses are ignored" >> "$LOG_FILE"
RESULT="OK"

if [ "$(sysctl -n net.ipv4.icmp_ignore_bogus_error_responses 2>/dev/null)" = "1" ]; then
    echo "✔️  Bogus ICMP error responses are ignored" >> "$LOG_FILE"
else
    echo "❌ net.ipv4.icmp_ignore_bogus_error_responses is not set to 1" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.2.7 Ensure Reverse Path Filtering is enabled" >> "$LOG_FILE"
RESULT="OK"

PARAMS=(
  "net.ipv4.conf.all.rp_filter"
  "net.ipv4.conf.default.rp_filter"
)

for param in "${PARAMS[@]}"; do
    val=$(sysctl -n "$param" 2>/dev/null)
    if [ "$val" != "1" ]; then
        echo "❌ $param is set to $val (should be 1)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $param is set to 1" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.2.8 Ensure TCP SYN Cookies is enabled" >> "$LOG_FILE"
RESULT="OK"

if [ "$(sysctl -n net.ipv4.tcp_syncookies 2>/dev/null)" = "1" ]; then
    echo "✔️  TCP SYN cookies are enabled" >> "$LOG_FILE"
else
    echo "❌ net.ipv4.tcp_syncookies is not set to 1" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.2.9 Ensure IPv6 is disabled (if required)" >> "$LOG_FILE"
RESULT="OK"

IPV6_DISABLED=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
if [ "$IPV6_DISABLED" = "1" ]; then
    echo "✔️  IPv6 is disabled (net.ipv6.conf.all.disable_ipv6 = 1)" >> "$LOG_FILE"
else
    echo "⚠️  IPv6 is enabled (this may be acceptable if IPv6 is in use)" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.3.1 Ensure DCCP is disabled" >> "$LOG_FILE"
RESULT="OK"

# Vérifie si le module est blacklisté
BLACKLISTED=$(grep -E '^(blacklist\s+dccp|install\s+dccp\s+/bin/false)' /etc/modprobe.d/* 2>/dev/null)

if lsmod | grep -q '^dccp'; then
    echo "❌ DCCP module is currently loaded" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  DCCP module is not loaded" >> "$LOG_FILE"
fi

if [ -z "$BLACKLISTED" ]; then
    echo "❌ DCCP module is not blacklisted in /etc/modprobe.d" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  DCCP module is blacklisted in modprobe config" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.3.2 Ensure SCTP is disabled" >> "$LOG_FILE"
RESULT="OK"

BLACKLISTED=$(grep -E '^(blacklist\s+sctp|install\s+sctp\s+/bin/false)' /etc/modprobe.d/* 2>/dev/null)

if lsmod | grep -q '^sctp'; then
    echo "❌ SCTP module is currently loaded" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  SCTP module is not loaded" >> "$LOG_FILE"
fi

if [ -z "$BLACKLISTED" ]; then
    echo "❌ SCTP module is not blacklisted in /etc/modprobe.d" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  SCTP module is blacklisted in modprobe config" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.3.3 Ensure RDS is disabled" >> "$LOG_FILE"
RESULT="OK"

BLACKLISTED=$(grep -E '^(blacklist\s+rds|install\s+rds\s+/bin/false)' /etc/modprobe.d/* 2>/dev/null)

if lsmod | grep -q '^rds'; then
    echo "❌ RDS module is currently loaded" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  RDS module is not loaded" >> "$LOG_FILE"
fi

if [ -z "$BLACKLISTED" ]; then
    echo "❌ RDS module is not blacklisted in /etc/modprobe.d" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  RDS module is blacklisted in modprobe config" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.3.4 Ensure TIPC is disabled" >> "$LOG_FILE"
RESULT="OK"

BLACKLISTED=$(grep -E '^(blacklist\s+tipc|install\s+tipc\s+/bin/false)' /etc/modprobe.d/* 2>/dev/null)

if lsmod | grep -q '^tipc'; then
    echo "❌ TIPC module is currently loaded" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  TIPC module is not loaded" >> "$LOG_FILE"
fi

if [ -z "$BLACKLISTED" ]; then
    echo "❌ TIPC module is not blacklisted in /etc/modprobe.d" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  TIPC module is blacklisted in modprobe config" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"




echo "Auditing: 3.4.1.1 Ensure a Firewall package is installed" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if rpm -q nftables >/dev/null 2>&1 || rpm -q firewalld >/dev/null 2>&1 || rpm -q iptables >/dev/null 2>&1; then
    echo "✔️  At least one firewall package is installed (nftables, firewalld, or iptables)" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ No firewall package installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.2.1 Ensure nftables is installed" >> "$LOG_FILE"
RESULT="OK"

if rpm -q nftables >/dev/null 2>&1; then
    echo "✔️  nftables is installed" >> "$LOG_FILE"
else
    echo "❌ nftables is not installed" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.2.2 Ensure iptables is not enabled" >> "$LOG_FILE"
RESULT="OK"

if systemctl is-enabled iptables 2>/dev/null | grep -q enabled; then
    echo "❌ iptables service is enabled" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  iptables service is disabled" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.2.3 Ensure nftables is enabled" >> "$LOG_FILE"
RESULT="OK"

if systemctl is-enabled nftables 2>/dev/null | grep -q enabled; then
    echo "✔️  nftables service is enabled" >> "$LOG_FILE"
else
    echo "❌ nftables service is not enabled" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.2.4 Ensure default zone is set in firewalld" >> "$LOG_FILE"
RESULT="OK"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)
    if [ -n "$DEFAULT_ZONE" ]; then
        echo "✔️  firewalld default zone is set to: $DEFAULT_ZONE" >> "$LOG_FILE"
    else
        echo "❌ firewalld default zone is not set" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "⚠️  firewalld not running — test skipped" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.2.5 Ensure firewalld interfaces are assigned to zones" >> "$LOG_FILE"
RESULT="OK"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    UNASSIGNED_IFS=()
    for IFACE in $(nmcli device status | awk '$2 == "connected" {print $1}'); do
        ZONE=$(firewall-cmd --get-zone-of-interface="$IFACE" 2>/dev/null)
        if [ -z "$ZONE" ]; then
            UNASSIGNED_IFS+=("$IFACE")
        else
            echo "✔️  Interface $IFACE is assigned to zone: $ZONE" >> "$LOG_FILE"
        fi
    done

    if [ "${#UNASSIGNED_IFS[@]}" -gt 0 ]; then
        echo "❌ Interfaces not assigned to any firewalld zone: ${UNASSIGNED_IFS[*]}" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "⚠️  firewalld not running — cannot check zone assignment" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.2.6 Ensure unnecessary services and ports are not accepted" >> "$LOG_FILE"
RESULT="OK"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)

    if [ -n "$DEFAULT_ZONE" ]; then
        SERVICES=$(firewall-cmd --zone="$DEFAULT_ZONE" --list-services)
        PORTS=$(firewall-cmd --zone="$DEFAULT_ZONE" --list-ports)

        if [ -n "$SERVICES" ] || [ -n "$PORTS" ]; then
            echo "⚠️  Default firewalld zone '$DEFAULT_ZONE' allows:" >> "$LOG_FILE"
            [ -n "$SERVICES" ] && echo "  Services: $SERVICES" >> "$LOG_FILE"
            [ -n "$PORTS" ] && echo "  Ports: $PORTS" >> "$LOG_FILE"
            echo "❌ Review required to determine if services/ports are justified" >> "$LOG_FILE"
            RESULT="MANUAL CHECK REQUIRED"
        else
            echo "✔️  Default zone '$DEFAULT_ZONE' does not allow unnecessary services or ports" >> "$LOG_FILE"
        fi
    else
        echo "❌ Unable to determine default firewalld zone" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "⚠️  firewalld not running — skipping port/service evaluation" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.3.1 Ensure iptables are flushed" >> "$LOG_FILE"
RESULT="OK"

if rpm -q iptables >/dev/null 2>&1 && systemctl is-enabled iptables 2>/dev/null | grep -q enabled; then
    RULES=$(iptables -S | grep -vE '^-P (INPUT|FORWARD|OUTPUT) (ACCEPT|DROP)$' | grep -v '^#')

    if [ -n "$RULES" ]; then
        echo "❌ iptables is enabled and contains active rules:" >> "$LOG_FILE"
        echo "$RULES" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  iptables is enabled but ruleset is flushed (default policies only)" >> "$LOG_FILE"
    fi
else
    echo "✔️  iptables is not enabled — no rules to flush" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"











########################################################################
########################################################################
##############   MGH / Mon Point d'avancement   ########################
########################################################################
########################################################################





echo "Auditing: 3.4.3.2 Ensure a table exists" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.3.3 Ensure base chains exist" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.3.4 Ensure loopback traffic is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.3.5 Ensure outbound and established connections are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.3.6 Ensure default deny firewall policy" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.3.7 Ensure nftables service is enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.3.8 Ensure nftables rules are permanent" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.4.1.1 Ensure default deny firewall policy" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.4.1.2 Ensure loopback traffic is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.4.1.3 Ensure outbound and established connections are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.4.1.4 Ensure firewall rules exist for all open ports" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.4.2.1 Ensure IPv6 default deny firewall policy" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.4.2.2 Ensure IPv6 loopback traffic is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.4.2.3 Ensure IPv6 outbound and established connections are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.4.2.4 Ensure IPv6 firewall rules exist for all open ports" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.5 Ensure wireless interfaces are disabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.6 Disable IPv6" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.1.1 Ensure auditd is installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.11 Ensure events that modify user/group information are collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.1.2 Ensure auditd service is enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.12 Ensure successful file system mounts are collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.13 Ensure use of privileged commands is collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.1.4 Ensure audit_backlog_limit is sufficient" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.14 Ensure file deletion events by users are collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.15 Ensure kernel module loading and unloading is collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.16 Ensure system administrator actions (sudolog) are collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.17 Ensure the audit configuration is immutable" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.2.1 Ensure audit log storage size is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.2.2 Ensure audit logs are not automatically deleted" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.2.3 Ensure system is disabled when audit logs are full" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.3 Ensure changes to system administration scope (sudoers) is collected" >> "$LOG_FILE"
RESULT=$(systemctl is-enabled auditd 2>/dev/null | grep -q enabled && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.4 Ensure login and logout events are collected" >> "$LOG_FILE"
RESULT=$(systemctl is-active auditd 2>/dev/null | grep -q active && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.5 Ensure session initiation information is collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.6 Ensure events that modify date and time information are collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.7 Ensure events that modify the system's Mandatory Access Controls are collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.8 Ensure events that modify the system's network environment are collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.1.9 Ensure discretionary access control permission modification events are collected" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.1.1 Ensure rsyslog is installed" >> "$LOG_FILE"
RESULT=$(command -v rsyslogd >/dev/null && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.1.2 Ensure rsyslog Service is enabled" >> "$LOG_FILE"
RESULT=$(systemctl is-enabled rsyslog 2>/dev/null | grep -q enabled && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.1.3 Ensure rsyslog default file permissions configured" >> "$LOG_FILE"
RESULT=$(systemctl is-active rsyslog 2>/dev/null | grep -q active && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.1.4 Ensure logging is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts." >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.2.1 Ensure journald is configured to send logs to rsyslog" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.2.2 Ensure journald is configured to compress large log files" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.3 Ensure permissions on all logfiles are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.3 Ensure logrotate is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.1.1 Ensure cron daemon is enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.1.2 Ensure permissions on /etc/crontab are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.1.3 Ensure permissions on /etc/cron.hourly are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.1.4 Ensure permissions on /etc/cron.daily are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.1.5 Ensure permissions on /etc/cron.weekly are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.1.6 Ensure permissions on /etc/cron.monthly are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.1.7 Ensure permissions on /etc/cron.d are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.1.8 Ensure at/cron is restricted to authorized users" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.10 Ensure SSH root login is disabled" >> "$LOG_FILE"
RESULT=$(grep -Ei '^PermitRootLogin\s+no' /etc/ssh/sshd_config && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.11 Ensure SSH PermitEmptyPasswords is disabled" >> "$LOG_FILE"
RESULT=$(grep -Ei '^PermitEmptyPasswords\s+no' /etc/ssh/sshd_config && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.12 Ensure SSH PermitUserEnvironment is disabled" >> "$LOG_FILE"
RESULT=$(grep -Ei '^PermitUserEnvironment\s+no' /etc/ssh/sshd_config && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.13 Ensure SSH Idle Timeout Interval is configured" >> "$LOG_FILE"
RESULT=$(grep -Ei '^IgnoreRhosts\s+yes' /etc/ssh/sshd_config && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.14 Ensure SSH LoginGraceTime is set to one minute or less" >> "$LOG_FILE"
RESULT=$(grep -Ei '^HostbasedAuthentication\s+no' /etc/ssh/sshd_config && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.15 Ensure SSH warning banner is configured" >> "$LOG_FILE"
RESULT=$(grep -Ei '^ClientAliveInterval\s+[0-9]+' /etc/ssh/sshd_config | awk '{if ($2 <= 300) print "OK"; else print "NOT COMPLIANT"}' || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.16 Ensure SSH PAM is enabled" >> "$LOG_FILE"
RESULT=$(grep -Ei '^ClientAliveCountMax\s+[0-9]+' /etc/ssh/sshd_config | awk '{if ($2 <= 2) print "OK"; else print "NOT COMPLIANT"}' || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.17 Ensure SSH AllowTcpForwarding is disabled" >> "$LOG_FILE"
RESULT=$(grep -Ei '^LoginGraceTime\s+[0-9]+[sm]?' /etc/ssh/sshd_config | awk -F ' ' '{gsub("s", "", $2); if ($2 <= 60) print "OK"; else print "NOT COMPLIANT"}' || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.18 Ensure SSH MaxStartups is configured" >> "$LOG_FILE"
RESULT=$(grep -Ei '^Banner\s+/etc/issue.net' /etc/ssh/sshd_config && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.19 Ensure SSH MaxSessions is set to 4 or less" >> "$LOG_FILE"
RESULT=$(grep -Ei '^AllowTcpForwarding\s+no' /etc/ssh/sshd_config && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.20 Ensure system-wide crypto policy is not over-ridden" >> "$LOG_FILE"
RESULT=$(grep -Ei '^MaxStartups\s+[0-9]+(:[0-9]+){0,2}' /etc/ssh/sshd_config && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.2 Ensure SSH access is limited" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.3 Ensure permissions on SSH private host key files are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.4 Ensure permissions on SSH public host key files are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.5 Ensure SSH LogLevel is appropriate" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.6 Ensure SSH X11 forwarding is disabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.8 Ensure SSH IgnoreRhosts is enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.9 Ensure SSH HostbasedAuthentication is disabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.3.1 Create custom authselect profile" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.3.2 Select authselect profile" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.3.3 Ensure authselect includes with-faillock" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.4.1 Ensure password creation requirements are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.4.2 Ensure lockout for failed password attempts is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.4.3 Ensure password reuse is limited" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.4.4 Ensure password hashing algorithm is SHA-512" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.5.1.1 Ensure password expiration is 365 days or less" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.5.1.2 Ensure minimum days between password changes is 7 or more" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.5.1.3 Ensure password expiration warning days is 7 or more" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.5.1.4 Ensure inactive password lock is 30 days or less" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.5.1.5 Ensure all users last password change date is in the past" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.5.2 Ensure system accounts are secured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.5.3 Ensure default user shell timeout is 900 seconds or less" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.5.4 Ensure default group for the root account is GID 0" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.5.5 Ensure default user umask is 027 or more restrictive" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.6 Ensure root login is restricted to system console" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.7 Ensure access to the su command is restricted" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.10 Ensure no world writable files exist" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.11 Ensure no unowned files or directories exist" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.12 Ensure no ungrouped files or directories exist" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.13 Audit SUID executables" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.14 Audit SGID executables" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.1 Audit system file permissions" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.2 Ensure permissions on /etc/passwd are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.3 Ensure permissions on /etc/shadow are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.4 Ensure permissions on /etc/group are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.5 Ensure permissions on /etc/gshadow are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.6 Ensure permissions on /etc/passwd- are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.7 Ensure permissions on /etc/shadow- are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.8 Ensure permissions on /etc/group- are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.1.9 Ensure permissions on /etc/gshadow- are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.10 Ensure no users have .forward files" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.11 Ensure no users have .netrc files" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.12 Ensure users' .netrc Files are not group or world accessible" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.13 Ensure no users have .rhosts files" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.14 Ensure all groups in /etc/passwd exist in /etc/group" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.15 Ensure no duplicate UIDs exist" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.16 Ensure no duplicate GIDs exist" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.17 Ensure no duplicate user names exist" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.18 Ensure no duplicate group names exist" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.19 Ensure shadow group is empty" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.1 Ensure password fields are not empty" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.20 Ensure all users' home directories exist" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.2 Ensure no legacy \"+\" entries exist in /etc/passwd" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.3 Ensure root PATH Integrity" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.4 Ensure no legacy \"+\" entries exist in /etc/shadow" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.5 Ensure no legacy \"+\" entries exist in /etc/group" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.6 Ensure root is the only UID 0 account" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.7 Ensure users' home directories permissions are 750 or more restrictive" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.8 Ensure users own their home directories" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.9 Ensure users' dot files are not group or world writable" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


# Génération des rapports CSV/HTML
CSV_REPORT="cis_audit_report_$(date +%F).csv"
HTML_REPORT="cis_audit_report_$(date +%F).html"
echo "Check,Result" > "$CSV_REPORT"
grep '^Auditing:' "$LOG_FILE" | cut -d':' -f2- > /tmp/tmp_audit_descs
grep '^Result:' "$LOG_FILE" | cut -d':' -f2- > /tmp/tmp_audit_results
paste -d',' /tmp/tmp_audit_descs /tmp/tmp_audit_results >> "$CSV_REPORT"
echo "<html><body><h2>CIS Audit Report</h2><table border=1><tr><th>Check</th><th>Result</th></tr>" > "$HTML_REPORT"
awk -F',' '{print "<tr><td>"$1"</td><td>"$2"</td></tr>"}' "$CSV_REPORT" >> "$HTML_REPORT"
echo "</table></body></html>" >> "$HTML_REPORT"
rm -f /tmp/tmp_audit_descs /tmp/tmp_audit_results