#!/bin/bash

#
# MGH / CIS Linux Audit Script - VERSION 41 beta du 25/9/2025
#
# Reference: https://www.cisecurity.org/benchmark/red_hat_linux
#
#
#
########################################################################
########################################################################
########################################################################
############## Special Char OK ✔️ ######################################
############## Special Char NOK ❌ #####################################
########################################################################
########################################################################


# LOG FILE Nammed using date
#LOG_FILE="cis_audit_report_$(date +%F).log"

# Updated to include host FQDN in lofgile name
LOG_FILE="cis_audit_report_$(hostname -f)_$(date +%F).log"

#Exceptions comment files folder
CIS_EXEPTIONS_FOLDER="/cis/"

#Exception comment file namming format
# cis-ID.txt
# cis-1.1.0.txt
# cis-3.5.1.txt
# file can contain up to 4000 Char


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
if modinfo cramfs >/dev/null 2>&1; then
RESULT=$(modprobe -n -v cramfs 2>/dev/null | grep -q 'install /bin/true' && echo OK || echo NOT COMPLIANT)
else
RESULT="OK"
fi
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



echo "Auditing: 3.4.3.2 Ensure a nftables table exists" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if command -v nft >/dev/null 2>&1 && systemctl is-active nftables 2>/dev/null | grep -q active; then
    NFT_TABLES=$(nft list tables 2>/dev/null | grep -v '^$')
    if [ -n "$NFT_TABLES" ]; then
        echo "✔️  At least one nftables table exists:" >> "$LOG_FILE"
        echo "$NFT_TABLES" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ No nftables table found" >> "$LOG_FILE"
    fi
else
    echo "⚠️  nftables not running or not installed — skipping check" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.3.3 Ensure base chains exist in nftables" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if command -v nft >/dev/null 2>&1 && systemctl is-active nftables 2>/dev/null | grep -q active; then
    BASE_CHAINS=$(nft list ruleset 2>/dev/null | grep -E 'hook (input|forward|output)' | grep -E 'type filter')

    if [ -n "$BASE_CHAINS" ]; then
        echo "✔️  nftables has base chains with hooks:" >> "$LOG_FILE"
        echo "$BASE_CHAINS" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ No base chains with hook found in nftables ruleset" >> "$LOG_FILE"
    fi
else
    echo "⚠️  nftables not running or not installed — skipping check" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.3.4 Ensure loopback traffic is configured in nftables" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if command -v nft >/dev/null 2>&1 && systemctl is-active nftables 2>/dev/null | grep -q active; then
    ACCEPT_LOOPBACK=$(nft list ruleset | grep -c 'iif "lo" accept')
    BLOCK_SPOOF=$(nft list ruleset | grep -c 'ip saddr 127.0.0.0/8 drop')

    if [ "$ACCEPT_LOOPBACK" -gt 0 ] && [ "$BLOCK_SPOOF" -gt 0 ]; then
        echo "✔️  Loopback traffic is allowed and spoofed 127.0.0.0/8 is blocked" >> "$LOG_FILE"
        RESULT="OK"
    else
        if [ "$ACCEPT_LOOPBACK" -eq 0 ]; then
            echo "❌ No rule found to allow loopback interface (iif \"lo\" accept)" >> "$LOG_FILE"
        fi
        if [ "$BLOCK_SPOOF" -eq 0 ]; then
            echo "❌ No rule found to block spoofed 127.0.0.0/8 packets" >> "$LOG_FILE"
        fi
    fi
else
    echo "⚠️  nftables not running or not installed — check skipped" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.3.5 Ensure outbound and established connections are configured in nftables" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if command -v nft >/dev/null 2>&1 && systemctl is-active nftables 2>/dev/null | grep -q active; then
    ESTABLISHED_IN=$(nft list ruleset | grep -E 'hook input' | grep -c 'ct state established accept')
    OUTBOUND_NEW=$(nft list ruleset | grep -E 'hook output' | grep -c 'ct state (new,established|established,related|established) accept')

    if [ "$ESTABLISHED_IN" -gt 0 ] && [ "$OUTBOUND_NEW" -gt 0 ]; then
        echo "✔️  Rules for outbound and established connections are present" >> "$LOG_FILE"
        RESULT="OK"
    else
        if [ "$ESTABLISHED_IN" -eq 0 ]; then
            echo "❌ No rule found to allow ct state established on input chain" >> "$LOG_FILE"
        fi
        if [ "$OUTBOUND_NEW" -eq 0 ]; then
            echo "❌ No rule found to allow outbound new/established traffic on output chain" >> "$LOG_FILE"
        fi
    fi
else
    echo "⚠️  nftables not running or not installed — check skipped" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.3.6 Ensure default deny firewall policy in nftables" >> "$LOG_FILE"
RESULT="OK"

if command -v nft >/dev/null 2>&1 && systemctl is-active nftables 2>/dev/null | grep -q active; then
    HOOKS=("input" "forward" "output")
    for hook in "${HOOKS[@]}"; do
        if ! nft list ruleset | grep -E "hook $hook" | grep -q "policy drop"; then
            echo "❌ Missing or incorrect 'policy drop' on hook $hook" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        else
            echo "✔️  Default policy is set to drop on hook $hook" >> "$LOG_FILE"
        fi
    done
else
    echo "⚠️  nftables not active — check skipped" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.3.7 Ensure nftables service is enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q nftables >/dev/null 2>&1; then
    if systemctl is-enabled nftables 2>/dev/null | grep -q enabled; then
        echo "✔️  nftables service is enabled" >> "$LOG_FILE"
    else
        echo "❌ nftables service is installed but not enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ nftables package is not installed" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.3.8 Ensure nftables rules are permanent" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Liste des fichiers de config possibles
CONF_FILES=(
  "/etc/sysconfig/nftables.conf"
  "/etc/nftables.conf"
)

RULE_FOUND=0

if command -v nft >/dev/null 2>&1; then
    for f in "${CONF_FILES[@]}"; do
        if [ -f "$f" ]; then
            if grep -qE '^\s*table\s+' "$f"; then
                echo "✔️  Found nftables table rule in: $f" >> "$LOG_FILE"
                RULE_FOUND=1
                RESULT="OK"
                break
            else
                echo "⚠️  Config file $f found but does not define any table" >> "$LOG_FILE"
            fi
        fi
    done

    if [ "$RULE_FOUND" -eq 0 ]; then
        echo "❌ No nftables rules found in expected config files" >> "$LOG_FILE"
    fi
else
    echo "⚠️  nft command not available — cannot check persistence" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.4.1.1 Ensure default deny firewall policy in firewalld" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)

    if [ -n "$DEFAULT_ZONE" ]; then
        ZONE_TARGET=$(firewall-cmd --zone="$DEFAULT_ZONE" --get-target 2>/dev/null)

        if [ "$ZONE_TARGET" = "DROP" ]; then
            echo "✔️  Default firewalld zone '$DEFAULT_ZONE' has DROP policy" >> "$LOG_FILE"
            RESULT="OK"
        else
            echo "❌ Default firewalld zone '$DEFAULT_ZONE' target is '$ZONE_TARGET' instead of DROP" >> "$LOG_FILE"
        fi
    else
        echo "❌ Could not determine default firewalld zone" >> "$LOG_FILE"
    fi
else
    echo "⚠️  firewalld is not active — skipping check" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.4.1.2 Ensure loopback traffic is configured in firewalld" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    RUNTIME_RULES=$(firewall-cmd --direct --get-all-rules 2>/dev/null)

    LOOPBACK_ALLOW=$(echo "$RUNTIME_RULES" | grep -c 'ACCEPT.*-i lo')
    SPOOF_BLOCK=$(echo "$RUNTIME_RULES" | grep -c 'DROP.*-s 127.0.0.0/8 ! -i lo')

    if [ "$LOOPBACK_ALLOW" -gt 0 ]; then
        echo "✔️  firewalld accepts traffic on lo interface" >> "$LOG_FILE"
    else
        echo "❌ No rule found to explicitly allow loopback traffic on lo" >> "$LOG_FILE"
    fi

    if [ "$SPOOF_BLOCK" -gt 0 ]; then
        echo "✔️  firewalld drops spoofed 127.0.0.0/8 traffic not via lo" >> "$LOG_FILE"
    else
        echo "❌ No rule found to drop spoofed 127.0.0.0/8 packets not via lo" >> "$LOG_FILE"
    fi

    if [ "$LOOPBACK_ALLOW" -gt 0 ] && [ "$SPOOF_BLOCK" -gt 0 ]; then
        RESULT="OK"
    fi
else
    echo "⚠️  firewalld is not running — skipping check" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.4.1.3 Ensure outbound and established connections are configured in firewalld" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    RUNTIME_RULES=$(firewall-cmd --direct --get-all-rules 2>/dev/null)

    # Recherche de règles ACCEPT pour états ESTABLISHED et RELATED
    ESTABLISHED_RULES=$(echo "$RUNTIME_RULES" | grep -E 'ACCEPT' | grep -E '\-m state\s+--state\s+(ESTABLISHED|RELATED)')

    # Recherche de règles autorisant les connexions sortantes
    OUTPUT_RULES=$(echo "$RUNTIME_RULES" | grep -E '^-A OUTPUT.*ACCEPT')

    if [ -n "$ESTABLISHED_RULES" ]; then
        echo "✔️  firewalld accepts established/related connections" >> "$LOG_FILE"
    else
        echo "❌ No rule found for accepting ESTABLISHED or RELATED traffic" >> "$LOG_FILE"
    fi

    if [ -n "$OUTPUT_RULES" ]; then
        echo "✔️  firewalld allows outbound connections" >> "$LOG_FILE"
    else
        echo "❌ No rule found to allow outbound connections (OUTPUT chain)" >> "$LOG_FILE"
    fi

    if [ -n "$ESTABLISHED_RULES" ] && [ -n "$OUTPUT_RULES" ]; then
        RESULT="OK"
    fi
else
    echo "⚠️  firewalld is not active — check skipped" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 3.4.4.1.4 Ensure firewall rules exist for all open ports" >> "$LOG_FILE"
RESULT="OK"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    # Ports écoutés en TCP/UDP
    OPEN_PORTS=$(ss -tuln | awk 'NR>1 && $1 ~ /^(tcp|udp)$/ {gsub(".*:", "", $5); print $1 ":" $5}' | sort -u)
    
    # Ports autorisés dans firewalld (toutes zones)
    FIREWALL_PORTS=$(firewall-cmd --list-all-zones | grep -E 'ports:' | sed 's/.*ports: //' | tr ' ' '\n' | sed 's/\/.*//' | sort -u)

    for port_proto in $OPEN_PORTS; do
        proto=$(echo "$port_proto" | cut -d: -f1)
        port=$(echo "$port_proto" | cut -d: -f2)

        # Vérifie si le port figure dans la configuration firewalld
        if echo "$FIREWALL_PORTS" | grep -qx "$port"; then
            echo "✔️  Open $proto port $port is covered by firewalld rules" >> "$LOG_FILE"
        else
            echo "❌ Open $proto port $port is NOT covered by firewalld" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi
    done

    if [ -z "$OPEN_PORTS" ]; then
        echo "✔️  No open TCP/UDP ports detected" >> "$LOG_FILE"
    fi
else
    echo "⚠️  firewalld not running — cannot validate open ports coverage" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.4.2.1 Ensure IPv6 default deny firewall policy in firewalld" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    DEFAULT_ZONE=$(firewall-cmd --get-default-zone 2>/dev/null)

    if [ -n "$DEFAULT_ZONE" ]; then
        TARGET=$(firewall-cmd --zone="$DEFAULT_ZONE" --get-target 2>/dev/null)

        if [ "$TARGET" = "DROP" ]; then
            echo "✔️  Default zone '$DEFAULT_ZONE' uses DROP policy (applies to IPv4 and IPv6)" >> "$LOG_FILE"
            RESULT="OK"
        else
            echo "❌ Default zone '$DEFAULT_ZONE' uses target '$TARGET' instead of DROP" >> "$LOG_FILE"
        fi
    else
        echo "❌ Unable to determine default firewalld zone" >> "$LOG_FILE"
    fi
else
    echo "⚠️  firewalld is not running — skipping IPv6 deny policy check" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.4.2.2 Ensure IPv6 loopback traffic is configured in firewalld" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    DIRECT_RULES=$(firewall-cmd --direct --get-all-rules 2>/dev/null)

    IPV6_LOOP_ALLOW=$(echo "$DIRECT_RULES" | grep -cE 'ipv6.*ACCEPT.*-i lo')
    IPV6_SPOOF_BLOCK=$(echo "$DIRECT_RULES" | grep -cE 'ipv6.*DROP.*-s ::1/128 ! -i lo')

    if [ "$IPV6_LOOP_ALLOW" -gt 0 ]; then
        echo "✔️  firewalld accepts IPv6 traffic on lo interface (::1)" >> "$LOG_FILE"
    else
        echo "❌ No rule found to allow IPv6 loopback (::1) traffic on lo" >> "$LOG_FILE"
    fi

    if [ "$IPV6_SPOOF_BLOCK" -gt 0 ]; then
        echo "✔️  firewalld drops spoofed IPv6 loopback (::1) traffic not via lo" >> "$LOG_FILE"
    else
        echo "❌ No rule found to drop spoofed ::1 packets not via lo" >> "$LOG_FILE"
    fi

    if [ "$IPV6_LOOP_ALLOW" -gt 0 ] && [ "$IPV6_SPOOF_BLOCK" -gt 0 ]; then
        RESULT="OK"
    fi
else
    echo "⚠️  firewalld is not active — check skipped" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.4.2.3 Ensure IPv6 outbound and established connections are configured in firewalld" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    DIRECT_RULES=$(firewall-cmd --direct --get-all-rules 2>/dev/null)

    # Règle pour les connexions établies entrantes
    IPV6_ESTABLISHED=$(echo "$DIRECT_RULES" | grep -E 'ipv6.*-m state --state (RELATED|ESTABLISHED).*ACCEPT' | grep -i '\-A INPUT')
    
    # Règle pour les connexions sortantes
    IPV6_OUTPUT=$(echo "$DIRECT_RULES" | grep -E 'ipv6.*-A OUTPUT.*ACCEPT')

    if [ -n "$IPV6_ESTABLISHED" ]; then
        echo "✔️  firewalld accepts IPv6 established/related inbound connections" >> "$LOG_FILE"
    else
        echo "❌ No IPv6 rule found to accept ESTABLISHED or RELATED input traffic" >> "$LOG_FILE"
    fi

    if [ -n "$IPV6_OUTPUT" ]; then
        echo "✔️  firewalld allows IPv6 outbound traffic" >> "$LOG_FILE"
    else
        echo "❌ No IPv6 rule found to allow outbound traffic" >> "$LOG_FILE"
    fi

    if [ -n "$IPV6_ESTABLISHED" ] && [ -n "$IPV6_OUTPUT" ]; then
        RESULT="OK"
    fi
else
    echo "⚠️  firewalld is not running — skipping IPv6 connection checks" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.4.4.2.4 Ensure IPv6 firewall rules exist for all open ports" >> "$LOG_FILE"
RESULT="OK"

if systemctl is-active firewalld 2>/dev/null | grep -q active; then
    # Récupère les ports IPv6 ouverts avec ss
    OPEN_IPV6_PORTS=$(ss -tuln6 | awk 'NR>1 && $1 ~ /^(tcp|udp)$/ {gsub(".*:", "", $5); print $1 ":" $5}' | sort -u)

    # Récupère tous les ports déclarés dans firewalld
    FW_ALL_ZONES=$(firewall-cmd --list-all-zones 2>/dev/null)
    FIREWALL_IPV6_PORTS=$(echo "$FW_ALL_ZONES" | grep -E 'ports:' | sed 's/.*ports: //' | tr ' ' '\n' | sed 's|/.*||' | sort -u)

    for port_proto in $OPEN_IPV6_PORTS; do
        proto=$(echo "$port_proto" | cut -d: -f1)
        port=$(echo "$port_proto" | cut -d: -f2)

        if echo "$FIREWALL_IPV6_PORTS" | grep -qx "$port"; then
            echo "✔️  IPv6 $proto port $port is covered by firewalld" >> "$LOG_FILE"
        else
            echo "❌ IPv6 $proto port $port is NOT explicitly allowed by firewalld" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi
    done

    if [ -z "$OPEN_IPV6_PORTS" ]; then
        echo "✔️  No IPv6 ports are listening — nothing to check" >> "$LOG_FILE"
    fi
else
    echo "⚠️  firewalld is not running — check skipped" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.5 Ensure wireless interfaces are disabled" >> "$LOG_FILE"
RESULT="OK"

if command -v iw >/dev/null 2>&1; then
    WIFI_INTERFACES=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')

    if [ -z "$WIFI_INTERFACES" ]; then
        echo "✔️  No wireless interfaces detected" >> "$LOG_FILE"
    else
        for iface in $WIFI_INTERFACES; do
            IF_STATE=$(cat /sys/class/net/"$iface"/operstate 2>/dev/null)
            if [ "$IF_STATE" = "up" ]; then
                echo "❌ Wireless interface $iface is UP (should be disabled)" >> "$LOG_FILE"
                RESULT="NOT COMPLIANT"
            else
                echo "✔️  Wireless interface $iface is present but not active" >> "$LOG_FILE"
            fi
        done
    fi
else
    echo "⚠️  'iw' utility not available — cannot detect wireless interfaces" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 3.6 Ensure IPv6 is disabled" >> "$LOG_FILE"
RESULT="OK"

# 1. Vérifie si IPv6 est désactivé via sysctl
DISABLE_ALL=$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null)
DISABLE_DEFAULT=$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null)

if [ "$DISABLE_ALL" = "1" ] && [ "$DISABLE_DEFAULT" = "1" ]; then
    echo "✔️  IPv6 is disabled via sysctl (net.ipv6.conf.*.disable_ipv6 = 1)" >> "$LOG_FILE"
else
    echo "❌ IPv6 sysctl disable flags are not correctly set" >> "$LOG_FILE"
    echo "Current values: all=$DISABLE_ALL, default=$DISABLE_DEFAULT" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

# 2. Vérifie si le module est bloqué au chargement
MODPROBE_BLOCK=$(grep -E '^(install|blacklist)\s+ipv6' /etc/modprobe.d/* 2>/dev/null)

if echo "$MODPROBE_BLOCK" | grep -q 'install ipv6 /bin/true'; then
    echo "✔️  IPv6 module is blocked from loading (/etc/modprobe.d)" >> "$LOG_FILE"
else
    echo "❌ IPv6 module is not explicitly blocked in modprobe config" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

# 3. Vérifie qu’aucune interface n’a d’adresse IPv6 active
ACTIVE_IPV6=$(ip -6 addr show scope global 2>/dev/null | grep -c inet6)

if [ "$ACTIVE_IPV6" -eq 0 ]; then
    echo "✔️  No active IPv6 addresses detected on interfaces" >> "$LOG_FILE"
else
    echo "❌ Detected $ACTIVE_IPV6 active IPv6 address(es)" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.10 Ensure unsuccessful unauthorized file access attempts are collected" >> "$LOG_FILE"
RESULT="OK"

REQUIRED_SYSCALLS=("creat" "open" "openat" "truncate" "ftruncate")
AUDIT_RULES=$(auditctl -l 2>/dev/null)

for syscall in "${REQUIRED_SYSCALLS[@]}"; do
    RULE_EACCES=$(echo "$AUDIT_RULES" | grep -E "^-a always,exit.*-F arch=.*-S $syscall.*-F exit=-EACCES")
    RULE_EPERM=$(echo "$AUDIT_RULES" | grep -E "^-a always,exit.*-F arch=.*-S $syscall.*-F exit=-EPERM")

    if [ -z "$RULE_EACCES" ] && [ -z "$RULE_EPERM" ]; then
        echo "❌ Missing audit rule for syscall '$syscall' with -EACCES or -EPERM" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  Audit rule found for '$syscall' (access denied logging)" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.1.1 Ensure auditd is installed" >> "$LOG_FILE"
RESULT="OK"

if rpm -q audit >/dev/null 2>&1; then
    echo "✔️  auditd package is installed" >> "$LOG_FILE"
else
    echo "❌ auditd (package 'audit') is NOT installed" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.11 Ensure events that modify user/group information are collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)

BINARIES=(
  /usr/sbin/useradd
  /usr/sbin/userdel
  /usr/sbin/usermod
  /usr/sbin/groupadd
  /usr/sbin/groupdel
  /usr/sbin/groupmod
  /usr/bin/passwd
  /usr/bin/gpasswd
  /usr/bin/chage
)

for bin in "${BINARIES[@]}"; do
    if echo "$AUDIT_RULES" | grep -E "\-w $bin " | grep -qE '\-p [wa]'; then
        echo "✔️  Audit rule found for $bin" >> "$LOG_FILE"
    else
        echo "❌ Missing audit rule for $bin" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.1.2 Ensure auditd service is enabled" >> "$LOG_FILE"
RESULT="OK"

if rpm -q audit >/dev/null 2>&1; then
    if systemctl is-enabled auditd 2>/dev/null | grep -q enabled; then
        echo "✔️  auditd service is enabled" >> "$LOG_FILE"
    else
        echo "❌ auditd service is installed but not enabled" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ auditd package (audit) is not installed" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.12 Ensure successful file system mounts are collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)

# Vérifie la présence de la règle pour le syscall mount (x86_64 arch)
MOUNT_RULE_B64=$(echo "$AUDIT_RULES" | grep -E '\-a always,exit.*-F arch=b64.*-S mount')

# Vérifie aussi pour les systèmes 32 bits si pertinent (facultatif)
MOUNT_RULE_B32=$(echo "$AUDIT_RULES" | grep -E '\-a always,exit.*-F arch=b32.*-S mount')

if [ -n "$MOUNT_RULE_B64" ] || [ -n "$MOUNT_RULE_B32" ]; then
    echo "✔️  Audit rule found for syscall mount" >> "$LOG_FILE"
else
    echo "❌ Missing audit rule for syscall mount" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.1.3 Ensure auditing for processes that start prior to auditd is enabled" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Vérifie la présence de audit=1 dans les paramètres GRUB actuels
if grep -q '^\s*GRUB_CMDLINE_LINUX=.*audit=1' /etc/default/grub; then
    echo "✔️  'audit=1' found in GRUB_CMDLINE_LINUX in /etc/default/grub" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ 'audit=1' is missing from GRUB_CMDLINE_LINUX in /etc/default/grub" >> "$LOG_FILE"
    echo "Example: GRUB_CMDLINE_LINUX=\"... audit=1\"" >> "$LOG_FILE"
fi

# Vérifie aussi s'il est effectivement actif sur le système en cours
if grep -qw audit=1 /proc/cmdline; then
    echo "✔️  audit=1 is active in current kernel boot parameters (/proc/cmdline)" >> "$LOG_FILE"
else
    echo "⚠️  audit=1 is not active in current kernel boot — system reboot may be required" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.13 Ensure use of privileged commands is collected" >> "$LOG_FILE"
RESULT="OK"

# Récupère tous les fichiers setuid/setgid root
PRIV_CMDS=$(find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)

AUDIT_RULES=$(auditctl -l 2>/dev/null)

for cmd in $PRIV_CMDS; do
    if echo "$AUDIT_RULES" | grep -q -- "-w $cmd"; then
        echo "✔️  Audit rule exists for privileged command: $cmd" >> "$LOG_FILE"
    else
        echo "❌ Missing audit rule for privileged command: $cmd" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 4.1.1.4 Ensure audit_backlog_limit is sufficient" >> "$LOG_FILE"
RESULT="OK"

# 1. Vérifie la valeur active
ACTIVE_LIMIT=$(cat /proc/cmdline 2>/dev/null | grep -oP 'audit_backlog_limit=\K[0-9]+')

if [ -n "$ACTIVE_LIMIT" ]; then
    if [ "$ACTIVE_LIMIT" -ge 8192 ]; then
        echo "✔️  audit_backlog_limit is set to $ACTIVE_LIMIT in /proc/cmdline (>= 8192)" >> "$LOG_FILE"
    else
        echo "❌ audit_backlog_limit is set to $ACTIVE_LIMIT (less than 8192)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ audit_backlog_limit is not set in /proc/cmdline" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

# 2. Vérifie s’il est défini dans la config GRUB
if grep -q 'audit_backlog_limit=' /etc/default/grub; then
    echo "✔️  audit_backlog_limit is configured in /etc/default/grub" >> "$LOG_FILE"
else
    echo "❌ audit_backlog_limit is NOT defined in /etc/default/grub" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 4.1.14 Ensure file deletion events by users are collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)

SYSCALLS=("unlink" "unlinkat" "rename" "renameat")
ARCHS=("b64")

# Inclure b32 si le système est 32 bits ou bi-architecture
if [ -d /sys/kernel/tracing/events/syscalls ] && grep -Rq 'arch.*b32' /sys/kernel/tracing/events/syscalls/ 2>/dev/null; then
    ARCHS+=("b32")
fi

for arch in "${ARCHS[@]}"; do
    for syscall in "${SYSCALLS[@]}"; do
        RULE_FOUND=$(echo "$AUDIT_RULES" | grep -E "\-a always,exit.*-F arch=$arch.*-S $syscall.*-F auid>=1000.*-F auid!=unset")
        if [ -z "$RULE_FOUND" ]; then
            echo "❌ Missing audit rule for $syscall on $arch" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        else
            echo "✔️  Audit rule exists for $syscall on $arch" >> "$LOG_FILE"
        fi
    done
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 4.1.15 Ensure kernel module loading and unloading is collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)
SYSCALLS=("init_module" "finit_module" "delete_module")
ARCHS=("b64")

# Vérifie si le système supporte aussi b32 (architecture 32 bits)
if grep -q 'arch.*b32' /sys/kernel/tracing/events/syscalls/ 2>/dev/null; then
    ARCHS+=("b32")
fi

for arch in "${ARCHS[@]}"; do
    for syscall in "${SYSCALLS[@]}"; do
        RULE_FOUND=$(echo "$AUDIT_RULES" | grep -E "\-a always,exit.*-F arch=$arch.*-S $syscall.*-F auid>=1000.*-F auid!=unset")
        if [ -z "$RULE_FOUND" ]; then
            echo "❌ Missing audit rule for $syscall on $arch" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        else
            echo "✔️  Audit rule exists for $syscall on $arch" >> "$LOG_FILE"
        fi
    done
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.16 Ensure system administrator actions (sudo log) are collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)

# Chemins possibles pour le sudo log
SUDO_LOG_FILES=(
  /var/log/sudo.log
  /var/log/auth.log
  /var/log/secure
)

RULE_FOUND=0

for file in "${SUDO_LOG_FILES[@]}"; do
    if [ -f "$file" ]; then
        if echo "$AUDIT_RULES" | grep -q -- "-w $file"; then
            echo "✔️  Audit rule exists for $file" >> "$LOG_FILE"
            RULE_FOUND=1
        else
            echo "❌ No audit rule for $file (but file exists)" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi
    fi
done

if [ "$RULE_FOUND" -eq 0 ]; then
    echo "⚠️  No known sudo log file found or audited — verify sudoers or syslog config" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.17 Ensure audit configuration is immutable" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Recherche du -e 2 dans les fichiers de règles persistantes
IMMUTABLE_LINE=$(grep -rE '^\s*-e\s+2\b' /etc/audit/rules.d/ /etc/audit/audit.rules 2>/dev/null)

if [ -n "$IMMUTABLE_LINE" ]; then
    echo "✔️  Immutable setting '-e 2' found in audit rules" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ Missing '-e 2' in audit configuration files (audit rules are not immutable)" >> "$LOG_FILE"
    echo "Tip: Add '-e 2' as the last line in your /etc/audit/rules.d/*.rules file" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.2.1 Ensure audit log storage size is configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

CONF_FILE="/etc/audit/auditd.conf"
if [ -f "$CONF_FILE" ]; then
    MAX_LOG_FILE=$(grep -Ei '^max_log_file\s*=' "$CONF_FILE" | awk -F= '{gsub(/ /, "", $2); print $2}')

    if [[ "$MAX_LOG_FILE" =~ ^[0-9]+$ ]]; then
        if [ "$MAX_LOG_FILE" -ge 8 ]; then
            echo "✔️  max_log_file is set to $MAX_LOG_FILE MB in $CONF_FILE" >> "$LOG_FILE"
            RESULT="OK"
        else
            echo "❌ max_log_file is set to $MAX_LOG_FILE (should be >= 8 MB)" >> "$LOG_FILE"
        fi
    else
        echo "❌ max_log_file is not set to a numeric value in $CONF_FILE" >> "$LOG_FILE"
    fi
else
    echo "❌ $CONF_FILE not found" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.2.2 Ensure audit logs are not automatically deleted" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

CONF_FILE="/etc/audit/auditd.conf"

if [ -f "$CONF_FILE" ]; then
    LOG_ACTION=$(grep -Ei '^max_log_file_action\s*=' "$CONF_FILE" | awk -F= '{gsub(/ /, "", $2); print tolower($2)}')

    if [ "$LOG_ACTION" = "keep_logs" ]; then
        echo "✔️  max_log_file_action is set to keep_logs in $CONF_FILE" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ max_log_file_action is set to '$LOG_ACTION' (should be 'keep_logs')" >> "$LOG_FILE"
    fi
else
    echo "❌ Configuration file $CONF_FILE not found" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.2.3 Ensure system is disabled when audit logs are full" >> "$LOG_FILE"
RESULT="OK"

CONF_FILE="/etc/audit/auditd.conf"

# Récupère et nettoie les valeurs
SPACE_LEFT=$(grep -Ei '^space_left_action\s*=' "$CONF_FILE" | awk -F= '{gsub(/ /, "", $2); print tolower($2)}')
MAIL_ACCT=$(grep -Ei '^action_mail_acct\s*=' "$CONF_FILE" | awk -F= '{gsub(/ /, "", $2); print $2}')
ADMIN_ACTION=$(grep -Ei '^admin_space_left_action\s*=' "$CONF_FILE" | awk -F= '{gsub(/ /, "", $2); print tolower($2)}')

# Vérifications individuelles
if [ "$SPACE_LEFT" != "email" ]; then
    echo "❌ space_left_action is '$SPACE_LEFT' (should be 'email')" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  space_left_action is set to 'email'" >> "$LOG_FILE"
fi

if [ "$MAIL_ACCT" != "root" ]; then
    echo "❌ action_mail_acct is '$MAIL_ACCT' (should be 'root')" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  action_mail_acct is set to 'root'" >> "$LOG_FILE"
fi

if [ "$ADMIN_ACTION" != "halt" ]; then
    echo "❌ admin_space_left_action is '$ADMIN_ACTION' (should be 'halt')" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  admin_space_left_action is set to 'halt'" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.3 Ensure changes to sudoers configuration are collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)
FILES_TO_CHECK=(
  "/etc/sudoers"
  "/etc/sudoers.d"
)

for file in "${FILES_TO_CHECK[@]}"; do
    if echo "$AUDIT_RULES" | grep -q -- "-w $file"; then
        echo "✔️  Audit rule exists for $file" >> "$LOG_FILE"
    else
        echo "❌ Missing audit rule for $file" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.4 Ensure login and logout events are collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)

LOGIN_FILES=(
  "/var/log/faillog"
  "/var/log/lastlog"
  "/var/log/tallylog"
)

for file in "${LOGIN_FILES[@]}"; do
    if [ -f "$file" ]; then
        if echo "$AUDIT_RULES" | grep -q -- "-w $file"; then
            echo "✔️  Audit rule exists for $file" >> "$LOG_FILE"
        else
            echo "❌ Missing audit rule for $file" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi
    else
        echo "ℹ️  File $file does not exist on this system — skipped" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"




echo "Auditing: 4.1.6 Ensure events that modify date and time information are collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)

FILES_TO_CHECK=(
  "/usr/bin/date"
  "/usr/sbin/hwclock"
  "/usr/bin/timedatectl"
  "/etc/localtime"
)

for file in "${FILES_TO_CHECK[@]}"; do
    if [ -f "$file" ]; then
        if echo "$AUDIT_RULES" | grep -q -- "-w $file"; then
            echo "✔️  Audit rule exists for $file" >> "$LOG_FILE"
        else
            echo "❌ Missing audit rule for $file" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi
    else
        echo "ℹ️  File $file does not exist on this system — skipped" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"




echo "Auditing: 4.1.7 Ensure events that modify the system's MAC are collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)

FILES_TO_CHECK=(
  "/etc/selinux/"
  "/usr/sbin/setsebool"
  "/usr/sbin/semanage"
  "/usr/sbin/setenforce"
  "/usr/sbin/sestatus"
)

for file in "${FILES_TO_CHECK[@]}"; do
    if [ -e "$file" ]; then
        if echo "$AUDIT_RULES" | grep -q -- "-w $file"; then
            echo "✔️  Audit rule exists for $file" >> "$LOG_FILE"
        else
            echo "❌ Missing audit rule for $file" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi
    else
        echo "ℹ️  $file not found — skipped" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.8 Ensure events that modify the system's network environment are collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)

FILES_TO_CHECK=(
  "/etc/issue"
  "/etc/issue.net"
  "/etc/hosts"
  "/etc/sysconfig/network"
  "/usr/bin/nmcli"
  "/usr/sbin/ifconfig"
  "/usr/sbin/ip"
  "/usr/sbin/route"
)

for file in "${FILES_TO_CHECK[@]}"; do
    if [ -e "$file" ]; then
        if echo "$AUDIT_RULES" | grep -q -- "-w $file"; then
            echo "✔️  Audit rule exists for $file" >> "$LOG_FILE"
        else
            echo "❌ Missing audit rule for $file" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi
    else
        echo "ℹ️  $file not found — skipped" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.1.9 Ensure DAC permission modification events are collected" >> "$LOG_FILE"
RESULT="OK"

AUDIT_RULES=$(auditctl -l 2>/dev/null)

SYSCALLS=("chmod" "fchmod" "fchmodat" "chown" "fchown" "fchownat" "lchown")
ARCHS=("b64")

# Ajoute b32 si applicable (système bi-architecture)
if grep -q 'arch.*b32' /sys/kernel/tracing/events/syscalls/ 2>/dev/null; then
    ARCHS+=("b32")
fi

for arch in "${ARCHS[@]}"; do
    for syscall in "${SYSCALLS[@]}"; do
        RULE_FOUND=$(echo "$AUDIT_RULES" | grep -E "\-a always,exit.*-F arch=$arch.*-S $syscall.*-F auid>=1000.*-F auid!=unset")
        if [ -z "$RULE_FOUND" ]; then
            echo "❌ Missing audit rule for syscall $syscall on $arch" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        else
            echo "✔️  Audit rule exists for $syscall on $arch" >> "$LOG_FILE"
        fi
    done
done

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

#
# Old version of this check that does not really check if rpm is installed.
#
#echo "Auditing: 4.2.1.1 Ensure rsyslog is installed" >> "$LOG_FILE"
#RESULT=$(command -v rsyslogd >/dev/null && echo OK || echo NOT COMPLIANT)
#echo "Result: $RESULT" >> "$LOG_FILE"
#echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.2.1.1 Ensure rsyslog is installed" >> "$LOG_FILE"
RESULT="OK"

if rpm -q rsyslog >/dev/null 2>&1; then
    echo "✔️  rsyslog package is installed" >> "$LOG_FILE"
else
    echo "❌ rsyslog package is NOT installed" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.2.1.2 Ensure rsyslog Service is enabled" >> "$LOG_FILE"
RESULT=$(systemctl is-enabled rsyslog 2>/dev/null | grep -q enabled && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 4.2.1.3 Ensure rsyslog default file permissions are configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Rechercher la directive dans le fichier principal ou dans les inclusions
MATCHES=$(grep -Er '^\s*\$FileCreateMode\s+[0-7]{4}' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null)

if [ -n "$MATCHES" ]; then
    # Extraire la valeur et comparer
    VALUE=$(echo "$MATCHES" | head -n 1 | awk '{print $2}')
    if [[ "$VALUE" =~ ^[0-7]{4}$ ]] && [ "$VALUE" -le 0640 ]; then
        echo "✔️  rsyslog default file mode is set to $VALUE (OK)" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ rsyslog $FileCreateMode is set to $VALUE (should be 0640 or stricter)" >> "$LOG_FILE"
    fi
else
    echo "❌ No \$FileCreateMode directive found in rsyslog configuration" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.2.1.4 Ensure logging is configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if systemctl is-active rsyslog 2>/dev/null | grep -q active; then
    LOG_DEST=$(grep -E '^[^#]*\/var\/log\/' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null)

    if [ -n "$LOG_DEST" ]; then
        echo "✔️  rsyslog is active and logging to local files:" >> "$LOG_FILE"
        echo "$LOG_DEST" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ rsyslog is active but no local file logging destination is configured" >> "$LOG_FILE"
    fi
else
    echo "⚠️  rsyslog is not active — checking journald instead" >> "$LOG_FILE"
    if systemctl is-active systemd-journald 2>/dev/null | grep -q active; then
        echo "✔️  systemd-journald is active (logs stored in /var/log/journal or volatile memory)" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ Neither rsyslog nor journald is actively logging" >> "$LOG_FILE"
    fi
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Recherche de directives @ ou @@ dans la config rsyslog
REMOTE_DEST=$(grep -Er '^[^#]*\*\.\* *@{1,2}[a-zA-Z0-9\.\-]+' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null)

if [ -n "$REMOTE_DEST" ]; then
    echo "✔️  rsyslog is configured to send logs to remote host(s):" >> "$LOG_FILE"
    echo "$REMOTE_DEST" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ No remote log forwarding configuration found in rsyslog" >> "$LOG_FILE"
    echo "Expected lines like: '*.* @@loghost.example.com'" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts" >> "$LOG_FILE"
RESULT="OK"

# Vérifie si le système écoute pour des logs entrants rsyslog (TCP 514)
LISTENING_RSYSLOG=$(ss -tuln | grep -E ':514\b')

if [ -n "$LISTENING_RSYSLOG" ]; then
    echo "❌ This system is listening on port 514 (rsyslog default)" >> "$LOG_FILE"
    echo "Only designated log servers should accept remote logs" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  This system is not listening on port 514 — not accepting remote rsyslog messages" >> "$LOG_FILE"
fi

# Optionnel : vérifie la config rsyslog
RSYSLOG_RECV=$(grep -Er '^\s*\$Input(TCP|UDP)ServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null)

if [ -n "$RSYSLOG_RECV" ]; then
    echo "⚠️  rsyslog is configured to accept remote logs — ensure this host is a designated log server" >> "$LOG_FILE"
    echo "$RSYSLOG_RECV" >> "$LOG_FILE"
    # Note: ce n'est pas nécessairement une non-conformité si ce système est le log host
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.2.2.1 Ensure journald is configured to send logs to rsyslog" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

CONF_FILE="/etc/systemd/journald.conf"

if [ -f "$CONF_FILE" ]; then
    FORWARD_LINE=$(grep -Ei '^\s*ForwardToSyslog\s*=' "$CONF_FILE")

    if echo "$FORWARD_LINE" | grep -q -i 'yes'; then
        echo "✔️  ForwardToSyslog is set to 'yes' in $CONF_FILE" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ ForwardToSyslog is not set to 'yes' (value: $FORWARD_LINE)" >> "$LOG_FILE"
    fi
else
    echo "❌ Configuration file $CONF_FILE not found" >> "$LOG_FILE"
fi

# Vérifie aussi l’état runtime effectif (bonus)
RUNTIME_FORWARD=$(journalctl --verify --no-pager 2>/dev/null | grep -i "ForwardToSyslog")

if [ -z "$RUNTIME_FORWARD" ]; then
    echo "ℹ️  Cannot verify runtime status of ForwardToSyslog — manual check recommended" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.2.2.2 Ensure journald is configured to compress large log files" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

CONF_FILE="/etc/systemd/journald.conf"

if [ -f "$CONF_FILE" ]; then
    COMPRESS_SETTING=$(grep -Ei '^\s*Compress\s*=' "$CONF_FILE")

    if echo "$COMPRESS_SETTING" | grep -q -i 'yes'; then
        echo "✔️  Compress is set to 'yes' in $CONF_FILE" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ Compress is not set to 'yes' (value: $COMPRESS_SETTING)" >> "$LOG_FILE"
    fi
else
    echo "❌ Configuration file $CONF_FILE not found" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

CONF_FILE="/etc/systemd/journald.conf"

if [ -f "$CONF_FILE" ]; then
    STORAGE_SETTING=$(grep -Ei '^\s*Storage\s*=' "$CONF_FILE")

    if echo "$STORAGE_SETTING" | grep -q -i 'persistent'; then
        echo "✔️  Storage is set to 'persistent' in $CONF_FILE" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ Storage is not set to 'persistent' (value: $STORAGE_SETTING)" >> "$LOG_FILE"
    fi
else
    echo "❌ Configuration file $CONF_FILE not found" >> "$LOG_FILE"
fi

# Vérifie si le répertoire de logs persistants existe
if [ -d "/var/log/journal" ]; then
    echo "✔️  /var/log/journal exists — persistent storage is active" >> "$LOG_FILE"
else
    echo "❌ /var/log/journal is missing — journald logs may not persist after reboot" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.2.3 Ensure permissions on all logfiles are configured" >> "$LOG_FILE"
RESULT="OK"

LOGFILES=$(find /var/log -type f 2>/dev/null)

for file in $LOGFILES; do
    perms=$(stat -c "%a" "$file")
    owner=$(stat -c "%U" "$file")

    if [ "$perms" -gt 640 ]; then
        echo "❌ $file has permissions $perms (should be 640 or stricter)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi

    if [ "$owner" != "root" ] && [ "$owner" != "syslog" ]; then
        echo "❌ $file is owned by $owner (should be root or syslog)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
done

if [ "$RESULT" = "OK" ]; then
    echo "✔️  All logfiles in /var/log have secure ownership and permissions" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 4.3 Ensure logrotate is configured" >> "$LOG_FILE"
RESULT="OK"

# 1. Vérifie si le paquet logrotate est installé
if ! rpm -q logrotate >/dev/null 2>&1; then
    echo "❌ logrotate package is NOT installed" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  logrotate package is installed" >> "$LOG_FILE"
fi

# 2. Vérifie la présence du fichier principal de configuration
if [ ! -f /etc/logrotate.conf ]; then
    echo "❌ /etc/logrotate.conf is missing" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  /etc/logrotate.conf exists" >> "$LOG_FILE"
fi

# 3. Vérifie qu'il y a au moins un fichier de configuration dans /etc/logrotate.d
ROTATE_ENTRIES=$(find /etc/logrotate.d/ -type f 2>/dev/null | wc -l)

if [ "$ROTATE_ENTRIES" -ge 1 ]; then
    echo "✔️  logrotate includes $ROTATE_ENTRIES custom configuration(s) in /etc/logrotate.d/" >> "$LOG_FILE"
else
    echo "❌ No logrotate rules found in /etc/logrotate.d/" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 5.1.1 Ensure cron daemon is enabled" >> "$LOG_FILE"
RESULT="OK"

# Vérifie si cronie (cron daemon) est installé
if ! rpm -q cronie >/dev/null 2>&1; then
    echo "❌ cronie package is NOT installed" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  cronie package is installed" >> "$LOG_FILE"
fi

# Vérifie si le service est activé
if systemctl is-enabled crond 2>/dev/null | grep -q enabled; then
    echo "✔️  crond service is enabled at boot" >> "$LOG_FILE"
else
    echo "❌ crond service is not enabled" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

# Bonus : vérifier s'il tourne actuellement
if systemctl is-active crond 2>/dev/null | grep -q active; then
    echo "✔️  crond service is currently running" >> "$LOG_FILE"
else
    echo "⚠️  crond service is not running right now (but may start at boot)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 5.1.2 Ensure permissions on /etc/crontab are configured" >> "$LOG_FILE"
RESULT="OK"

FILE="/etc/crontab"

if [ -f "$FILE" ]; then
    OWNER=$(stat -c "%U" "$FILE")
    PERMS=$(stat -c "%a" "$FILE")

    # Vérifie le propriétaire
    if [ "$OWNER" != "root" ]; then
        echo "❌ $FILE is owned by $OWNER (should be root)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $FILE is owned by root" >> "$LOG_FILE"
    fi

    # Vérifie les permissions
    if [ "$PERMS" -le 640 ]; then
        echo "✔️  $FILE permissions are $PERMS (OK)" >> "$LOG_FILE"
    else
        echo "❌ $FILE permissions are $PERMS (should be 600, 640, or stricter)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ $FILE does not exist!" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.1.3 Ensure permissions on /etc/cron.hourly are configured" >> "$LOG_FILE"
RESULT="OK"

DIR="/etc/cron.hourly"

if [ -d "$DIR" ]; then
    OWNER=$(stat -c "%U" "$DIR")
    PERMS=$(stat -c "%a" "$DIR")

    # Vérifie le propriétaire
    if [ "$OWNER" != "root" ]; then
        echo "❌ $DIR is owned by $OWNER (should be root)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $DIR is owned by root" >> "$LOG_FILE"
    fi

    # Vérifie les permissions
    if [ "$PERMS" -le 700 ]; then
        echo "✔️  $DIR permissions are $PERMS (OK)" >> "$LOG_FILE"
    else
        echo "❌ $DIR permissions are $PERMS (should be 0700 or stricter)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ $DIR does not exist!" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.1.4 Ensure permissions on /etc/cron.daily are configured" >> "$LOG_FILE"
RESULT="OK"

DIR="/etc/cron.daily"

if [ -d "$DIR" ]; then
    OWNER=$(stat -c "%U" "$DIR")
    PERMS=$(stat -c "%a" "$DIR")

    if [ "$OWNER" != "root" ]; then
        echo "❌ $DIR is owned by $OWNER (should be root)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $DIR is owned by root" >> "$LOG_FILE"
    fi

    if [ "$PERMS" -le 700 ]; then
        echo "✔️  $DIR permissions are $PERMS (OK)" >> "$LOG_FILE"
    else
        echo "❌ $DIR permissions are $PERMS (should be 0700 or stricter)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ $DIR does not exist!" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.1.5 Ensure permissions on /etc/cron.weekly are configured" >> "$LOG_FILE"
RESULT="OK"

DIR="/etc/cron.weekly"

if [ -d "$DIR" ]; then
    OWNER=$(stat -c "%U" "$DIR")
    PERMS=$(stat -c "%a" "$DIR")

    if [ "$OWNER" != "root" ]; then
        echo "❌ $DIR is owned by $OWNER (should be root)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $DIR is owned by root" >> "$LOG_FILE"
    fi

    if [ "$PERMS" -le 700 ]; then
        echo "✔️  $DIR permissions are $PERMS (OK)" >> "$LOG_FILE"
    else
        echo "❌ $DIR permissions are $PERMS (should be 0700 or stricter)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ $DIR does not exist!" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 5.1.6 Ensure permissions on /etc/cron.monthly are configured" >> "$LOG_FILE"
RESULT="OK"

DIR="/etc/cron.monthly"

if [ -d "$DIR" ]; then
    OWNER=$(stat -c "%U" "$DIR")
    PERMS=$(stat -c "%a" "$DIR")

    if [ "$OWNER" != "root" ]; then
        echo "❌ $DIR is owned by $OWNER (should be root)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $DIR is owned by root" >> "$LOG_FILE"
    fi

    if [ "$PERMS" -le 700 ]; then
        echo "✔️  $DIR permissions are $PERMS (OK)" >> "$LOG_FILE"
    else
        echo "❌ $DIR permissions are $PERMS (should be 0700 or stricter)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ $DIR does not exist!" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.1.7 Ensure permissions on /etc/cron.d are configured" >> "$LOG_FILE"
RESULT="OK"

DIR="/etc/cron.d"

if [ -d "$DIR" ]; then
    OWNER=$(stat -c "%U" "$DIR")
    PERMS=$(stat -c "%a" "$DIR")

    if [ "$OWNER" != "root" ]; then
        echo "❌ $DIR is owned by $OWNER (should be root)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $DIR is owned by root" >> "$LOG_FILE"
    fi

    if [ "$PERMS" -le 700 ]; then
        echo "✔️  $DIR permissions are $PERMS (OK)" >> "$LOG_FILE"
    else
        echo "❌ $DIR permissions are $PERMS (should be 0700 or stricter)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ $DIR does not exist!" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.1.8 Ensure at/cron is restricted to authorized users" >> "$LOG_FILE"
RESULT="OK"

FILES_ALLOW=("/etc/cron.allow" "/etc/at.allow")
FILES_DENY=("/etc/cron.deny" "/etc/at.deny")

# Vérifie la présence des fichiers .allow
for file in "${FILES_ALLOW[@]}"; do
    if [ -f "$file" ]; then
        OWNER=$(stat -c "%U" "$file")
        PERMS=$(stat -c "%a" "$file")

        if [ "$OWNER" != "root" ]; then
            echo "❌ $file is owned by $OWNER (should be root)" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        fi

        if [ "$PERMS" -gt 600 ]; then
            echo "❌ $file has permissions $PERMS (should be 0600 or stricter)" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
        else
            echo "✔️  $file exists with correct owner and permissions" >> "$LOG_FILE"
        fi
    else
        echo "❌ $file is missing (should exist to restrict access)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
done

# Vérifie que les fichiers .deny n'existent pas
for file in "${FILES_DENY[@]}"; do
    if [ -e "$file" ]; then
        echo "❌ $file exists (should be removed)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $file does not exist (OK)" >> "$LOG_FILE"
    fi
done

echo "Result: $RESULT" >> "$LOG_FILE"
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
RESULT="OK"

SSHD_CONFIG="/etc/ssh/sshd_config"

if [ ! -f "$SSHD_CONFIG" ]; then
    echo "❌ SSH configuration file not found: $SSHD_CONFIG" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    # Lire les valeurs actuelles (en ignorant les commentaires)
    INTERVAL=$(grep -Ei '^\s*ClientAliveInterval' "$SSHD_CONFIG" | awk '{print $2}')
    COUNTMAX=$(grep -Ei '^\s*ClientAliveCountMax' "$SSHD_CONFIG" | awk '{print $2}')

    # Vérifie les deux directives
    if [ -z "$INTERVAL" ] || [ "$INTERVAL" -gt 300 ]; then
        echo "❌ ClientAliveInterval is missing or > 300 (current: $INTERVAL)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  ClientAliveInterval is set to $INTERVAL" >> "$LOG_FILE"
    fi

    if [ -z "$COUNTMAX" ] || [ "$COUNTMAX" -ne 0 ]; then
        echo "❌ ClientAliveCountMax is missing or != 0 (current: $COUNTMAX)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  ClientAliveCountMax is set to 0" >> "$LOG_FILE"
    fi
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 5.2.14 Ensure SSH LoginGraceTime is set to one minute or less" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

LOGIN_GRACE_TIME=$(grep -Ei '^\s*LoginGraceTime\s+' /etc/ssh/sshd_config | awk '{print $2}' | head -n1)

if [ -z "$LOGIN_GRACE_TIME" ]; then
    echo "❌ LoginGraceTime is not explicitly set (default is 120 seconds)" >> "$LOG_FILE"
else
    case "$LOGIN_GRACE_TIME" in
        *m) VALUE=$(( ${LOGIN_GRACE_TIME%m} * 60 ));;
        *s) VALUE=${LOGIN_GRACE_TIME%s};;
        *) VALUE=$LOGIN_GRACE_TIME;;
    esac

    if [ "$VALUE" -le 60 ]; then
        echo "✔️  LoginGraceTime is set to $VALUE seconds" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ LoginGraceTime is set to $VALUE seconds (should be ≤ 60)" >> "$LOG_FILE"
    fi
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"



echo "Auditing: 5.2.15 Ensure SSH Banner is set to /etc/issue.net" >> "$LOG_FILE"
if [ -f "$SSHD_CONFIG" ]; then
    VALUE=$(grep -Ei "^\s*Banner\s+" "$SSHD_CONFIG" | awk '{print tolower($2)}')
    if [ "$VALUE" = "/etc/issue.net" ]; then
        echo "✔️  Banner is correctly set to /etc/issue.net" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ Banner is set to $VALUE (expected: /etc/issue.net)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ SSH configuration file not found" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.16 Ensure SSH UsePAM is set to yes" >> "$LOG_FILE"
if [ -f "$SSHD_CONFIG" ]; then
    VALUE=$(grep -Ei "^\s*UsePAM\s+" "$SSHD_CONFIG" | awk '{print tolower($2)}')
    if [ "$VALUE" = "yes" ]; then
        echo "✔️  UsePAM is correctly set to yes" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ UsePAM is set to $VALUE (expected: yes)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ SSH configuration file not found" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.17 Ensure SSH AllowTcpForwarding is set to no" >> "$LOG_FILE"
if [ -f "$SSHD_CONFIG" ]; then
    VALUE=$(grep -Ei "^\s*AllowTcpForwarding\s+" "$SSHD_CONFIG" | awk '{print tolower($2)}')
    if [ "$VALUE" = "no" ]; then
        echo "✔️  AllowTcpForwarding is correctly set to no" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ AllowTcpForwarding is set to $VALUE (expected: no)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ SSH configuration file not found" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.18 Ensure SSH MaxStartups is configured" >> "$LOG_FILE"
if [ -f "$SSHD_CONFIG" ]; then
    VALUE=$(grep -Ei "^\s*MaxStartups\s+" "$SSHD_CONFIG" | awk '{print $2}')
    if echo "$VALUE" | grep -qE "^\d+(:\d+){0,2}$"; then
        echo "✔️  MaxStartups is correctly set to: $VALUE" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ MaxStartups format is invalid or missing (value: $VALUE)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ SSH configuration file not found" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.19 Ensure SSH MaxSessions is set to 4 or less" >> "$LOG_FILE"
if [ -f "$SSHD_CONFIG" ]; then
    VALUE=$(grep -Ei "^\s*MaxSessions\s+" "$SSHD_CONFIG" | awk '{print $2}')
    if [ -n "$VALUE" ] && [ "$VALUE" -le 4 ]; then
        echo "✔️  MaxSessions is set to $VALUE (OK)" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ MaxSessions is $VALUE (should be ≤ 4)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ SSH configuration file not found" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.20 Ensure system-wide crypto policy is not over-ridden" >> "$LOG_FILE"
if [ -f /etc/sysconfig/sshd ]; then
    if grep -Eq "^\\s*CRYPTO_POLICY=" /etc/sysconfig/sshd; then
        echo "❌ /etc/sysconfig/sshd overrides system-wide crypto policy" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  No system-wide crypto override in /etc/sysconfig/sshd" >> "$LOG_FILE"
        RESULT="OK"
    fi
else
    echo "✔️  /etc/sysconfig/sshd does not exist — no override detected" >> "$LOG_FILE"
    RESULT="OK"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured" >> "$LOG_FILE"

if [ -f "/etc/ssh/sshd_config" ]; then
    OWNER=$(stat -c "%U" "/etc/ssh/sshd_config")
    PERMS=$(stat -c "%a" "/etc/ssh/sshd_config")
    if [ "$OWNER" != "root" ]; then
        echo "❌ /etc/ssh/sshd_config is owned by $OWNER (expected: root)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    elif [ "$PERMS" -gt 600 ]; then
        echo "❌ /etc/ssh/sshd_config has permissions $PERMS (should be ≤ 600)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  /etc/ssh/sshd_config is owned by root and permissions are OK ($PERMS)" >> "$LOG_FILE"
        RESULT="OK"
    fi
else
    echo "❌ /etc/ssh/sshd_config does not exist" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.2 Ensure SSH access is limited" >> "$LOG_FILE"

if grep -Eq "^\s*(AllowUsers|AllowGroups|DenyUsers|DenyGroups)\s+.+" "$SSHD_CONFIG"; then
    echo "✔️  SSH access limitation directive is configured" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ No SSH access limitation directive found in $SSHD_CONFIG" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.3 Ensure permissions on SSH private host key files are configured" >> "$LOG_FILE"

for file in $(find /etc/ssh/ -type f -name "*_key"); do
    OWNER=$(stat -c "%U" "$file")
    PERMS=$(stat -c "%a" "$file")
    if [ "$OWNER" != "root" ] || [ "$PERMS" -gt 600 ]; then
        echo "❌ $file has incorrect ownership or permissions ($OWNER:$PERMS)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $file ownership and permissions are OK" >> "$LOG_FILE"
        RESULT="OK"
    fi
done
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.4 Ensure permissions on SSH public host key files are configured" >> "$LOG_FILE"

for file in $(find /etc/ssh/ -type f -name "*.pub"); do
    OWNER=$(stat -c "%U" "$file")
    PERMS=$(stat -c "%a" "$file")
    if [ "$OWNER" != "root" ] || [ "$PERMS" -gt 644 ]; then
        echo "❌ $file has incorrect ownership or permissions ($OWNER:$PERMS)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    else
        echo "✔️  $file ownership and permissions are OK" >> "$LOG_FILE"
        RESULT="OK"
    fi
done
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.5 Ensure SSH LogLevel is appropriate" >> "$LOG_FILE"

if [ -f "$SSHD_CONFIG" ]; then
    VALUE=$(grep -Ei "^\s*LogLevel\s+" "$SSHD_CONFIG" | awk '{print tolower($2)}')
    if [ "$VALUE" = "INFO" ]; then
        echo "✔️  LogLevel is set to INFO" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ LogLevel is set to $VALUE (expected: INFO)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ SSH config file not found" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.6 Ensure SSH X11 forwarding is disabled" >> "$LOG_FILE"

if [ -f "$SSHD_CONFIG" ]; then
    VALUE=$(grep -Ei "^\s*X11Forwarding\s+" "$SSHD_CONFIG" | awk '{print tolower($2)}')
    if [ "$VALUE" = "no" ]; then
        echo "✔️  X11Forwarding is set to no" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ X11Forwarding is set to $VALUE (expected: no)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ SSH config file not found" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less" >> "$LOG_FILE"

if [ -f "$SSHD_CONFIG" ]; then
    VALUE=$(grep -Ei "^\s*MaxAuthTries\s+" "$SSHD_CONFIG" | awk '{print $2}')
    if [[ "$VALUE" =~ ^[0-9]+$ ]] && [ "$VALUE" -le 4 ]; then
        echo "✔️  MaxAuthTries is set to $VALUE (OK)" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ MaxAuthTries is set to $VALUE (should be ≤ 4)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ SSH config file not found" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.8 Ensure SSH IgnoreRhosts is enabled" >> "$LOG_FILE"

if [ -f "$SSHD_CONFIG" ]; then
    VALUE=$(grep -Ei "^\s*IgnoreRhosts\s+" "$SSHD_CONFIG" | awk '{print tolower($2)}')
    if [ "$VALUE" = "yes" ]; then
        echo "✔️  IgnoreRhosts is set to yes" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ IgnoreRhosts is set to $VALUE (expected: yes)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ SSH config file not found" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 5.2.9 Ensure SSH HostbasedAuthentication is disabled" >> "$LOG_FILE"

if [ -f "$SSHD_CONFIG" ]; then
    VALUE=$(grep -Ei "^\s*HostbasedAuthentication\s+" "$SSHD_CONFIG" | awk '{print tolower($2)}')
    if [ "$VALUE" = "no" ]; then
        echo "✔️  HostbasedAuthentication is set to no" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ HostbasedAuthentication is set to $VALUE (expected: no)" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
else
    echo "❌ SSH config file not found" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.3.1 Ensure custom authselect profile is used" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if command -v authselect >/dev/null 2>&1; then
    PROFILE_LINE=$(authselect current 2>/dev/null | grep "Profile ID:")

    if echo "$PROFILE_LINE" | grep -q ": custom/"; then
        echo "✔️  Custom authselect profile is in use: $PROFILE_LINE" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ A default or stock authselect profile is in use: $PROFILE_LINE" >> "$LOG_FILE"
    fi
else
    echo "⚠️  authselect command not found (not applicable)" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.3.2 Ensure correct authselect profile is selected" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if command -v authselect >/dev/null 2>&1; then
    PROFILE=$(authselect current 2>/dev/null | grep "Profile ID:" | awk -F ': ' '{print $2}')

    if [[ "$PROFILE" =~ ^(sssd|custom/sssd|custom/.*sssd.*)$ ]]; then
        echo "✔️  Correct authselect profile is selected: $PROFILE" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ Incorrect or unexpected authselect profile in use: $PROFILE" >> "$LOG_FILE"
    fi
else
    echo "⚠️  authselect command not found (not applicable)" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.3.3 Ensure authselect includes with-faillock" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if command -v authselect >/dev/null 2>&1; then
    FEATURES=$(authselect current 2>/dev/null | grep "Enabled features:")

    if echo "$FEATURES" | grep -qw "with-faillock"; then
        echo "✔️  with-faillock feature is enabled in authselect" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ with-faillock feature is NOT enabled in authselect" >> "$LOG_FILE"
    fi
else
    echo "⚠️  authselect not found (not applicable)" >> "$LOG_FILE"
    RESULT="MANUAL CHECK REQUIRED"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.4.1 Ensure password creation requirements are configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if grep -E '^password\s+requisite\s+pam_pwquality.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null | grep -qE 'retry=[1-5]'; then
    if grep -q '^minlen\s*=\s*[8-9]' /etc/security/pwquality.conf || grep -q '^minlen\s*=\s*[1-9][0-9]' /etc/security/pwquality.conf; then
        echo "✔️  Password complexity (pam_pwquality) is configured with minlen ≥ 8 and retry set" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ pam_pwquality is configured, but minlen < 8 or missing in pwquality.conf" >> "$LOG_FILE"
    fi
else
    echo "❌ pam_pwquality is not properly configured in PAM stack" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.4.2 Ensure lockout for failed password attempts is configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Vérifie la présence de pam_faillock dans system-auth et password-auth
if grep -E 'pam_faillock\.so.*(preauth|authfail)' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null | grep -qvE '^\s*#'; then
    # Vérifie si faillock.conf est bien configuré
    if [ -f /etc/security/faillock.conf ]; then
        DENY=$(grep -E '^deny\s*=' /etc/security/faillock.conf | awk -F= '{print $2}' | tr -d ' ')
        UNLOCK=$(grep -E '^unlock_time\s*=' /etc/security/faillock.conf | awk -F= '{print $2}' | tr -d ' ')

        if [[ "$DENY" -le 5 && "$DENY" -ge 1 ]] && [[ "$UNLOCK" -ge 600 ]]; then
            echo "✔️  pam_faillock is active with deny=$DENY and unlock_time=$UNLOCK" >> "$LOG_FILE"
            RESULT="OK"
        else
            echo "❌ pam_faillock parameters are not compliant (deny=$DENY, unlock_time=$UNLOCK)" >> "$LOG_FILE"
        fi
    else
        echo "❌ /etc/security/faillock.conf not found" >> "$LOG_FILE"
    fi
else
    echo "❌ pam_faillock is not properly configured in PAM stack" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.4.3 Ensure password reuse is limited" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Recherche dans system-auth ou password-auth
PW_HISTORY_LINE=$(grep -E 'password\s+(sufficient|required)\s+pam_pwhistory.so' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null | grep -vE '^\s*#')

if [ -n "$PW_HISTORY_LINE" ]; then
    REMEMBER=$(echo "$PW_HISTORY_LINE" | grep -oE 'remember=[0-9]+' | cut -d= -f2)
    if [ -n "$REMEMBER" ] && [ "$REMEMBER" -ge 5 ]; then
        echo "✔️  pam_pwhistory is configured with remember=$REMEMBER" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ pam_pwhistory is present but remember value is missing or < 5 (value: $REMEMBER)" >> "$LOG_FILE"
    fi
else
    echo "❌ pam_pwhistory is not configured in PAM stack" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.4.4 Ensure password hashing algorithm is SHA-512" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Vérifie dans login.defs
if grep -q "^ENCRYPT_METHOD\s\+SHA512" /etc/login.defs 2>/dev/null; then
    echo "✔️  ENCRYPT_METHOD is set to SHA512 in /etc/login.defs" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ ENCRYPT_METHOD is not set to SHA512 in /etc/login.defs" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.5.1.1 Ensure password expiration is 365 days or less" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Vérifie la valeur par défaut dans /etc/login.defs
PASS_MAX_DAYS=$(grep -E '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}')

if [ -n "$PASS_MAX_DAYS" ] && [ "$PASS_MAX_DAYS" -le 365 ]; then
    echo "✔️  PASS_MAX_DAYS is set to $PASS_MAX_DAYS in /etc/login.defs" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ PASS_MAX_DAYS is not compliant (value: $PASS_MAX_DAYS)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.5.1.2 Ensure minimum days between password changes is 7 or more" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Vérifie la valeur par défaut dans /etc/login.defs
PASS_MIN_DAYS=$(grep -E '^PASS_MIN_DAYS' /etc/login.defs | awk '{print $2}')

if [ -n "$PASS_MIN_DAYS" ] && [ "$PASS_MIN_DAYS" -ge 7 ]; then
    echo "✔️  PASS_MIN_DAYS is set to $PASS_MIN_DAYS in /etc/login.defs" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ PASS_MIN_DAYS is not compliant (value: $PASS_MIN_DAYS)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.5.1.3 Ensure password expiration warning days is 7 or more" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Vérifie la valeur par défaut dans /etc/login.defs
PASS_WARN_AGE=$(grep -E '^PASS_WARN_AGE' /etc/login.defs | awk '{print $2}')

if [ -n "$PASS_WARN_AGE" ] && [ "$PASS_WARN_AGE" -ge 7 ]; then
    echo "✔️  PASS_WARN_AGE is set to $PASS_WARN_AGE in /etc/login.defs" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ PASS_WARN_AGE is not compliant (value: $PASS_WARN_AGE)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.5.1.4 Ensure inactive password lock is 30 days or less" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

INACTIVE_DAYS=$(grep -E '^INACTIVE=' /etc/default/useradd | cut -d= -f2)

if [ -n "$INACTIVE_DAYS" ] && [ "$INACTIVE_DAYS" -ge 0 ] && [ "$INACTIVE_DAYS" -le 30 ]; then
    echo "✔️  INACTIVE is set to $INACTIVE_DAYS in /etc/default/useradd" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ INACTIVE is not compliant (value: $INACTIVE_DAYS)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.5.1.5 Ensure all users last password change date is in the past" >> "$LOG_FILE"
RESULT="OK"

TODAY=$(date +%s)
NON_COMPLIANT_USERS=()

while IFS=: read -r username _ uid _; do
    if [ "$uid" -ge 1000 ] && [ "$username" != "nfsnobody" ]; then
        LAST_CHANGE_DAYS=$(chage --list "$username" 2>/dev/null | grep "Last password change" | cut -d: -f2- | xargs)
        if [ "$LAST_CHANGE_DAYS" = "never" ]; then
            continue
        fi
        LAST_CHANGE_DATE=$(date -d "$LAST_CHANGE_DAYS" +%s 2>/dev/null)
        if [ -n "$LAST_CHANGE_DATE" ] && [ "$LAST_CHANGE_DATE" -gt "$TODAY" ]; then
            NON_COMPLIANT_USERS+=("$username ($LAST_CHANGE_DAYS)")
        fi
    fi
done < /etc/passwd

if [ "${#NON_COMPLIANT_USERS[@]}" -gt 0 ]; then
    echo "❌ Users with future last password change dates:" >> "$LOG_FILE"
    for u in "${NON_COMPLIANT_USERS[@]}"; do
        echo " - $u" >> "$LOG_FILE"
    done
    RESULT="NOT COMPLIANT"
else
    echo "✔️  All users have valid (past) last password change dates" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.5.2 Ensure system accounts are secured (non-login)" >> "$LOG_FILE"
RESULT="OK"

BAD_SHELL_USERS=()

# Liste des comptes système avec UID < 1000 sauf root
while IFS=: read -r user _ uid _ _ _ shell; do
    if [ "$uid" -lt 1000 ] && [ "$user" != "root" ]; then
        if [[ ! "$shell" =~ (nologin|false) ]]; then
            BAD_SHELL_USERS+=("$user ($shell)")
        fi
    fi
done < /etc/passwd

if [ "${#BAD_SHELL_USERS[@]}" -gt 0 ]; then
    echo "❌ Some system accounts have login shells:" >> "$LOG_FILE"
    for u in "${BAD_SHELL_USERS[@]}"; do
        echo " - $u" >> "$LOG_FILE"
    done
    RESULT="NOT COMPLIANT"
else
    echo "✔️  All system accounts are secured with non-login shells" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.5.3 Ensure default user shell timeout is 900 seconds or less" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Recherche TMOUT dans les fichiers de configuration globaux
TIMEOUT_VAL=$(grep -E "^(\s*export\s+)?TMOUT=" /etc/profile /etc/profile.d/* /etc/bashrc 2>/dev/null | \
              grep -vE '^\s*#' | awk -F= '{print $2}' | awk '{print $1}' | sort -n | head -n1)

if [ -n "$TIMEOUT_VAL" ] && [ "$TIMEOUT_VAL" -le 900 ]; then
    echo "✔️  TMOUT is configured to $TIMEOUT_VAL seconds" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ TMOUT is not configured or is greater than 900 seconds (value: ${TIMEOUT_VAL:-unset})" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.5.4 Ensure default group for the root account is GID 0" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

ROOT_GROUP_ID=$(getent passwd root | cut -d: -f4)

if [ "$ROOT_GROUP_ID" -eq 0 ]; then
    echo "✔️  root account has GID 0" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ root account has GID $ROOT_GROUP_ID instead of 0" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.5.5 Ensure default user umask is 027 or more restrictive" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Recherche de la configuration dans /etc/profile*, /etc/bashrc
UMASK_VALUES=$(grep -E '^(\s*umask\s+)' /etc/profile /etc/profile.d/* /etc/bashrc 2>/dev/null | \
               grep -vE '^\s*#' | awk '{print $2}' | sort -u)

for val in $UMASK_VALUES; do
    if [[ "$val" =~ ^0?[0-7]{3}$ ]]; then
        # Vérifie que les permissions groupe et autres sont plus restrictives ou égales à 027
        U=$(echo "$val" | cut -c2)
        G=$(echo "$val" | cut -c3)
        O=$(echo "$val" | cut -c4)
        if [ "$G" -ge 2 ] || [ "$O" -ge 7 ]; then
            echo "❌ Found umask $val which is too permissive" >> "$LOG_FILE"
            RESULT="NOT COMPLIANT"
            break
        else
            echo "✔️  Found compliant umask: $val" >> "$LOG_FILE"
            RESULT="OK"
        fi
    fi
done

if [ -z "$UMASK_VALUES" ]; then
    echo "❌ No default umask setting found in /etc/profile*, /etc/bashrc" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.6 Ensure root login is restricted to system console" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

SECURETTY="/etc/securetty"

if [ -f "$SECURETTY" ]; then
    NON_CONSOLE_LINES=$(grep -vE '^tty[0-9]+$' "$SECURETTY" | grep -vE '^\s*#|^\s*$')
    if [ -z "$NON_CONSOLE_LINES" ]; then
        echo "✔️  /etc/securetty only allows local console TTYs" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ /etc/securetty contains non-console TTY entries:" >> "$LOG_FILE"
        echo "$NON_CONSOLE_LINES" >> "$LOG_FILE"
    fi
else
    echo "❌ /etc/securetty not found. Cannot restrict root login to console." >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 5.7 Ensure access to the su command is restricted to authorized groups" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

# Vérifie que pam_wheel est utilisé avec use_uid et group=wheel
if grep -E '^auth\s+required\s+pam_wheel.so' /etc/pam.d/su 2>/dev/null | grep -qE '\buse_uid\b.*\bgroup=wheel\b|\bgroup=wheel\b.*\buse_uid\b'; then
    echo "✔️  su command is restricted to members of the 'wheel' group via pam_wheel" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ pam_wheel is not properly configured in /etc/pam.d/su" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

#### Warning: Ce test peu prendre beaucoup de temps !!
echo "Auditing: 6.1.10 Ensure no world writable files exist" >> "$LOG_FILE"
RESULT="OK"

WW_FILES=$(find / -xdev -type f -perm -0002 2>/dev/null)

if [ -z "$WW_FILES" ]; then
    echo "✔️  No world-writable files found" >> "$LOG_FILE"
else
    echo "❌ World-writable files found:" >> "$LOG_FILE"
    echo "$WW_FILES" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.11 Ensure no unowned files or directories exist" >> "$LOG_FILE"
RESULT="OK"

UNOWNED=$(find / -xdev -nouser 2>/dev/null)

if [ -z "$UNOWNED" ]; then
    echo "✔️  No unowned files or directories found" >> "$LOG_FILE"
else
    echo "❌ Unowned files or directories found:" >> "$LOG_FILE"
    echo "$UNOWNED" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"




echo "Auditing: 6.1.12 Ensure no ungrouped files or directories exist" >> "$LOG_FILE"
RESULT="OK"

UNGROUPED=$(find / -xdev -nogroup 2>/dev/null)

if [ -z "$UNGROUPED" ]; then
    echo "✔️  No ungrouped files or directories found" >> "$LOG_FILE"
else
    echo "❌ Ungrouped files or directories found:" >> "$LOG_FILE"
    echo "$UNGROUPED" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"




echo "Auditing: 6.1.13 Audit SUID executables" >> "$LOG_FILE"
RESULT="OK"

SUID_FILES=$(find / -xdev -type f -perm -4000 2>/dev/null)

if [ -n "$SUID_FILES" ]; then
    echo "✔️  SUID executables found (audit required):" >> "$LOG_FILE"
    echo "$SUID_FILES" >> "$LOG_FILE"
else
    echo "✔️  No SUID executables found" >> "$LOG_FILE"
fi

echo "Result: OK (Review output manually)" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.14 Audit SGID executables" >> "$LOG_FILE"
RESULT="OK"

SGID_FILES=$(find / -xdev -type f -perm -2000 2>/dev/null)

if [ -n "$SGID_FILES" ]; then
    echo "✔️  SGID executables found (audit required):" >> "$LOG_FILE"
    echo "$SGID_FILES" >> "$LOG_FILE"
else
    echo "✔️  No SGID executables found" >> "$LOG_FILE"
fi

echo "Result: OK (Review output manually)" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.1 Audit system file permissions (AIDE)" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if rpm -q aide >/dev/null 2>&1 || (command -v dpkg >/dev/null 2>&1 && dpkg -l | grep -q "^ii  aide"); then
    if [ -f /var/lib/aide/aide.db.gz ] || [ -f /var/lib/aide/aide.db ]; then
        echo "✔️  AIDE is installed and a database exists" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ AIDE is installed but the database is missing. Run 'aide --init'." >> "$LOG_FILE"
    fi
else
    echo "❌ AIDE is not installed" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.2 Ensure permissions on /etc/passwd are configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

PERM=$(stat -c %a /etc/passwd)
OWNER=$(stat -c %U:%G /etc/passwd)

if [ "$PERM" = "644" ] && [ "$OWNER" = "root:root" ]; then
    echo "✔️  /etc/passwd permissions are correct (644, root:root)" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ /etc/passwd has permissions $PERM and owner $OWNER (expected: 644, root:root)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.3 Ensure permissions on /etc/shadow are configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

PERM=$(stat -c %a /etc/shadow)
OWNER=$(stat -c %U:%G /etc/shadow)

# autoriser 000 ou 640
if { [ "$PERM" = "000" ] || [ "$PERM" = "640" ]; } && [ "$OWNER" = "root:shadow" ]; then
    echo "✔️  /etc/shadow permissions are correct ($PERM, $OWNER)" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ /etc/shadow has permissions $PERM and owner $OWNER (expected: 000 or 640, root:shadow)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.4 Ensure permissions on /etc/group are configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

PERM=$(stat -c %a /etc/group)
OWNER=$(stat -c %U:%G /etc/group)

if [ "$PERM" = "644" ] && [ "$OWNER" = "root:root" ]; then
    echo "✔️  /etc/group permissions are correct (644, root:root)" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ /etc/group has permissions $PERM and owner $OWNER (expected: 644, root:root)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.5 Ensure permissions on /etc/gshadow are configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

PERM=$(stat -c %a /etc/gshadow)
OWNER=$(stat -c %U:%G /etc/gshadow)

if { [ "$PERM" = "000" ] || [ "$PERM" = "640" ]; } && [ "$OWNER" = "root:shadow" ]; then
    echo "✔️  /etc/gshadow permissions are correct ($PERM, $OWNER)" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ /etc/gshadow has permissions $PERM and owner $OWNER (expected: 000 or 640, root:shadow)" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.6 Ensure permissions on /etc/passwd- are configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if [ -f /etc/passwd- ]; then
    PERM=$(stat -c %a /etc/passwd-)
    OWNER=$(stat -c %U:%G /etc/passwd-)

    if [ "$PERM" = "600" ] && [ "$OWNER" = "root:root" ]; then
        echo "✔️  /etc/passwd- permissions are correct (600, root:root)" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ /etc/passwd- has permissions $PERM and owner $OWNER (expected: 600, root:root)" >> "$LOG_FILE"
    fi
else
    echo "❌ /etc/passwd- file not found" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.7 Ensure permissions on /etc/shadow- are configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if [ -f /etc/shadow- ]; then
    PERM=$(stat -c %a /etc/shadow-)
    OWNER=$(stat -c %U:%G /etc/shadow-)

    if { [ "$PERM" = "000" ] || [ "$PERM" = "640" ]; } && [ "$OWNER" = "root:shadow" ]; then
        echo "✔️  /etc/shadow- permissions are correct ($PERM, root:shadow)" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ /etc/shadow- has permissions $PERM and owner $OWNER (expected: 000 or 640, root:shadow)" >> "$LOG_FILE"
    fi
else
    echo "❌ /etc/shadow- file not found" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.8 Ensure permissions on /etc/group- are configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if [ -f /etc/group- ]; then
    PERM=$(stat -c %a /etc/group-)
    OWNER=$(stat -c %U:%G /etc/group-)

    if [ "$PERM" = "600" ] && [ "$OWNER" = "root:root" ]; then
        echo "✔️  /etc/group- permissions are correct (600, root:root)" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ /etc/group- has permissions $PERM and owner $OWNER (expected: 600, root:root)" >> "$LOG_FILE"
    fi
else
    echo "❌ /etc/group- file not found" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.1.9 Ensure permissions on /etc/gshadow- are configured" >> "$LOG_FILE"
RESULT="NOT COMPLIANT"

if [ -f /etc/gshadow- ]; then
    PERM=$(stat -c %a /etc/gshadow-)
    OWNER=$(stat -c %U:%G /etc/gshadow-)

    if { [ "$PERM" = "000" ] || [ "$PERM" = "640" ]; } && [ "$OWNER" = "root:shadow" ]; then
        echo "✔️  /etc/gshadow- permissions are correct ($PERM, root:shadow)" >> "$LOG_FILE"
        RESULT="OK"
    else
        echo "❌ /etc/gshadow- has permissions $PERM and owner $OWNER (expected: 000 or 640, root:shadow)" >> "$LOG_FILE"
    fi
else
    echo "❌ /etc/gshadow- file not found" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.2.10 Ensure no users have .forward files" >> "$LOG_FILE"
FOUND=$(find /home -name '.forward' 2>/dev/null)
if [ -z "$FOUND" ]; then
    echo "✔️  No user has a .forward file" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ The following users have a .forward file:" >> "$LOG_FILE"
    echo "$FOUND" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"
echo "Auditing: 6.2.11 Ensure no users have .netrc files" >> "$LOG_FILE"
FOUND=$(find /home -name '.netrc' 2>/dev/null)
if [ -z "$FOUND" ]; then
    echo "✔️  No user has a .netrc file" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ The following users have a .netrc file:" >> "$LOG_FILE"
    echo "$FOUND" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"
echo "Auditing: 6.2.12 Ensure users .netrc Files are not group or world accessible" >> "$LOG_FILE"
BAD_PERMS=$(find /home -name '.netrc' -perm /027 -exec ls -l {} \; 2>/dev/null)
if [ -z "$BAD_PERMS" ]; then
    echo "✔️  All .netrc files are not group/world accessible" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ Some .netrc files are too permissive:" >> "$LOG_FILE"
    echo "$BAD_PERMS" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"
echo "Auditing: 6.2.13 Ensure no users have .rhosts files" >> "$LOG_FILE"
FOUND=$(find /home -name '.rhosts' 2>/dev/null)
if [ -z "$FOUND" ]; then
    echo "✔️  No user has a .rhosts file" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ The following users have a .rhosts file:" >> "$LOG_FILE"
    echo "$FOUND" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"
echo "Auditing: 6.2.14 Ensure all groups in /etc/passwd exist in /etc/group" >> "$LOG_FILE"
MISSING_GROUPS=$(cut -d: -f4 /etc/passwd | grep -v '^$' | while read gid; do
    grep -q ":\*\?:\*\?:$gid:" /etc/group || echo "$gid"
done)
if [ -z "$MISSING_GROUPS" ]; then
    echo "✔️  All groups in /etc/passwd exist in /etc/group" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ The following GIDs are missing in /etc/group:" >> "$LOG_FILE"
    echo "$MISSING_GROUPS" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"
echo "Auditing: 6.2.15 Ensure no duplicate UIDs exist" >> "$LOG_FILE"
DUPES=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
if [ -z "$DUPES" ]; then
    echo "✔️  No duplicate UIDs found" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ Duplicate UIDs found:" >> "$LOG_FILE"
    echo "$DUPES" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"
echo "Auditing: 6.2.16 Ensure no duplicate GIDs exist" >> "$LOG_FILE"
DUPES=$(cut -d: -f3 /etc/group | sort | uniq -d)
if [ -z "$DUPES" ]; then
    echo "✔️  No duplicate GIDs found" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ Duplicate GIDs found:" >> "$LOG_FILE"
    echo "$DUPES" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"
echo "Auditing: 6.2.17 Ensure no duplicate user names exist" >> "$LOG_FILE"
DUPES=$(cut -d: -f1 /etc/passwd | sort | uniq -d)
if [ -z "$DUPES" ]; then
    echo "✔️  No duplicate usernames found" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ Duplicate usernames found:" >> "$LOG_FILE"
    echo "$DUPES" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"
echo "Auditing: 6.2.18 Ensure no duplicate group names exist" >> "$LOG_FILE"
DUPES=$(cut -d: -f1 /etc/group | sort | uniq -d)
if [ -z "$DUPES" ]; then
    echo "✔️  No duplicate group names found" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ Duplicate group names found:" >> "$LOG_FILE"
    echo "$DUPES" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"
echo "Auditing: 6.2.19 Ensure shadow group is empty" >> "$LOG_FILE"
SHADOW_USERS=$(getent group shadow | awk -F: '{print $4}')
if [ -z "$SHADOW_USERS" ]; then
    echo "✔️  shadow group is empty" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ shadow group is not empty: $SHADOW_USERS" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"
echo "Auditing: 6.2.20 Ensure all users home directories exist" >> "$LOG_FILE"
MISSING_DIRS=$(awk -F: '{ if ($7 != "/sbin/nologin" && $7 != "/usr/sbin/nologin" && $6 != "" && $1 != "nobody" && !system("test -d " $6)) print $1 ": " $6 }' /etc/passwd)
if [ -z "$MISSING_DIRS" ]; then
    echo "✔️  All users have home directories" >> "$LOG_FILE"
    RESULT="OK"
else
    echo "❌ Some users lack home directories:" >> "$LOG_FILE"
    echo "$MISSING_DIRS" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 6.2.2 Ensure no legacy '+' entries exist in /etc/passwd" >> "$LOG_FILE"
RESULT="OK"

if grep -q '^\+:' /etc/passwd; then
    echo "❌ Legacy '+' entry found in /etc/passwd" >> "$LOG_FILE"
    grep '^\+:' /etc/passwd >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  No legacy '+' entries found in /etc/passwd" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


########### Bloc à optimiser ?
echo "Auditing: 6.2.3 Ensure root PATH Integrity" >> "$LOG_FILE"
RESULT="OK"

ROOT_PATH=$(su - root -c 'echo $PATH')
IFS=':' read -ra PATH_DIRS <<< "$ROOT_PATH"

for dir in "${PATH_DIRS[@]}"; do
    if [ -z "$dir" ]; then
        echo "❌ Empty directory entry (i.e., ::) found in PATH" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    elif [ "$dir" = "." ]; then
        echo "❌ PATH contains '.' which is insecure" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    elif [ ! -d "$dir" ]; then
        echo "❌ PATH contains non-existent directory: $dir" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    elif [ "$(stat -c %a "$dir" 2>/dev/null)" -ge 777 ]; then
        echo "❌ PATH directory $dir is world-writable" >> "$LOG_FILE"
        RESULT="NOT COMPLIANT"
    fi
done

if [ "$RESULT" = "OK" ]; then
    echo "✔️  Root PATH does not contain empty, '.', non-existent or world-writable directories" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

###########

echo "Auditing: 6.2.4 Ensure no legacy '+' entries exist in /etc/shadow" >> "$LOG_FILE"
RESULT="OK"

if grep -q '^\+:' /etc/shadow; then
    echo "❌ Legacy '+' entry found in /etc/shadow" >> "$LOG_FILE"
    grep '^\+:' /etc/shadow >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  No legacy '+' entries found in /etc/shadow" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.2.5 Ensure no legacy '+' entries exist in /etc/group" >> "$LOG_FILE"
RESULT="OK"

if grep -q '^\+:' /etc/group; then
    echo "❌ Legacy '+' entry found in /etc/group" >> "$LOG_FILE"
    grep '^\+:' /etc/group >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
else
    echo "✔️  No legacy '+' entries found in /etc/group" >> "$LOG_FILE"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.2.6 Ensure root is the only UID 0 account" >> "$LOG_FILE"
RESULT="OK"

UID_0_USERS=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)

if [ "$UID_0_USERS" = "root" ]; then
    echo "✔️  Only 'root' has UID 0" >> "$LOG_FILE"
else
    echo "❌ Multiple UID 0 accounts found:" >> "$LOG_FILE"
    echo "$UID_0_USERS" >> "$LOG_FILE"
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.2.7 Ensure users home directories permissions are 750 or more restrictive" >> "$LOG_FILE"
RESULT="OK"

NON_COMPLIANT_DIRS=()

# Vérifie tous les comptes utilisateurs UID >= 1000 (hors system users)
awk -F: '($3 >= 1000 && $1 != "nfsnobody") {print $1 ":" $6}' /etc/passwd | while IFS=: read -r user homedir; do
    if [ -d "$homedir" ]; then
        PERM=$(stat -c %a "$homedir")
        if [ "$PERM" -gt 750 ]; then
            NON_COMPLIANT_DIRS+=("$user ($homedir, $PERM)")
        fi
    fi
done

if [ "${#NON_COMPLIANT_DIRS[@]}" -eq 0 ]; then
    echo "✔️  All user home directories have permissions 750 or more restrictive" >> "$LOG_FILE"
else
    echo "❌ The following user home directories have overly permissive permissions:" >> "$LOG_FILE"
    for entry in "${NON_COMPLIANT_DIRS[@]}"; do
        echo " - $entry" >> "$LOG_FILE"
    done
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.2.8 Ensure users own their home directories" >> "$LOG_FILE"
RESULT="OK"

BAD_OWNERSHIP=()

# Vérifie tous les comptes utilisateurs UID >= 1000 (hors system users)
awk -F: '($3 >= 1000 && $1 != "nfsnobody") {print $1 ":" $3 ":" $6}' /etc/passwd | while IFS=: read -r user uid homedir; do
    if [ -d "$homedir" ]; then
        OWNER_UID=$(stat -c %u "$homedir")
        if [ "$OWNER_UID" -ne "$uid" ]; then
            BAD_OWNERSHIP+=("$user ($homedir is owned by UID $OWNER_UID instead of $uid)")
        fi
    fi
done

if [ "${#BAD_OWNERSHIP[@]}" -eq 0 ]; then
    echo "✔️  All users own their home directories" >> "$LOG_FILE"
else
    echo "❌ The following home directories are not owned by their users:" >> "$LOG_FILE"
    for entry in "${BAD_OWNERSHIP[@]}"; do
        echo " - $entry" >> "$LOG_FILE"
    done
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


echo "Auditing: 6.2.9 Ensure users dot files are not group or world writable" >> "$LOG_FILE"
RESULT="OK"

BAD_DOT_FILES=()

awk -F: '($3 >= 1000 && $1 != "nfsnobody") {print $1 ":" $6}' /etc/passwd | while IFS=: read -r user home; do
    if [ -d "$home" ]; then
        find "$home" -maxdepth 1 -type f -name ".*" \( -perm -002 -o -perm -020 \) 2>/dev/null | while read -r file; do
            BAD_DOT_FILES+=("$user owns writable dot file: $file")
        done
    fi
done

if [ "${#BAD_DOT_FILES[@]}" -eq 0 ]; then
    echo "✔️  No user dot files are group or world writable" >> "$LOG_FILE"
else
    echo "❌ Writable dot files found in user home directories:" >> "$LOG_FILE"
    for entry in "${BAD_DOT_FILES[@]}"; do
        echo " - $entry" >> "$LOG_FILE"
    done
    RESULT="NOT COMPLIANT"
fi

echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"


###########################################################################################################
# Génération du rapport final - Formats CSV et HTML
###########################################################################################################

# Génération des rapports CSV/HTML (robuste) avec colonne Exception
CSV_REPORT="cis_audit_report_$(hostname -f)_$(date +%F).csv"
HTML_REPORT="cis_audit_report_$(hostname -f)_$(date +%F).html"

# Répertoire des fichiers d'exception : /cis/cis-<control>.txt (ex: /cis/cis-1.1.10.txt)
EXC_DIR="${EXC_DIR:-/cis}"

# Extraire libellés et résultats depuis le log
grep '^Auditing:' "$LOG_FILE" | cut -d':' -f2- > /tmp/tmp_audit_descs
grep '^Result:'   "$LOG_FILE" | cut -d':' -f2- > /tmp/tmp_audit_results

# Construire les colonnes ID + Exception à partir des IDs (premier token du champ 'Check')
> /tmp/tmp_audit_exceptions
> /tmp/tmp_audit_ids
while IFS= read -r check; do
  # Trim leading/trailing whitespace
  check="${check#${check%%[![:space:]]*}}"; check="${check%${check##*[![:space:]]}}"
  cid="${check%% *}"                         # ex: 1.1.10
  printf '%s\n' "$cid" >> /tmp/tmp_audit_ids

  exc_file="${EXC_DIR}/cis-${cid}.txt"
  if [[ -s "$exc_file" ]]; then
    exc="$(head -c 4000 "$exc_file")"
    if [[ $(wc -c < "$exc_file") -gt 4000 ]]; then
      exc="${exc} … (tronqué)"
    fi
  else
    exc=""
  fi
  printf '%s\n' "$exc" >> /tmp/tmp_audit_exceptions
done < /tmp/tmp_audit_descs

# Utiliser un séparateur sûr (Unit Separator) pour assembler les colonnes sans conflit avec les virgules
DEL=$'\x1f'
paste -d "$DEL" /tmp/tmp_audit_ids /tmp/tmp_audit_descs /tmp/tmp_audit_results /tmp/tmp_audit_exceptions > /tmp/tmp_joined_cis

# -- Générer le CSV avec quoting correct --
{
  echo "ID,Check,Result,Exception"
  while IFS=$'\x1f' read -r cid check result exc; do
    # Trim
    check="${check#"${check%%[![:space:]]*}"}"; check="${check%"${check##*[![:space:]]}"}"
    result="${result#"${result%%[![:space:]]*}"}"; result="${result%"${result##*[![:space:]]}"}"
    # Escape CSV quotes
    esc() { printf '%s' "$1" | sed 's/"/""/g'; }
    printf "\"%s\",\"%s\",\"%s\",\"%s\"\n" "$(esc "$cid")" "$(esc "$check")" "$(esc "$result")" "$(esc "$exc")"
  done < /tmp/tmp_joined_cis
} > "$CSV_REPORT"

# -- Générer le HTML (avec badge Exception) --
{
  cat <<HTML_HEAD
<!DOCTYPE html>
<html lang="fr"><head>
<meta charset="utf-8"/>
<title>CIS Audit Report</title>
<style>
table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:8px;vertical-align:top}
th{background:#f5f5f5}
.excbadge{display:inline-block;padding:2px 6px;border-radius:10px;font-size:12px;font-weight:600;background:#fff3cd;border:1px solid #ffeeba;color:#856404;margin-bottom:4px}
.exc{background:#fff8e1}
.pre{white-space:pre-wrap;margin:0}
</style>
</head><body>
<h2>CIS Audit Report for host $(hostname -f)</h2>
<table><tr><th>ID</th><th>Check</th><th>Result</th><th>Exception</th></tr>
HTML_HEAD
  awk -v FS="$DEL" '
    function htmlesc(s){ gsub(/&/,"&amp;",s); gsub(/</,"&lt;",s); gsub(/>/,"&gt;",s); return s }
    {
      cid=$1; check=$2; result=$3; exc=$4;
      badge = (length(exc)>0 ? "<div class=\"excbadge\">EXCEPTION</div><br/>" : "");
      cellc = (length(exc)>0 ? " class=\"exc\"" : "");
      print "<tr><td>" htmlesc(cid) "</td><td>" htmlesc(check) "</td><td>" htmlesc(result) "</td><td" cellc ">" badge "<pre class=\"pre\">" htmlesc(exc) "</pre></td></tr>";
    }
  ' /tmp/tmp_joined_cis
  cat <<'HTML_TAIL'
</table></body></html>
HTML_TAIL
} > "$HTML_REPORT"

# Nettoyage
rm -f /tmp/tmp_audit_descs /tmp/tmp_audit_results /tmp/tmp_audit_exceptions /tmp/tmp_audit_ids /tmp/tmp_joined_cis
