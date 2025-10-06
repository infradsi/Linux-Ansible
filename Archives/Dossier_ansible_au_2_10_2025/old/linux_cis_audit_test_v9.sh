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
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.11 Ensure system-wide crypto policy is FUTURE or FIPS" >> "$LOG_FILE"
RESULT=$([ -f /etc/crypto-policies/config ] && grep -Eq 'FUTURE|FIPS' /etc/crypto-policies/config && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.20 Ensure noexec option set on removable media partitions" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
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
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.6 Ensure separate partition exists for /var" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.1.7 Ensure separate partition exists for /var/tmp" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.2.1 Ensure Red Hat Subscription Manager connection is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.2.2 Disable the rhnsd Daemon" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.2.3 Ensure GPG keys are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.2.4 Ensure gpgcheck is globally activated" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.2.5 Ensure package manager repositories are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
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
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.4.1 Ensure AIDE is installed" >> "$LOG_FILE"
RESULT=$(command -v aide >/dev/null && echo OK || echo NOT COMPLIANT)
echo "Result: $RESULT" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.4.2 Ensure filesystem integrity is regularly checked" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.5.1 Ensure permissions on bootloader config are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.5.2 Ensure bootloader password is set" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.5.3 Ensure authentication required for single user mode" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.6.1 Ensure core dumps are restricted" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.6.2 Ensure address space layout randomization (ASLR) is enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.7.1.1 Ensure SELinux is installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.7.1.2 Ensure SELinux is not disabled in bootloader configuration" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.7.1.3 Ensure SELinux policy is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.7.1.4 Ensure the SELinux state is enforcing" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.7.1.5 Ensure no unconfined services exist" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.7.1.6 Ensure SETroubleshoot is not installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.7.1.7 Ensure the MCS Translation Service (mcstrans) is not installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.8.1.1 Ensure message of the day is configured properly" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.8.1.2 Ensure local login warning banner is configured properly" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.8.1.3 Ensure remote login warning banner is configured properly" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.8.1.4 Ensure permissions on /etc/motd are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.8.1.5 Ensure permissions on /etc/issue are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.8.1.6 Ensure permissions on /etc/issue.net are configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.8.2 Ensure GDM login banner is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 1.9 Ensure updates, patches, and additional security software are installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.1.1 Ensure xinetd is not installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.10 Ensure FTP Server is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.1.1 Ensure time synchronization is in use" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: Ensure chrony is configured" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: servers should be tic & toc" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.11 Ensure DNS Server is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.12 Ensure NFS is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.13 Ensure RPC is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.14 Ensure LDAP server is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.15 Ensure DHCP Server is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.16 Ensure CUPS is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.17 Ensure NIS Server is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.18 Ensure mail transfer agent is configured for local-only mode" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.2 Ensure X Window System is not installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.3 Ensure rsync service is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.4 Ensure Avahi Server is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.5 Ensure SNMP Server is not enabled (if monitoring not required)" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.6 Ensure HTTP Proxy Server is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.7 Ensure Samba is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.8 Ensure IMAP and POP3 server is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.2.9 Ensure HTTP server is not enabled (if not web server)" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.3.1 Ensure NIS Client is not installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.3.2 Ensure telnet client is not installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 2.3.3 Ensure LDAP client is not installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.1.1 Ensure IP forwarding is disabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.1.2 Ensure packet redirect sending is disabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.2.1 Ensure source routed packets are not accepted" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.2.2 Ensure ICMP redirects are not accepted" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.2.3 Ensure secure ICMP redirects are not accepted" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.2.4 Ensure suspicious packets are logged" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.2.5 Ensure broadcast ICMP requests are ignored" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.2.6 Ensure bogus ICMP responses are ignored" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.2.7 Ensure Reverse Path Filtering is enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.2.8 Ensure TCP SYN Cookies is enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.2.9 Ensure IPv6 router advertisements are not accepted" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.3.1 Ensure DCCP is disabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.3.2 Ensure SCTP is disabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.3.3 Ensure RDS is disabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.3.4 Ensure TIPC is disabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.1.1 Ensure a Firewall package is installed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.2.1 Ensure firewalld service is enabled and running" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.2.2 Ensure iptables is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.2.3 Ensure nftables is not enabled" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.2.4 Ensure default zone is set" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.2.5 Ensure network interfaces are assigned to appropriate zone" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.2.6 Ensure unnecessary services and ports are not accepted" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

echo "Auditing: 3.4.3.1 Ensure iptables are flushed" >> "$LOG_FILE"
echo "Result: [MANUAL CHECK REQUIRED]" >> "$LOG_FILE"
echo "-----------------------------------------" >> "$LOG_FILE"

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