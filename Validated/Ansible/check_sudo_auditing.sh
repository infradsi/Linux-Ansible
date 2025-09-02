#!/bin/bash

echo "=== Checking sudo logging and auditing status ==="

# 1. Check if sudo logs exist in common log files
echo -e "\n[1] Searching for sudo entries in log files..."

if grep -q "sudo" /var/log/auth.log 2>/dev/null; then
    echo "✅ Found sudo activity in /var/log/auth.log"
elif grep -q "sudo" /var/log/secure 2>/dev/null; then
    echo "✅ Found sudo activity in /var/log/secure"
else
    echo "⚠️  No sudo activity found in /var/log/auth.log or /var/log/secure"
fi

# 2. Check if journalctl logs sudo activity
echo -e "\n[2] Checking journalctl logs for sudo..."

if journalctl _COMM=sudo | grep -q "COMMAND="; then
    echo "✅ journalctl is logging sudo commands"
else
    echo "⚠️  journalctl does not show sudo command activity"
fi

# 3. Check if auditd is installed and running
echo -e "\n[3] Checking auditd status..."

if systemctl is-active --quiet auditd; then
    echo "✅ auditd is active"
else
    echo "⚠️  auditd is not active"
fi

# 4. Check audit rules for sudo usage
echo -e "\n[4] Checking audit rules for sudo usage..."

if auditctl -l | grep -q "/usr/bin/sudo"; then
    echo "✅ Audit rule exists for /usr/bin/sudo"
else
    echo "⚠️  No audit rule found for /usr/bin/sudo"
    echo "➡️  You can add it with: auditctl -a always,exit -F path=/usr/bin/sudo -F perm=x -k sudo"
fi

# Summary
echo -e "\n=== Summary ==="
echo "✅ means logging/auditing is in place"
echo "⚠️  means sudo actions may not be audited properly"


