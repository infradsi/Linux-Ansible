#!/bin/bash
# Script: check_root_usage_html.sh
# Purpose: Perform root usage audit and generate HTML report

hostname=$(hostname)
timestamp=$(date "+%Y-%m-%d %H:%M:%S")
report="/ansible-tmp/root_audit_${hostname}_$(date +%Y%m%d_%H%M%S).html"

# Start HTML
cat <<EOF > "$report"
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Linux Root Audit Report - $hostname</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #333; }
        pre { background-color: #f4f4f4; padding: 10px; border-left: 4px solid #ccc; overflow-x: auto; }
        .pass { color: green; }
        .fail { color: red; }
        .warn { color: orange; }
    </style>
</head>
<body>
    <h1>Linux Root Account Audit Report</h1>
    <p><strong>Host:</strong> $hostname</p>
    <p><strong>Date:</strong> $timestamp</p>
EOF

## 1. SSHD PermitRootLogin
echo "[1] Checking SSH root login policy..."
sshd_conf="/etc/ssh/sshd_config"
if grep -q "^PermitRootLogin no" "$sshd_conf"; then
    status="<span class='pass'>✔️ SSH root login is disabled.</span>"
else
    status="<span class='fail'>❌ SSH root login is NOT disabled!</span>"
fi
echo "<h2>1. SSH Root Login Policy</h2><p>$status</p>" >> "$report"

## 2. Root password aging policy
echo "[2] Checking root password aging policy..."
echo "<h2>2. Root Password Aging Policy</h2>" >> "$report"
chage_output=$(chage -l root)
echo "<pre>$chage_output</pre>" >> "$report"

max_age=$(echo "$chage_output" | grep "Maximum" | awk '{print $NF}')
if [[ "$max_age" -gt 90 ]]; then
    echo "<p class='fail'>❌ Root password max age is more than 90 days!</p>" >> "$report"
else
    echo "<p class='pass'>✔️ Root password aging policy is acceptable.</p>" >> "$report"
fi

## 3. Console-only login
echo "[3] Checking securetty..."
echo "<h2>3. Console-only Root Login (/etc/securetty)</h2>" >> "$report"
if [ -e /etc/securetty ]; then
    echo "<p class='pass'>✔️ /etc/securetty exists. Root login restricted to listed TTYs:</p>" >> "$report"
    echo "<pre>$(cat /etc/securetty)</pre>" >> "$report"
else
    echo "<p class='fail'>❌ /etc/securetty is missing. Root login is not restricted to console!</p>" >> "$report"
fi

## 4. Direct root logins
echo "[4] Checking direct root logins..."
echo "<h2>4. Direct Root Logins (last 10)</h2>" >> "$report"
logins=$(last -w | grep -E '^root\s' | head -n 10)
if [[ -z "$logins" ]]; then
    echo "<p class='pass'>✔️ No direct root logins found in recent history.</p>" >> "$report"
else
    echo "<p class='warn'>⚠️ Direct root logins detected:</p><pre>$logins</pre>" >> "$report"
fi

## 5. sudo/su usage
echo "[5] Checking sudo/su usage..."
echo "<h2>5. Admin Sudo/Su Usage</h2>" >> "$report"
logs=""
for log_file in /var/log/auth.log /var/log/secure; do
    if [ -f "$log_file" ]; then
        logs="${logs}$(grep -E 'sudo|su' \"$log_file\" | tail -n 20)\n"
    fi
done

if [[ -n "$logs" ]]; then
    echo "<pre>$logs</pre>" >> "$report"
else
    echo "<p class='warn'>⚠️ Could not find sudo/su logs. Check log configuration or permissions.</p>" >> "$report"
fi

## 6. UID 0 accounts
echo "[6] Checking for shared UID 0 accounts..."
echo "<h2>6. Shared UID 0 Accounts</h2>" >> "$report"
uid0=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
uid0_count=$(echo "$uid0" | wc -l)

if [[ "$uid0_count" -gt 1 ]]; then
    echo "<p class='fail'>❌ Multiple accounts with UID 0 detected:</p><pre>$uid0</pre>" >> "$report"
else
    echo "<p class='pass'>✔️ Only root has UID 0.</p>" >> "$report"
fi

# End HTML
echo "<h2>✅ Audit Completed</h2>" >> "$report"
echo "</body></html>" >> "$report"

echo "✔️ HTML report generated: $report"

echo "$report"
