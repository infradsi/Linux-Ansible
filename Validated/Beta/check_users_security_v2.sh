#!/bin/bash

CSV_REPORT="user_account_audit.csv"
HTML_REPORT="user_account_audit.html"

# Prepare CSV/HTML header
echo "Username,UID,Shell,MinPasswordAge,MaxPasswordAge,InactiveDays,InteractiveShell,PasswordComplexity,UserType,ComplianceSummary" > "$CSV_REPORT"

cat <<EOF > "$HTML_REPORT"
<html>
<head>
<title>User Account Audit Report</title>
<style>
table { border-collapse: collapse; width: 100%; }
th, td { border: 1px solid #ccc; padding: 6px; }
th { background-color: #f2f2f2; }
.ok { color: green; }
.warn { color: red; font-weight: bold; }
</style>
</head>
<body>
<h2>User Account Audit Report ($(hostname -f))</h2>
<table>
<tr>
  <th>Username</th>
  <th>UID</th>
  <th>Shell</th>
  <th>MinPwdAge</th>
  <th>MaxPwdAge</th>
  <th>InactiveDays</th>
  <th>InteractiveShell</th>
  <th>PasswordComplexity</th>
  <th>UserType</th>
  <th>Compliance</th>
</tr>
EOF

# 4. Check password complexity (PAM pwquality/cracklib)
COMPLEXITY_STATUS=""
PAM_FILE="/etc/security/pwquality.conf"
PAM_PWQUALITY=$(grep -E "pam_pwquality|pam_cracklib" /etc/pam.d/system-auth /etc/pam.d/common-password 2>/dev/null)
PWQUALITY_CONF=$(grep -vE '^\s*#' $PAM_FILE 2>/dev/null | grep -E "minlen|dcredit|ucredit|lcredit|ocredit")
if [ -n "$PAM_PWQUALITY" ]; then
    if [ -n "$PWQUALITY_CONF" ]; then
        COMPLEXITY_STATUS="OK"
    else
        COMPLEXITY_STATUS="PARTIAL"
    fi
else
    COMPLEXITY_STATUS="NOT_SET"
fi

# 3. Checking default useradd inactivity
USERADD_DEF=$(grep INACTIVE /etc/default/useradd | cut -d= -f2)
[ -z "$USERADD_DEF" ] && USERADD_DEF="NOT_SET"

while IFS=: read -r user _ uid gid _ home shell; do
    if [ "$uid" -ge 1000 ] || { [ "$uid" -ge 100 ] && [ "$uid" -lt 1000 ]; }; then
        aging_info=$(chage -l "$user")
        minage=$(echo "$aging_info" | awk -F': ' '/Minimum/ {print $2}')
        maxage=$(echo "$aging_info" | awk -F': ' '/Maximum/ {print $2}')
        inactivedays=$(echo "$aging_info" | awk -F': ' '/Inactive/ {print $2}')
        [ "$minage" == "never" ] && minage="0"
        [ "$maxage" == "never" ] && maxage="NOT_SET"
        [ "$inactivedays" == "never" ] && inactivedays="NOT_SET"
        is_interactive="NO"
        compliance="OK"
        usertype=""

        # Check if user is a regular user or service account
        if [ "$uid" -ge 1000 ]; then
            usertype="Regular"
            # Compliance checks
            [[ "$minage" == "0" ]] && { compliance="MinPwdAge_NOT_SET"; }
            [[ "$maxage" == "NOT_SET" ]] && { compliance="$compliance MaxPwdAge_NOT_SET"; }
            [[ "$inactivedays" == "NOT_SET" || "$inactivedays" -gt 90 ]] && { compliance="$compliance InactiveDays>90"; }
            [[ ! "$shell" =~ (nologin|false) ]] && is_interactive="YES"
        else
            usertype="Service"
            [[ ! "$shell" =~ (nologin|false) ]] && { compliance="ServiceAccount_InteractiveShell"; is_interactive="YES"; }
        fi
        # Password complexity
        case "$COMPLEXITY_STATUS" in
            OK) pcomplex="OK" ;;
            PARTIAL) pcomplex="Partial" ;;
            *) pcomplex="NOT_SET" ;;
        esac
        [[ "$compliance" == "OK" && "$pcomplex" == "OK" ]] && compliance="OK"

        # CSV row
        echo "$user,$uid,$shell,$minage,$maxage,$inactivedays,$is_interactive,$pcomplex,$usertype,\"$compliance\"" >> "$CSV_REPORT"

        # HTML row
        html_class="ok"
        [[ "$compliance" != "OK" ]] && html_class="warn"
        echo "<tr class=\"$html_class\"><td>$user</td><td>$uid</td><td>$shell</td><td>$minage</td><td>$maxage</td><td>$inactivedays</td><td>$is_interactive</td><td>$pcomplex</td><td>$usertype</td><td>$compliance</td></tr>" >> "$HTML_REPORT"
    fi
done < /etc/passwd

echo "</table><br>" >> "$HTML_REPORT"
echo "<b>Global password inactivity default (useradd):</b> $USERADD_DEF<br>" >> "$HTML_REPORT"
echo "<b>Password complexity PAM status:</b> $COMPLEXITY_STATUS<br>" >> "$HTML_REPORT"
if [ "$COMPLEXITY_STATUS" == "OK" ]; then
    echo "<pre>$(echo "$PWQUALITY_CONF")</pre>" >> "$HTML_REPORT"
fi
echo "<hr><i>Report generated on $(date)</i></body></html>" >> "$HTML_REPORT"

echo "CSV report: $CSV_REPORT"
echo "HTML report: $HTML_REPORT"
