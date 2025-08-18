#!/usr/bin/env bash
# find_unused_accounts.sh
# List local login-capable accounts unused for more than N days.
# Works on RHEL/CentOS/Alma/Rocky/Ubuntu/Debian.

# Script to get unused logings on Linux Systems
# By defaults return accounts (with shell) not logged in for more than 90 days



set -o errexit
set -o nounset
set -o pipefail

DAYS=90
CSV_OUT=""
INCLUDE_NONINTERACTIVE=0      # 0 = only real shells; 1 = include nologin/false
SKIP_USERS="root"             # comma-separated usernames to exclude

usage() {
  cat <<EOF
Usage: $(basename "$0") [-d DAYS] [-o /path/report.csv] [-m MIN_UID] [-i] [-s user1,user2]
  -d DAYS     Threshold in days (default: 90)
  -o FILE     Also write results to CSV file
  -m MIN_UID  Minimum UID to consider (default: from /etc/login.defs or 1000)
  -i          Include non-interactive shells (nologin/false) too
  -s LIST     Comma-separated usernames to exclude (default: root)
EOF
}

# Defaults
MIN_UID="$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs 2>/dev/null || echo 1000)"

while getopts ":d:o:m:is:h" opt; do
  case "$opt" in
    d) DAYS="$OPTARG" ;;
    o) CSV_OUT="$OPTARG" ;;
    m) MIN_UID="$OPTARG" ;;
    i) INCLUDE_NONINTERACTIVE=1 ;;
    s) SKIP_USERS="$OPTARG" ;;
    h|\?) usage; exit 0 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (needed to read shadow/chage for all users)." >&2
  exit 1
fi

# Helpers
IFS=',' read -r -a _SKIPS <<< "$SKIP_USERS"
is_skipped() {
  local u="$1"
  for s in "${_SKIPS[@]}"; do [[ "$u" == "$s" ]] && return 0; done
  return 1
}

is_interactive_shell() {
  local sh="$1"
  [[ $INCLUDE_NONINTERACTIVE -eq 1 ]] && return 0
  case "$sh" in
    */nologin|*/false|*/sync|*/shutdown|*/halt) return 1 ;;
    *) return 0 ;;
  esac
}

to_epoch() {
  # Convert a date string to epoch seconds; return 0 on failure.
  local d="$1"
  [[ -z "$d" ]] && { echo 0; return; }
  date -d "$d" +%s 2>/dev/null || echo 0
}

last_login_epoch() {
  local u="$1"
  # Force C locale for predictable month/day names
  local line
  line="$(LC_ALL=C lastlog -u "$u" 2>/dev/null | tail -n 1 || true)"
  [[ -z "$line" ]] && { echo 0; return; }
  if grep -q "Never logged in" <<<"$line"; then
    echo 0; return
  fi
  # Take the last 6 fields (e.g., Mon Aug  9 12:34:56 +0200 2021)
  local dstr
  dstr="$(awk '{if (NF>=6){for (i=NF-5;i<=NF;i++) printf "%s ", $i}}' <<<"$line")"
  to_epoch "$dstr"
}

last_pass_change_epoch() {
  local u="$1"
  local dstr
  dstr="$(LC_ALL=C chage -l "$u" 2>/dev/null | awk -F': ' '/Last password change/{print $2}')"
  [[ -z "$dstr" ]] && { echo 0; return; }
  [[ "$dstr" =~ [Nn]ever ]] && { echo 0; return; }
  to_epoch "$dstr"
}

now_epoch() { date +%s; }

print_header() {
  printf "%-20s %-6s %-6s %-10s %-10s %-28s %-28s %-6s %-18s\n" \
    "USER" "UID" "GID" "THRESH" "DAYS" "LAST_LOGIN" "LAST_PASS_CHANGE" "STAT" "SHELL"
}

print_row() {
  local user="$1" uid="$2" gid="$3" days="$4" last_login="$5" last_pass="$6" status="$7" shell="$8" thr="$9"
  printf "%-20s %-6s %-6s %-10s %-10s %-28s %-28s %-6s %-18s\n" \
    "$user" "$uid" "$gid" "$thr" "$days" "$last_login" "$last_pass" "$status" "$shell"
}

csv_header() {
  echo "user,uid,gid,threshold_days,days_since_last_activity,last_login,last_password_change,status,shell,home"
}

csv_row() {
  # CSV-safe (no commas expected in fields); quote just in case
  local user="$1" uid="$2" gid="$3" thr="$4" days="$5" last_login="$6" last_pass="$7" status="$8" shell="$9" home="${10}"
  printf '"%s","%s","%s","%s","%s","%s","%s","%s","%s","%s"\n' \
    "$user" "$uid" "$gid" "$thr" "$days" "$last_login" "$last_pass" "$status" "$shell" "$home"
}

# Output init
print_header
[[ -n "$CSV_OUT" ]] && { mkdir -p "$(dirname "$CSV_OUT")"; csv_header > "$CSV_OUT"; }

NOW=$(now_epoch)

# Iterate local accounts (not SSSD/AD); honor MIN_UID and shell filter.
while IFS=: read -r user x uid gid gecos home shell; do
  # Numeric UID and threshold
  [[ "$uid" =~ ^[0-9]+$ ]] || continue
  (( uid < MIN_UID )) && continue
  is_skipped "$user" && continue
  is_interactive_shell "$shell" || continue

  # Gather timestamps
  LLOGIN_E=$(last_login_epoch "$user")
  LPASS_E=$(last_pass_change_epoch "$user")

  # Compose human-readable dates
  [[ "$LLOGIN_E" -gt 0 ]] && LLOGIN_H="$(date -d @"$LLOGIN_E" '+%Y-%m-%d %H:%M:%S %z')" || LLOGIN_H="Never"
  [[ "$LPASS_E" -gt 0 ]] && LPASS_H="$(date -d @"$LPASS_E" '+%Y-%m-%d %H:%M:%S %z')" || LPASS_H="Never"

  # Last activity = prefer last login; else password change; else 0
  LAST_ACT_E="$LLOGIN_E"
  [[ "$LAST_ACT_E" -eq 0 ]] && LAST_ACT_E="$LPASS_E"

  if [[ "$LAST_ACT_E" -gt 0 ]]; then
    DIFF_DAYS=$(( (NOW - LAST_ACT_E) / 86400 ))
  else
    DIFF_DAYS=999999   # treat “Never” as very old
  fi

  if (( DIFF_DAYS >= DAYS )); then
    STATUS="STALE"
  else
    STATUS="OK"
  fi

  print_row "$user" "$uid" "$gid" "$DAYS" "$DIFF_DAYS" "$LLOGIN_H" "$LPASS_H" "$STATUS" "$shell"
  [[ -n "$CSV_OUT" ]] && csv_row "$user" "$uid" "$gid" "$DAYS" "$DIFF_DAYS" "$LLOGIN_H" "$LPASS_H" "$STATUS" "$shell" "$home" >> "$CSV_OUT"
done < /etc/passwd
