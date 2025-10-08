#!/usr/bin/env bash
# find_unused_accounts_plus.sh (enhanced with LOCKED/EXPIRED/STALE + CSV/JSON)
# Compatible with RHEL 7/8/9 (incl. Rocky/Alma) & Ubuntu/Debian
set -euo pipefail

log() { echo "[$(date +'%F %T')] $*" >&2; }
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing prerequisite: $1" >&2; exit 2; }; }
csv_safe() { local s=${1//\"/\"\"}; printf '\"%s\"' "$s"; }
json_escape() { local s="$1"; s=${s//\\/\\\\}; s=${s//\"/\\\""}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}; printf '%s' "$s"; }
in_list() { local n="$1" list="${2:-}"; IFS=',' read -r -a arr <<< "${list}"; for x in "${arr[@]}"; do [[ "$n" == "$x" ]] && return 0; done; return 1; }
to_epoch() { local d="$1"; [[ -z "$d" ]] && { echo 0; return; }; [[ "$d" =~ ^[Nn]ever$ || "$d" =~ ^[Uu]nknown$ ]] && { echo 0; return; }; LC_ALL=C date -d "$d" +%s 2>/dev/null || echo 0; }
last_login_epoch() { local u="$1" line rest; line="$(LC_ALL=C lastlog -u "$u" 2>/dev/null | tail -n +2 || true)"; [[ -z "$line" || "$line" == *"Never logged in"* ]] && { echo 0; return; }; rest="$(printf '%s\n' "$line" | awk '{ $1=\"\"; $2=\"\"; $3=\"\"; sub(/^ +/, \"\"); print }')"; to_epoch "$rest"; }
last_pass_change_epoch() { local u="$1" d; d="$(LC_ALL=C chage -l "$u" 2>/dev/null | awk -F': ' '/Last password change/{print $2}')" || true; to_epoch "$d"; }
account_expiry_epoch() { local u="$1" d; d="$(LC_ALL=C chage -l "$u" 2>/dev/null | awk -F': ' '/Account expires/{print $2}')" || true; to_epoch "$d"; }
account_state_lock() { local u="$1" pw; pw="$(awk -F: -v U=\"$u\" '($1==U){print $2}' /etc/shadow 2>/dev/null || true)"; [[ -z "$pw" ]] && { echo \"NORMAL\"; return; }; [[ \"$pw\" == \"!\"* || \"$pw\" == \"*\"* ]] && { echo \"LOCKED\"; return; }; echo \"NORMAL\"; }
is_interactive_shell() { local shell=\"$1\"; [[ \"${INCLUDE_NONINTERACTIVE:-0}\" -eq 1 ]] && return 0; if [[ -r /etc/shells ]]; then grep -qxF \"$shell\" /etc/shells 2>/dev/null; else case \"$shell\" in */bash|*/zsh|*/sh|*/ksh) return 0 ;; *) return 1 ;; esac; fi; }
print_csv_header(){ echo \"user,uid,gid,threshold_days,days_since_last_activity,last_login,last_password_change,activity_source,status,account_state,shell,home\"; }
print_csv_row(){ local user=\"$1\" uid=\"$2\" gid=\"$3\" thr=\"$4\" days=\"$5\" last_login=\"$6\" last_pass=\"$7\" src=\"$8\" status=\"$9\" accst=\"${10}\" shell=\"${11}\" home=\"${12}\"; paste -d, <(csv_safe \"$user\") <(csv_safe \"$uid\") <(csv_safe \"$gid\") <(csv_safe \"$thr\") <(csv_safe \"$days\") <(csv_safe \"$last_login\") <(csv_safe \"$last_pass\") <(csv_safe \"$src\") <(csv_safe \"$status\") <(csv_safe \"$accst\") <(csv_safe \"$shell\") <(csv_safe \"$home\"); }
DAYS=90; CSV_OUT=\"./unused_accounts_enriched.csv\"; JSON_OUT=\"\"; SKIP_USERS=\"\"; INCLUDE_SYSTEM=0; MAXUID=\"\"; INCLUDE_NONINTERACTIVE=0; VERBOSE=0
ARGS=(); while [[ $# -gt 0 ]]; do case \"$1\" in -d) DAYS=\"${2:?}\"; shift 2;; -o) CSV_OUT=\"${2:?}\"; shift 2;; --json) JSON_OUT=\"${2:?}\"; shift 2;; -s) SKIP_USERS=\"${2:-}\"; shift 2;; -I) INCLUDE_SYSTEM=1; shift;; -M) MAXUID=\"${2:?}\"; shift 2;; -i) INCLUDE_NONINTERACTIVE=1; shift;; -v) VERBOSE=1; shift;; -h|--help) echo \"Usage: $0 [-d DAYS] [-o CSV] [--json FILE] [-s list] [-I] [-M MAXUID] [-i] [-v]\"; exit 0;; --) shift; break;; -*) echo \"Unknown option: $1\" >&2; exit 1;; *) ARGS+=(\"$1\"); shift;; esac; done; set -- \"${ARGS[@]}\"
need_cmd awk; need_cmd date; need_cmd lastlog; need_cmd chage
NOW=$(date +%s); UID_MIN=1000; [[ -r /etc/login.defs ]] && { v=$(awk '/^\s*UID_MIN/{print $2}' /etc/login.defs | tail -n1); [[ -n \"${v:-}\" ]] && UID_MIN=\"$v\"; }
scanned=0; stale=0; locked=0; expired=0; ok=0
: > \"$CSV_OUT\"; print_csv_header >> \"$CSV_OUT\"
[[ -n \"$JSON_OUT\" ]] && { : > \"$JSON_OUT\"; echo \"[\" >> \"$JSON_OUT\"; }
while IFS=: read -r user pw uid gid gecos home shell; do
  if ! INCLUDE_NONINTERACTIVE=\"$INCLUDE_NONINTERACTIVE\" is_interactive_shell \"$shell\"; then [[ \"$VERBOSE\" -eq 1 ]] && echo \"Skip non-interactive: $user\" >&2; continue; fi
  in_list \"$user\" \"$SKIP_USERS\" && { [[ \"$VERBOSE\" -eq 1 ]] && echo \"Skip by filter: $user\" >&2; continue; }
  if [[ \"$INCLUDE_SYSTEM\" -eq 0 && \"$uid\" -lt \"$UID_MIN\" ]]; then [[ \"$VERBOSE\" -eq 1 ]] && echo \"Skip system: $user\" >&2; continue; fi
  if [[ -n \"$MAXUID\" && \"$uid\" -gt \"$MAXUID\" ]]; then [[ \"$VERBOSE\" -eq 1 ]] && echo \"Skip >MAXUID: $user\" >&2; continue; fi
  scanned=$((scanned+1))
  LLOGIN_E=$(last_login_epoch \"$user\"); LPASS_E=$(last_pass_change_epoch \"$user\")
  [[ \"$LLOGIN_E\" -gt 0 ]] && LLOGIN_H=\"$(date -d \"@$LLOGIN_E\" +'%F %T')\" || LLOGIN_H=\"Never\"
  [[ \"$LPASS_E\" -gt 0 ]] && LPASS_H=\"$(date -d \"@$LPASS_E\" +'%F %T')\" || LPASS_H=\"Never\"
  SRC=\"pass_change\"; BASE=\"$LPASS_E\"
  if [[ \"$LLOGIN_E\" -gt 0 ]]; then SRC=\"login\"; BASE=\"$LLOGIN_E\"; fi
  DIFF_DAYS=0; [[ \"$BASE\" -gt 0 ]] && DIFF_DAYS=$(( (NOW - BASE) / 86400 ))
  ACC_STATE=\"$(account_state_lock \"$user\")\"; EXP_EPOCH=\"$(account_expiry_epoch \"$user\")\"
  EXP_STATUS=\"OK\"; [[ \"$EXP_EPOCH\" -gt 0 && \"$EXP_EPOCH\" -lt \"$NOW\" ]] && EXP_STATUS=\"EXPIRED\"
  STATUS=\"OK\"
  if [[ \"$EXP_STATUS\" == \"EXPIRED\" ]]; then STATUS=\"EXPIRED\"; expired=$((expired+1))
  elif [[ \"$ACC_STATE\" == \"LOCKED\" ]]; then STATUS=\"LOCKED\"; locked=$((locked+1))
  elif [[ \"$DIFF_DAYS\" -ge \"$DAYS\" ]]; then STATUS=\"STALE\"; stale=$((stale+1))
  else ok=$((ok+1)); fi
  print_csv_row \"$user\" \"$uid\" \"$gid\" \"$DAYS\" \"$DIFF_DAYS\" \"$LLOGIN_H\" \"$LPASS_H\" \"$SRC\" \"$STATUS\" \"$ACC_STATE\" \"$shell\" \"$home\" >> \"$CSV_OUT\"
  if [[ -n \"$JSON_OUT\" ]] && [[ -w \"$JSON_OUT\" ]]; then
    printf '  {\"user\":\"%s\",\"uid\":%s,\"gid\":%s,\"threshold_days\":%s,\"days_since_last_activity\":%s,' \"$(json_escape \"$user\")\" \"$uid\" \"$gid\" \"$DAYS\" \"$DIFF_DAYS\" >> \"$JSON_OUT\"
    printf '\"last_login\":\"%s\",\"last_password_change\":\"%s\",\"activity_source\":\"%s\",' \"$(json_escape \"$LLOGIN_H\")\" \"$(json_escape \"$LPASS_H\")\" \"$(json_escape \"$SRC\")\" >> \"$JSON_OUT\"
    printf '\"status\":\"%s\",\"account_state\":\"%s\",\"shell\":\"%s\",\"home\":\"%s\"},\n' \"$(json_escape \"$STATUS\")\" \"$(json_escape \"$ACC_STATE\")\" \"$(json_escape \"$shell\")\" \"$(json_escape \"$home\")\" >> \"$JSON_OUT\"
  fi
done < /etc/passwd
if [[ -n \"$JSON_OUT\" ]] && [[ -s \"$JSON_OUT\" ]]; then tmp=\"$(mktemp)\"; sed '$ s/},/}/' \"$JSON_OUT\" > \"$tmp\" || true; echo \"]\" >> \"$tmp\"; mv \"$tmp\" \"$JSON_OUT\"; fi
echo \"Scanned users: $scanned\"; echo \"Status counts: OK=$ok, STALE=$stale, LOCKED=$locked, EXPIRED=$expired\"; echo \"CSV report: $CSV_OUT\"; [[ -n \"$JSON_OUT\" ]] && echo \"JSON report: $JSON_OUT\"
exit 0
