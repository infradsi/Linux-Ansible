#!/usr/bin/env bash
# audit_password_policy.sh - Audit des politiques mots de passe & verrouillage (RHEL 8/9)
# Génère un rapport texte et CSV.
# Usage: sudo ./audit_password_policy.sh
# Optionnel: créez des listes d’exceptions :
#   /etc/policy_audit/service_accounts.list     (un compte par ligne)
#   /etc/policy_audit/privileged_accounts.list  (un compte par ligne)

set -euo pipefail

HOST="$(hostname -f 2>/dev/null || hostname)"
DATE="$(date +%F_%H%M%S)"
OUT_DIR="/var/tmp/password_audit"
TXT_REPORT="${OUT_DIR}/password_policy_audit_${HOST}_${DATE}.txt"
CSV_REPORT="${OUT_DIR}/password_policy_audit_${HOST}_${DATE}.csv"

mkdir -p "$OUT_DIR"

# ------------ Helpers ------------
log()   { echo -e "$*"    | tee -a "$TXT_REPORT" >/dev/null; }
line()  { printf '%*s\n' "${1:-80}" '' | tr ' ' '-'; }
have()  { command -v "$1" &>/dev/null; }
exists(){ [[ -e "$1" ]]; }
kv() { # read key=value from file; print value of key
  local file="$1" key="$2"
  [[ -r "$file" ]] || return 1
  awk -F= -v k="$key" '
    $0 !~ /^[[:space:]]*#/ && $1 ~ "^[[:space:]]*"k"[[:space:]]*$" {
      gsub(/[[:space:]]*/,"",$2); print $2; exit
    }' "$file"
}

# Read lists if present
read_list() {
  local file="$1"
  if [[ -r "$file" ]]; then
    grep -vE '^\s*(#|$)' "$file" | awk '{print $1}'
  fi
}

SERVICE_LIST="$(read_list /etc/policy_audit/service_accounts.list || true)"
PRIV_LIST="$(read_list /etc/policy_audit/privileged_accounts.list || true)"

# ------------ Collect OS & files ------------
OS_ID=""
if [[ -r /etc/os-release ]]; then
  OS_ID="$(. /etc/os-release; echo "${ID}-${VERSION_ID}")"
fi

FAILLOCK_CONF="/etc/security/faillock.conf"
PWQUALITY_CONF="/etc/security/pwquality.conf"
LOGINDEFS="/etc/login.defs"
USERADD_DEF="/etc/default/useradd"

SYSTEM_AUTH="/etc/pam.d/system-auth"
PASSWORD_AUTH="/etc/pam.d/password-auth"

# PAM files via authselect (RHEL 8/9)
if have authselect; then
  PROFILE_DIR="$(authselect current 2>/dev/null | awk '/Profile ID:/ {print $3}')"
  if [[ -n "$PROFILE_DIR" && -d "/etc/authselect/$PROFILE_DIR" ]]; then
    SYSTEM_AUTH="/etc/authselect/$PROFILE_DIR/system-auth"
    PASSWORD_AUTH="/etc/authselect/$PROFILE_DIR/password-auth"
  fi
fi

# ------------ CSV Header ------------
echo "host,check_id,description,status,details" > "$CSV_REPORT"
csv() { echo "$HOST,$1,$2,$3,$4" >> "$CSV_REPORT"; }

# ------------ Account inventory ------------
# Build user sets from /etc/passwd (UID >= 1000 are generally "normaux" sur RHEL)
# Service accounts heuristique: shell nologin/false OR explicit list OR uid<1000 (non-root)
mapfile -t ALL_USERS < <(awk -F: '{print $1}' /etc/passwd)
is_service() {
  local u="$1"
  local entry
  entry="$(getent passwd "$u" || true)"
  [[ -z "$entry" ]] && return 1
  IFS=: read -r _ _ uid _ _ _ shell <<< "$entry"
  if grep -qx "$u" <<< "$SERVICE_LIST"; then return 0; fi
  if (( uid < 1000 )) && [[ "$u" != "root" ]]; then return 0; fi
  if [[ "$shell" =~ /(nologin|false)$ ]]; then return 0; fi
  return 1
}
is_priv() {
  local u="$1"
  grep -qx "$u" <<< "$PRIV_LIST" && return 0 || return 1
}
is_human() {
  local u="$1"
  ! is_service "$u"
}

# ------------ Check 1: PASS_MAX_DAYS utilisateurs 1..91 ------------
# Vérif par utilisateur via chage -l (prioritaire) et cohérence globale via /etc/login.defs
violators_users_max=()
for u in "${ALL_USERS[@]}"; do
  is_human "$u" || continue
  shadow="$(getent shadow "$u" || true)"
  [[ -z "$shadow" ]] && continue
  maxdays="$(chage -l "$u" 2>/dev/null | awk -F: '/Maximum number of days between password change/ {gsub(/^[ \t]+/,"",$2); print $2}')"
  # gère "never" / "password must be changed"
  if [[ "$maxdays" == "never" || -z "$maxdays" ]]; then
    violators_users_max+=("$u:max=never")
  else
    if ! [[ "$maxdays" =~ ^[0-9]+$ ]]; then
      violators_users_max+=("$u:max=$maxdays")
    elif (( maxdays < 1 || maxdays > 91 )); then
      violators_users_max+=("$u:max=$maxdays")
    fi
  fi
done
if ((${#violators_users_max[@]})); then
  log "$(line)"; log "1) PASS_MAX_DAYS (utilisateurs) => NON CONFORME"
  printf '   %s\n' "${violators_users_max[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "1" "Users max days between 1..91" "FAIL" "$(IFS=';'; echo "${violators_users_max[*]}")"
else
  log "$(line)"; log "1) PASS_MAX_DAYS (utilisateurs) => OK"
  csv "1" "Users max days between 1..91" "OK" "All user accounts within 1..91"
fi

# ------------ Check 2: PASS_MAX_DAYS service 1..120 ------------
violators_svc_max=()
for u in "${ALL_USERS[@]}"; do
  is_service "$u" || continue
  shadow="$(getent shadow "$u" || true)"
  [[ -z "$shadow" ]] && continue
  maxdays="$(chage -l "$u" 2>/dev/null | awk -F: '/Maximum number of days between password change/ {gsub(/^[ \t]+/,"",$2); print $2}')"
  [[ -z "$maxdays" ]] && maxdays="never"
  if [[ "$maxdays" == "never" ]]; then
    violators_svc_max+=("$u:max=never")
  elif ! [[ "$maxdays" =~ ^[0-9]+$ ]]; then
    violators_svc_max+=("$u:max=$maxdays")
  elif (( maxdays < 1 || maxdays > 120 )); then
    violators_svc_max+=("$u:max=$maxdays")
  fi
done
if ((${#violators_svc_max[@]})); then
  log "$(line)"; log "2) PASS_MAX_DAYS (service) => NON CONFORME"
  printf '   %s\n' "${violators_svc_max[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "2" "Service max days 1..120" "FAIL" "$(IFS=';'; echo "${violators_svc_max[*]}")"
else
  log "$(line)"; log "2) PASS_MAX_DAYS (service) => OK"
  csv "2" "Service max days 1..120" "OK" "All service accounts within 1..120"
fi

# ------------ Check 3: Au moins un caractère change (difok >= 1) ------------
difok="$(kv "$PWQUALITY_CONF" "difok" || true)"
if [[ -n "$difok" && "$difok" =~ ^[0-9]+$ && "$difok" -ge 1 ]]; then
  log "$(line)"; log "3) difok (pwquality) >= 1 => OK (difok=$difok)"
  csv "3" "At least one char changes (difok>=1)" "OK" "difok=$difok"
else
  log "$(line)"; log "3) difok (pwquality) >= 1 => NON CONFORME (valeur actuelle: ${difok:-unset})"
  csv "3" "At least one char changes (difok>=1)" "FAIL" "difok=${difok:-unset}"
fi

# ------------ Check 4: Comptes inactifs désactivés après 90 jours ------------
# Politique par défaut à la création:
inactive_def="$(kv "$USERADD_DEF" "INACTIVE" || true)"
inactive_def="${inactive_def:-}"
if [[ -n "$inactive_def" && "$inactive_def" =~ ^-?[0-9]+$ && "$inactive_def" -eq 90 ]]; then
  def_status="OK"
else
  def_status="FAIL(INACTIVE=${inactive_def:-unset})"
fi

violators_inactive=()
for u in "${ALL_USERS[@]}"; do
  # on vérifie la valeur "Password inactive" via chage -l
  val="$(chage -l "$u" 2>/dev/null | awk -F: '/Password inactive/ {gsub(/^[ \t]+/,"",$2); print $2}')"
  if [[ -n "$val" && "$val" != "never" && "$val" != "password must be changed" ]]; then
    if [[ "$val" =~ ^[0-9]+$ ]] && (( val != 90 )); then
      violators_inactive+=("$u:inactive=$val")
    fi
  fi
done
if [[ "$def_status" == "OK" && ${#violators_inactive[@]} -eq 0 ]]; then
  log "$(line)"; log "4) Inactivité 90j => OK (défaut useradd + comptes existants)"
  csv "4" "Inactive disabled after 90 days" "OK" "INACTIVE=90; per-user ok"
else
  log "$(line)"; log "4) Inactivité 90j => NON CONFORME"
  log "   Défaut useradd: $def_status"
  ((${#violators_inactive[@]})) && printf '   %s\n' "${violators_inactive[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "4" "Inactive disabled after 90 days" "FAIL" "useradd:${def_status}; users:$(IFS=';'; echo "${violators_inactive[*]:-none}")"
fi

# ------------ Check 5: Verrouillage après 10 échecs / 15 min, déverrouillage 60 min ------------
# Sur RHEL8/9, vérifier /etc/security/faillock.conf ou les lignes PAM (deny, fail_interval, unlock_time)
read_faillock() {
  local key="$1"
  awk -v k="$key" '
    $0 !~ /^[[:space:]]*#/ && $0 ~ k"[[:space:]]*=" {
      gsub(/^[[:space:]]*|[[:space:]]*$/,""); 
      split($0,a,"="); gsub(/[[:space:]]*/,"",a[2]); print a[2]
    }' "$FAILLOCK_CONF" 2>/dev/null
}
deny="" fail_interval="" unlock_time=""
if exists "$FAILLOCK_CONF"; then
  deny="$(read_faillock "deny" || true)"
  fail_interval="$(read_faillock "fail_interval" || true)"
  unlock_time="$(read_faillock "unlock_time" || true)"
fi

pam_ok="UNKNOWN"
check_pam_faillock() {
  local file="$1"
  [[ -r "$file" ]] || return 1
  # Cherche deny, fail_interval, unlock_time dans la même ligne ou cumulées
  local d fi ut
  d="$(grep -E 'pam_faillock\.so.*deny=' "$file" -h 2>/dev/null | sed -n 's/.*deny=\([0-9]\+\).*/\1/p' | head -1)"
  fi="$(grep -E 'pam_faillock\.so.*fail_interval=' "$file" -h 2>/dev/null | sed -n 's/.*fail_interval=\([0-9]\+\).*/\1/p' | head -1)"
  ut="$(grep -E 'pam_faillock\.so.*unlock_time=' "$file" -h 2>/dev/null | sed -n 's/.*unlock_time=\([0-9]\+\).*/\1/p' | head -1)"
  [[ -z "$d"  && -n "$deny"         ]] && d="$deny"
  [[ -z "$fi" && -n "$fail_interval" ]] && fi="$fail_interval"
  [[ -z "$ut" && -n "$unlock_time"   ]] && ut="$unlock_time"
  if [[ "$d" =~ ^[0-9]+$ && "$fi" =~ ^[0-9]+$ && "$ut" =~ ^[0-9]+$ ]]; then
    if (( d==10 && fi==900 && ut==3600 )); then
      echo "OK (deny=$d, fail_interval=$fi, unlock_time=$ut)"
      return 0
    fi
    echo "MISMATCH (deny=${d:-?}, fail_interval=${fi:-?}, unlock_time=${ut:-?})"
    return 2
  fi
  echo "NOT_FOUND"
  return 3
}
pam_sys="$(check_pam_faillock "$SYSTEM_AUTH")"; rc1=$?
pam_pwd="$(check_pam_faillock "$PASSWORD_AUTH")"; rc2=$?
if (( rc1==0 || rc2==0 )); then pam_ok="OK"; else pam_ok="FAIL ($pam_sys | $pam_pwd)"; fi

if [[ "$pam_ok" == "OK" ]]; then
  log "$(line)"; log "5) Faillock 10 échecs/15min, blocage 60min => OK"
  csv "5" "Lockout deny=10 in 15m, unlock 60m" "OK" "$pam_sys | $pam_pwd"
else
  log "$(line)"; log "5) Faillock => NON CONFORME: $pam_ok"
  csv "5" "Lockout deny=10 in 15m, unlock 60m" "FAIL" "$pam_ok"
fi

# ------------ Check 6: Réutilisation des 10 derniers mdp (pwhistory remember>=10) ------------
check_pwhistory() {
  local file="$1"
  [[ -r "$file" ]] || return 1
  local rem
  rem="$(grep -E 'pam_pwhistory\.so' "$file" -h 2>/dev/null | sed -n 's/.*remember=\([0-9]\+\).*/\1/p' | head -1)"
  if [[ "$rem" =~ ^[0-9]+$ && "$rem" -ge 10 ]]; then
    echo "OK (remember=$rem)"; return 0
  fi
  echo "MISSING_OR_TOO_LOW (remember=${rem:-unset})"; return 2
}
pwh_sys="$(check_pwhistory "$SYSTEM_AUTH")"; r1=$?
pwh_pwd="$(check_pwhistory "$PASSWORD_AUTH")"; r2=$?
if (( r1==0 || r2==0 )); then
  log "$(line)"; log "6) Historique des mdp (≥10) => OK"
  csv "6" "No reuse last 10 passwords" "OK" "$pwh_sys | $pwh_pwd"
else
  log "$(line)"; log "6) Historique des mdp (≥10) => NON CONFORME: $pwh_sys | $pwh_pwd"
  csv "6" "No reuse last 10 passwords" "FAIL" "$pwh_sys | $pwh_pwd"
fi

# ------------ Check 7: Complexité utilisateurs (minlen>=8 + 4 classes) ------------
# On considère OK si:
#   - minlen >= 8
#   - ET (ucredit,lcredit,dcredit,ocredit) tous <= -1  (au moins un de chaque), OU minclass >= 4
get_pwq() { kv "$PWQUALITY_CONF" "$1" || true; }
minlen="$(get_pwq minlen)"
minclass="$(get_pwq minclass)"
ucredit="$(get_pwq ucredit)"; lcredit="$(get_pwq lcredit)"; dcredit="$(get_pwq dcredit)"; ocredit="$(get_pwq ocredit)"

classes_ok=false
if [[ "$minclass" =~ ^[0-9]+$ && "$minclass" -ge 4 ]]; then
  classes_ok=true
elif [[ "$ucredit" =~ ^-?[0-9]+$ && "$lcredit" =~ ^-?[0-9]+$ && "$dcredit" =~ ^-?[0-9]+$ && "$ocredit" =~ ^-?[0-9]+$ ]]; then
  if (( ucredit<=-1 && lcredit<=-1 && dcredit<=-1 && ocredit<=-1 )); then classes_ok=true; fi
fi
if [[ "$minlen" =~ ^[0-9]+$ && "$minlen" -ge 8 ]] && $classes_ok; then
  log "$(line)"; log "7) Complexité UTILISATEURS (≥8 + AZ/az/09/spécial) => OK"
  csv "7" "User complexity: minlen>=8 + 4 classes" "OK" "minlen=$minlen; minclass=${minclass:-}; u=$ucredit l=$lcredit d=$dcredit o=$ocredit"
else
  log "$(line)"; log "7) Complexité UTILISATEURS => NON CONFORME (minlen=${minlen:-unset}, minclass=${minclass:-unset}, u=$ucredit l=$lcredit d=$dcredit o=$ocredit)"
  csv "7" "User complexity: minlen>=8 + 4 classes" "FAIL" "minlen=${minlen:-unset}; minclass=${minclass:-unset}; u=$ucredit l=$lcredit d=$dcredit o=$ocredit"
fi

# ------------ Check 8: Complexité service/privilégiés (minlen>=15) ------------
# Remarque: RHEL ne gère pas nativement une minlen différente par groupe/utilisateur sans empilement PAM spécifique.
# On considère conforme si minlen global >=15 OU (si listes fournies) on détecte un empilement PAM spécifique (très rare).
pam_per_user_detected="no"
if [[ -r "$SYSTEM_AUTH" ]] && grep -qE 'pam_succeed_if\.so.*(user|uid|group)' "$SYSTEM_AUTH"; then pam_per_user_detected="yes"; fi
if [[ -r "$PASSWORD_AUTH" ]] && grep -qE 'pam_succeed_if\.so.*(user|uid|group)' "$PASSWORD_AUTH"; then pam_per_user_detected="yes"; fi

if [[ "$minlen" =~ ^[0-9]+$ && "$minlen" -ge 15 ]]; then
  log "$(line)"; log "8) Complexité SERVICE/PRIV (minlen≥15) => OK (minlen global=$minlen)"
  csv "8" "Service/privileged minlen>=15" "OK" "global minlen=$minlen"
else
  if [[ -n "${SERVICE_LIST}${PRIV_LIST}" && "$pam_per_user_detected" == "no" ]]; then
    log "$(line)"; log "8) Complexité SERVICE/PRIV (minlen≥15) => NON CONFORME (minlen global=${minlen:-unset})"
    log "   NOTE: pour appliquer une minlen différente par groupe, il faut une pile PAM dédiée (ex: pam_succeed_if + pwquality)."
    csv "8" "Service/privileged minlen>=15" "FAIL" "global minlen=${minlen:-unset}; no per-user PAM detected"
  else
    log "$(line)"; log "8) Complexité SERVICE/PRIV: IMPOSSIBLE À VALIDER précisément (minlen global=${minlen:-unset}; PAM per-user=${pam_per_user_detected})"
    csv "8" "Service/privileged minlen>=15" "WARN" "Cannot verify per-user policy reliably"
  fi
fi

# ------------ Récapitulatif ------------
line | tee -a "$TXT_REPORT" >/dev/null
log "Rapport texte : $TXT_REPORT"
log "Rapport CSV   : $CSV_REPORT"
line | tee -a "$TXT_REPORT" >/dev/null

exit 0
