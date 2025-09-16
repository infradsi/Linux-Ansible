#!/usr/bin/env bash
# ==============================================================================
#  audit_password_policy.sh
#  Audit des politiques de mots de passe & verrouillage (RHEL 8/9)
#  Version: 2025-09-16 (inclut lecture directe de /etc/shadow + cross-check chage)
# ------------------------------------------------------------------------------
#  CONTRÔLES
#    1) Utilisateurs "humains" : PASS_MAX_DAYS 1..91
#    2) Comptes "service"       : PASS_MAX_DAYS 1..120
#    3) pwquality: difok >= 1 (au moins 1 caractère diffère)
#    4) Inactivité: désactivation après 90 jours (INACTIVE=90 + par-utilisateur)
#    5) faillock: deny=10 en 15 min (900s), unlock_time=3600
#    6) pwhistory: remember >= 10 (pas de réutilisation des 10 derniers)
#    7) Complexité utilisateurs: minlen>=8 + 4 classes (minclass>=4 ou u/l/d/o <= -1)
#    8) Complexité service/privilégiés: minlen>=15 (global ou PAM dédié)
#
#  NOUVEAUTÉS /etc/shadow:
#    - Lecture prioritaire des champs shadow: lastchg, min, max, warn, inactive, expire.
#    - Détection: mot de passe verrouillé (!, *), compte expiré (expire < today).
#    - Cross-check: cohérence shadow vs chage -l (valeurs numériques).
#
#  SORTIES
#    - Rapport texte et CSV dans /var/tmp/password_audit/
#
# ==============================================================================

set -euo pipefail

HOST="$(hostname -f 2>/dev/null || hostname)"
DATE="$(date +%F_%H%M%S)"
OUT_DIR="/var/tmp/password_audit"
TXT_REPORT="${OUT_DIR}/password_policy_audit_${HOST}_${DATE}.txt"
CSV_REPORT="${OUT_DIR}/password_policy_audit_${HOST}_${DATE}.csv"

mkdir -p "$OUT_DIR"

# ------------------------------ Helpers --------------------------------------

log()   { echo -e "$*" | tee -a "$TXT_REPORT" >/dev/null; }
line()  { printf '%*s\n' "${1:-80}" '' | tr ' ' '-'; }
have()  { command -v "$1" &>/dev/null; }
exists(){ [[ -e "$1" ]]; }

# kv: extraire key=value en ignorant les # et les espaces
kv() {
  local file="$1" key="$2"
  [[ -r "$file" ]] || return 1
  awk -F= -v k="$key" '
    $0 !~ /^[[:space:]]*#/ && $1 ~ "^[[:space:]]*"k"[[:space:]]*$" {
      gsub(/[[:space:]]*/,"",$2); print $2; exit
    }' "$file"
}

# -------------------------- Files/piles PAM/RHEL ------------------------------

FAILLOCK_CONF="/etc/security/faillock.conf"
PWQUALITY_CONF="/etc/security/pwquality.conf"
USERADD_DEF="/etc/default/useradd"

SYSTEM_AUTH="/etc/pam.d/system-auth"
PASSWORD_AUTH="/etc/pam.d/password-auth"

if have authselect; then
  PROFILE_DIR="$(authselect current 2>/dev/null | awk '/Profile ID:/ {print $3}')"
  if [[ -n "$PROFILE_DIR" && -d "/etc/authselect/$PROFILE_DIR" ]]; then
    SYSTEM_AUTH="/etc/authselect/$PROFILE_DIR/system-auth"
    PASSWORD_AUTH="/etc/authselect/$PROFILE_DIR/password-auth"
  fi
fi

# ------------------------------ Lists (optionnel) -----------------------------

read_list() { [[ -r "$1" ]] && grep -vE '^\s*(#|$)' "$1" | awk '{print $1}'; }
SERVICE_LIST="$(read_list /etc/policy_audit/service_accounts.list || true)"
PRIV_LIST="$(read_list /etc/policy_audit/privileged_accounts.list || true)"

# ------------------------------ CSV header -----------------------------------

echo "host,check_id,description,status,details" > "$CSV_REPORT"
csv(){ echo "$HOST,$1,$2,$3,$4" >> "$CSV_REPORT"; }

# ------------------------ Comptes & classification ----------------------------

# Tous les comptes locaux connus (base /etc/passwd)
mapfile -t ALL_USERS < <(awk -F: '{print $1}' /etc/passwd)

is_service() {
  local u="$1" entry uid shell
  entry="$(getent passwd "$u" || true)"
  [[ -z "$entry" ]] && return 1
  IFS=: read -r _ _ uid _ _ _ shell <<< "$entry"
  if [[ -n "$SERVICE_LIST" ]] && grep -qx "$u" <<< "$SERVICE_LIST"; then return 0; fi
  if (( uid < 1000 )) && [[ "$u" != "root" ]]; then return 0; fi
  [[ "$shell" =~ /(nologin|false)$ ]] && return 0
  return 1
}
is_human(){ ! is_service "$1"; }
is_priv(){ [[ -n "$PRIV_LIST" ]] && grep -qx "$1" <<< "$PRIV_LIST"; }

# ----------------------------- /etc/shadow I/O --------------------------------
# Format /etc/shadow:
#   user:passwd:lastchg:min:max:warn:inactive:expire:flag
# lastchg/expire sont en jours depuis epoch (1970-01-01). 0/empty ont des sens particuliers.

# Support: lire depuis /etc/shadow si lisible, sinon via `getent shadow`
SHADOW_SOURCE="file"
[[ -r /etc/shadow ]] || SHADOW_SOURCE="getent"

# parse_shadow <user> -> echo "passwd lastchg min max warn inactive expire"
parse_shadow() {
  local u="$1" rec
  if [[ "$SHADOW_SOURCE" == "file" ]]; then
    rec="$(awk -F: -v u="$u" '$1==u{print; exit}' /etc/shadow)"
  else
    rec="$(getent shadow "$u" || true)"
  fi
  [[ -z "$rec" ]] && return 1
  IFS=: read -r _ passwd lastchg min max warn inactive expire _ <<< "$rec"
  echo "${passwd:-}${IFS}${lastchg:-}${IFS}${min:-}${IFS}${max:-}${IFS}${warn:-}${IFS}${inactive:-}${IFS}${expire:-}"
}

# helpers numériques
is_num(){ [[ "$1" =~ ^-?[0-9]+$ ]]; }

# Conversion "jours depuis epoch" -> date lisible (YYYY-MM-DD)
to_date() {
  local d="$1"
  is_num "$d" && date -d "1970-01-01 + $d days" +%F 2>/dev/null || echo ""
}

# Jour courant en jours epoch
TODAY_DAYS="$(($(date +%s)/86400))"

# Cross-check chage -l pour extraire des valeurs numériques (robuste aux locales)
chage_num() {
  # chage_num <user> <Label regex> (e.g. "Maximum number of days")
  local u="$1" pat="$2" val
  val="$(chage -l "$u" 2>/dev/null | awk -F: -v p="$pat" '$1 ~ p {gsub(/^[ \t]+/,"",$2); print $2}')"
  [[ -z "$val" ]] && return 1
  [[ "$val" == "never" || "$val" == "password must be changed" ]] && return 2
  is_num "$val" || return 3
  echo "$val"
}

# ----------------------------- Début des contrôles ----------------------------

violators_users_max=()
violators_svc_max=()
locked_pw=()       # comptes dont le champ mot de passe est verrouillé (!, *)
expired_accounts=()# comptes avec expire < today
shadow_chage_mismatch=() # incohérences shadow vs chage

# Boucle utilisateurs: on lit SHADOW et CHAGE et on applique les règles
for u in "${ALL_USERS[@]}"; do
  # Lecture shadow
  if ! IFS=$' \t\n' read -r pw_hash lastchg min max warn inactive expire < <(parse_shadow "$u"); then
    continue
  fi

  # Détections à partir de shadow
  #  - mot de passe verrouillé si hash commence par '!' ou '*'
  if [[ "$pw_hash" =~ ^[!\*] ]]; then
    locked_pw+=("$u:locked_field=${pw_hash%%,*}")
  fi

  #  - compte expiré si champ expire numérique < TODAY_DAYS
  if [[ -n "$expire" && "$expire" != "" && "$expire" != "0" && is_num "$expire" ]]; then
    if (( expire < TODAY_DAYS )); then
      expired_accounts+=("$u:expire=$(to_date "$expire")")
    fi
  fi

  # ------------------ Règle PASS_MAX_DAYS: utilisateurs vs service ------------------
  # On prend priorité aux champs shadow (max) s'ils sont numériques, sinon on tente chage.
  shadow_max_ok=false
  if [[ -n "$max" && is_num "$max" && "$max" -gt 0 ]]; then
    if is_human "$u"; then
      (( max >= 1 && max <= 91 )) || violators_users_max+=("$u:max=$max(shadow)")
    else
      (( max >= 1 && max <= 120 )) || violators_svc_max+=("$u:max=$max(shadow)")
    fi
    shadow_max_ok=true
  fi

  # Cross-check avec chage -l (si disponible): si shadow_max_ok et chage num présent, comparer
  chmax="$(chage_num "$u" "Maximum number of days" || true)" || true
  if [[ -n "${chmax:-}" && is_num "${chmax:-}" && "$shadow_max_ok" = true ]]; then
    if (( chmax != max )); then
      shadow_chage_mismatch+=("$u:max shadow=$max chage=$chmax")
    fi
  fi

  # Si shadow ne donnait pas de max exploitable, on exploite chage pour l’audit
  if [[ "$shadow_max_ok" = false && -n "${chmax:-}" && is_num "${chmax:-}" ]]; then
    if is_human "$u"; then
      (( chmax >= 1 && chmax <= 91 )) || violators_users_max+=("$u:max=$chmax(chage)")
    else
      (( chmax >= 1 && chmax <= 120 )) || violators_svc_max+=("$u:max=$chmax(chage)")
    fi
  fi
done

# ---- Sortie contrôles 1 & 2
line | tee -a "$TXT_REPORT" >/dev/null
if ((${#violators_users_max[@]})); then
  log "1) PASS_MAX_DAYS (utilisateurs 1..91) => NON CONFORME"
  printf '   %s\n' "${violators_users_max[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "1" "Users max days between 1..91" "FAIL" "$(IFS=';'; echo "${violators_users_max[*]}")"
else
  log "1) PASS_MAX_DAYS (utilisateurs 1..91) => OK"
  csv "1" "Users max days between 1..91" "OK" "All users within 1..91"
fi

if ((${#violators_svc_max[@]})); then
  log "2) PASS_MAX_DAYS (service 1..120) => NON CONFORME"
  printf '   %s\n' "${violators_svc_max[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "2" "Service max days 1..120" "FAIL" "$(IFS=';'; echo "${violators_svc_max[*]}")"
else
  log "2) PASS_MAX_DAYS (service 1..120) => OK"
  csv "2" "Service max days 1..120" "OK" "All service within 1..120"
fi

# ---- 3) difok >= 1 (pwquality)
difok="$(kv "$PWQUALITY_CONF" "difok" || true)"
line | tee -a "$TXT_REPORT" >/dev/null
if [[ -n "$difok" && "$difok" =~ ^[0-9]+$ && "$difok" -ge 1 ]]; then
  log "3) difok (pwquality) >= 1 => OK (difok=$difok)"
  csv "3" "At least one char changes (difok>=1)" "OK" "difok=$difok"
else
  log "3) difok (pwquality) >= 1 => NON CONFORME (actuel: ${difok:-unset})"
  csv "3" "At least one char changes (difok>=1)" "FAIL" "difok=${difok:-unset}"
fi

# ---- 4) Inactivité 90 jours (INACTIVE=90 + shadow.inactive/check chage)
inactive_def="$(kv "$USERADD_DEF" "INACTIVE" || true)"
inactive_def="${inactive_def:-}"
violators_inactive=()

for u in "${ALL_USERS[@]}"; do
  if IFS=$' \t\n' read -r _ lastchg _ _ _ inactive _ < <(parse_shadow "$u"); then
    # shadow: champ inactive (jours après expiration pour désactiver le compte)
    if [[ -n "$inactive" && "$inactive" != "" && "$inactive" != "0" && is_num "$inactive" ]]; then
      (( inactive == 90 )) || violators_inactive+=("$u:inactive_shadow=$inactive")
    else
      # Si shadow n’a pas de valeur, on tente chage -l (Password inactive)
      ch_inact="$(chage_num "$u" "Password inactive" || true)" || true
      if [[ -n "${ch_inact:-}" && is_num "${ch_inact:-}" ]]; then
        (( ch_inact == 90 )) || violators_inactive+=("$u:inactive_chage=$ch_inact")
      fi
    fi
  fi
done

line | tee -a "$TXT_REPORT" >/dev/null
if [[ -n "$inactive_def" && "$inactive_def" =~ ^-?[0-9]+$ && "$inactive_def" -eq 90 ]]; then
  log "4) INACTIVE (default useradd) = 90 => OK"
else
  log "4) INACTIVE (default useradd) => NON CONFORME (INACTIVE=${inactive_def:-unset})"
fi

if ((${#violators_inactive[@]})); then
  log "   Per-user inactive != 90:"
  printf '   %s\n' "${violators_inactive[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "4" "Inactive disabled after 90 days" "FAIL" "useradd=${inactive_def:-unset}; users:$(IFS=';'; echo "${violators_inactive[*]}")"
else
  csv "4" "Inactive disabled after 90 days" "OK" "useradd=${inactive_def:-unset}; per-user ok"
fi

# ---- 5) faillock deny=10, fail_interval=900, unlock_time=3600
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

check_pam_faillock() {
  local file="$1"
  [[ -r "$file" ]] || return 1
  local d fi ut
  d="$(grep -E 'pam_faillock\.so.*deny=' "$file" -h 2>/dev/null | sed -n 's/.*deny=\([0-9]\+\).*/\1/p' | head -1)"
  fi="$(grep -E 'pam_faillock\.so.*fail_interval=' "$file" -h 2>/dev/null | sed -n 's/.*fail_interval=\([0-9]\+\).*/\1/p' | head -1)"
  ut="$(grep -E 'pam_faillock\.so.*unlock_time=' "$file" -h 2>/dev/null | sed -n 's/.*unlock_time=\([0-9]\+\).*/\1/p' | head -1)"
  [[ -z "$d"  && -n "$deny"         ]] && d="$deny"
  [[ -z "$fi" && -n "$fail_interval" ]] && fi="$fail_interval"
  [[ -z "$ut" && -n "$unlock_time"   ]] && ut="$unlock_time"
  if [[ "$d" =~ ^[0-9]+$ && "$fi" =~ ^[0-9]+$ && "$ut" =~ ^[0-9]+$ ]]; then
    if (( d==10 && fi==900 && ut==3600 )); then
      echo "OK (deny=$d, fail_interval=$fi, unlock_time=$ut)"; return 0
    fi
    echo "MISMATCH (deny=${d:-?}, fail_interval=${fi:-?}, unlock_time=${ut:-?})"; return 2
  fi
  echo "NOT_FOUND"; return 3
}
pam_sys="$(check_pam_faillock "$SYSTEM_AUTH")"; rc1=$?
pam_pwd="$(check_pam_faillock "$PASSWORD_AUTH")"; rc2=$?
line | tee -a "$TXT_REPORT" >/dev/null
if (( rc1==0 || rc2==0 )); then
  log "5) Faillock 10/15min, blocage 60min => OK"
  csv "5" "Lockout deny=10 in 15m, unlock 60m" "OK" "$pam_sys | $pam_pwd"
else
  log "5) Faillock => NON CONFORME: $pam_sys | $pam_pwd"
  csv "5" "Lockout deny=10 in 15m, unlock 60m" "FAIL" "$pam_sys | $pam_pwd"
fi

# ---- 6) pwhistory remember >= 10
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
line | tee -a "$TXT_REPORT" >/dev/null
if (( r1==0 || r2==0 )); then
  log "6) Historique mdp ≥10 => OK"
  csv "6" "No reuse last 10 passwords" "OK" "$pwh_sys | $pwh_pwd"
else
  log "6) Historique mdp ≥10 => NON CONFORME: $pwh_sys | $pwh_pwd"
  csv "6" "No reuse last 10 passwords" "FAIL" "$pwh_sys | $pwh_pwd"
fi

# ---- 7) Complexité utilisateurs (pwquality)
get_pwq(){ kv "$PWQUALITY_CONF" "$1" || true; }
minlen="$(get_pwq minlen)"
minclass="$(get_pwq minclass)"
ucredit="$(get_pwq ucredit)"; lcredit="$(get_pwq lcredit)"; dcredit="$(get_pwq dcredit)"; ocredit="$(get_pwq ocredit)"
classes_ok=false
if [[ "$minclass" =~ ^[0-9]+$ && "$minclass" -ge 4 ]]; then
  classes_ok=true
elif [[ "$ucredit" =~ ^-?[0-9]+$ && "$lcredit" =~ ^-?[0-9]+$ && "$dcredit" =~ ^-?[0-9]+$ && "$ocredit" =~ ^-?[0-9]+$ ]]; then
  (( ucredit<=-1 && lcredit<=-1 && dcredit<=-1 && ocredit<=-1 )) && classes_ok=true
fi
line | tee -a "$TXT_REPORT" >/dev/null
if [[ "$minlen" =~ ^[0-9]+$ && "$minlen" -ge 8 ]] && $classes_ok; then
  log "7) Complexité UTILISATEURS (≥8 + 4 classes) => OK"
  csv "7" "User complexity: minlen>=8 + 4 classes" "OK" "minlen=$minlen; minclass=${minclass:-}; u=$ucredit l=$lcredit d=$dcredit o=$ocredit"
else
  log "7) Complexité UTILISATEURS => NON CONFORME (minlen=${minlen:-unset}, minclass=${minclass:-unset}, u=$ucredit l=$lcredit d=$dcredit o=$ocredit)"
  csv "7" "User complexity: minlen>=8 + 4 classes" "FAIL" "minlen=${minlen:-unset}; minclass=${minclass:-unset}; u=$ucredit l=$lcredit d=$dcredit o=$ocredit"
fi

# ---- 8) Complexité service/privilégiés: minlen >= 15
pam_per_user_detected="no"
[[ -r "$SYSTEM_AUTH"   ]] && grep -qE 'pam_succeed_if\.so.*(user|uid|group)' "$SYSTEM_AUTH"   && pam_per_user_detected="yes"
[[ -r "$PASSWORD_AUTH" ]] && grep -qE 'pam_succeed_if\.so.*(user|uid|group)' "$PASSWORD_AUTH" && pam_per_user_detected="yes"
line | tee -a "$TXT_REPORT" >/dev/null
if [[ "$minlen" =~ ^[0-9]+$ && "$minlen" -ge 15 ]]; then
  log "8) Complexité SERVICE/PRIV (minlen≥15) => OK (global=$minlen)"
  csv "8" "Service/privileged minlen>=15" "OK" "global minlen=$minlen"
else
  if [[ -n "${SERVICE_LIST}${PRIV_LIST}" && "$pam_per_user_detected" == "no" ]]; then
    log "8) Complexité SERVICE/PRIV (minlen≥15) => NON CONFORME (global=${minlen:-unset})"
    log "   Astuce: pile PAM conditionnelle (pam_succeed_if + pwquality) pour comptes ciblés."
    csv "8" "Service/privileged minlen>=15" "FAIL" "global=${minlen:-unset}; no per-user PAM"
  else
    log "8) Complexité SERVICE/PRIV: non vérifiable précisément (global=${minlen:-unset}; per-user PAM=${pam_per_user_detected})"
    csv "8" "Service/privileged minlen>=15" "WARN" "Cannot verify per-user policy reliably"
  fi
fi

# ---- Annexes: états shadow utiles (verrouillés/expirés/incohérences)
if ((${#locked_pw[@]})); then
  line | tee -a "$TXT_REPORT" >/dev/null
  log "Annexe A) Comptes au mot de passe verrouillé (champ shadow précédé de '!' ou '*'):"
  printf '   %s\n' "${locked_pw[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "A" "Locked password entries in shadow" "INFO" "$(IFS=';'; echo "${locked_pw[*]}")"
fi

if ((${#expired_accounts[@]})); then
  line | tee -a "$TXT_REPORT" >/dev/null
  log "Annexe B) Comptes expirés (shadow.expire < aujourd'hui ${TODAY_DAYS}):"
  printf '   %s\n' "${expired_accounts[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "B" "Expired accounts (shadow expire)" "INFO" "$(IFS=';'; echo "${expired_accounts[*]}")"
fi

if ((${#shadow_chage_mismatch[@]})); then
  line | tee -a "$TXT_REPORT" >/dev/null
  log "Annexe C) Incohérences shadow vs chage -l (max):"
  printf '   %s\n' "${shadow_chage_mismatch[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "C" "Shadow vs chage mismatch (max)" "WARN" "$(IFS=';'; echo "${shadow_chage_mismatch[*]}")"
fi

# ------------------------------- Récapitulatif --------------------------------
line | tee -a "$TXT_REPORT" >/dev/null
log "Rapport texte : $TXT_REPORT"
log "Rapport CSV   : $CSV_REPORT"
line | tee -a "$TXT_REPORT" >/dev/null

exit 0
