#!/usr/bin/env bash
# ==============================================================================
#  audit_password_policy.sh
#  Audit des politiques de mots de passe & verrouillage (RHEL 8/9)
# ------------------------------------------------------------------------------
#  OBJET
#    - Vérifier la conformité des règles suivantes :
#        1) Durée de vie des mots de passe utilisateurs : 1..91 jours
#        2) Durée de vie des mots de passe comptes de service/utilitaires : 1..120 jours
#        3) Au moins 1 caractère doit changer lors d'un changement de mot de passe (difok>=1)
#        4) Comptes inactifs désactivés après 90 jours (INACTIVE=90 + contrôle par utilisateur)
#        5) Verrouillage après 10 échecs en 15 minutes, déverrouillage après 60 minutes
#           (pam_faillock: deny=10, fail_interval=900, unlock_time=3600)
#        6) Empêcher la réutilisation des 10 derniers mots de passe
#           (pam_pwhistory remember>=10)
#        7) Complexité utilisateurs : minlen>=8 + (AZ/az/09/spéciaux) -> minclass>=4
#           OU ucredit/lcredit/dcredit/ocredit <= -1 tous
#        8) Complexité comptes de service/privilégiés : minlen>=15 (global ou via pile PAM dédiée)
#
#  SORTIES
#    - Un rapport texte lisible : /var/tmp/password_audit/password_policy_audit_<host>_<date>.txt
#    - Un rapport CSV exploitable  : /var/tmp/password_audit/password_policy_audit_<host>_<date>.csv
#
#  LISTES OPTIONNELLES (pour mieux classifier les comptes)
#    - /etc/policy_audit/service_accounts.list     (un compte par ligne)
#    - /etc/policy_audit/privileged_accounts.list  (un compte par ligne)
#    Ces fichiers permettent d’indiquer explicitement des comptes “service”
#    et des comptes “privilégiés” (ex: root, ops_adminX, etc.).
#
#  COMPATIBILITÉ
#    - Testé et prévu pour RHEL 8/9 (PAM via authselect)
#    - Nécessite les commandes usuelles: awk, sed, grep, getent, chage
#
#  USAGE
#    sudo /opt/scripts/audit_password_policy.sh
#
# ==============================================================================

# Options shell sécurisées :
# -e : stoppe le script dès qu'une commande renvoie un code de retour non nul
# -u : considère l'utilisation de variables non définies comme une erreur
# -o pipefail : propage l'échec si une commande au milieu d'un pipe échoue
set -euo pipefail

# -------------------------- Variables globales -------------------------------

# FQDN si possible, sinon hostname court.
HOST="$(hostname -f 2>/dev/null || hostname)"

# Timestamp pour distinguer les rapports.
DATE="$(date +%F_%H%M%S)"

# Répertoire de sortie des rapports (local au serveur audité).
OUT_DIR="/var/tmp/password_audit"

# Chemins des rapports.
TXT_REPORT="${OUT_DIR}/password_policy_audit_${HOST}_${DATE}.txt"
CSV_REPORT="${OUT_DIR}/password_policy_audit_${HOST}_${DATE}.csv"

# Création du répertoire de sortie s'il n'existe pas.
mkdir -p "$OUT_DIR"

# ------------------------------ Helpers --------------------------------------

# log : écrit un message à la fois sur stdout ET dans le rapport texte
log() {
  echo -e "$*" | tee -a "$TXT_REPORT" >/dev/null
}

# line : imprime une ligne de séparation (80 tirets par défaut)
line() {
  printf '%*s\n' "${1:-80}" '' | tr ' ' '-'
}

# have : teste la présence d’une commande dans le PATH (retour 0 si présente)
have() {
  command -v "$1" &>/dev/null
}

# exists : teste l’existence d’un fichier (retour 0 si existe)
exists() {
  [[ -e "$1" ]]
}

# kv : lit une clé de type "clé=valeur" dans un fichier de configuration
#      - ignore les lignes commentées (# en début)
#      - supprime les espaces autour de la valeur
#      - renvoie la valeur (stdout) si trouvée, sinon code de retour != 0
kv() {
  local file="$1" key="$2"
  [[ -r "$file" ]] || return 1
  awk -F= -v k="$key" '
    $0 !~ /^[[:space:]]*#/ && $1 ~ "^[[:space:]]*"k"[[:space:]]*$" {
      gsub(/[[:space:]]*/,"",$2); print $2; exit
    }' "$file"
}

# read_list : lit un fichier “liste d’utilisateurs” (un nom par ligne, commentaires admis)
#             et renvoie la liste sur stdout (une valeur par ligne)
read_list() {
  local file="$1"
  if [[ -r "$file" ]]; then
    # On ignore lignes vides ou commentées
    grep -vE '^\s*(#|$)' "$file" | awk '{print $1}'
  fi
}

# --------------------------- Fichiers systèmes -------------------------------

# Fichiers principaux liés aux politiques de sécurité (RHEL 8/9)
FAILLOCK_CONF="/etc/security/faillock.conf"   # Paramètres de verrouillage après échecs
PWQUALITY_CONF="/etc/security/pwquality.conf" # Paramètres de complexité des mots de passe
LOGINDEFS="/etc/login.defs"                   # (non utilisé directement ici, mais utile si besoin)
USERADD_DEF="/etc/default/useradd"            # Valeurs par défaut pour nouveaux comptes (INACTIVE, etc.)

# Fichiers PAM. Sur RHEL >= 8 on passe souvent par authselect qui génère ces fichiers.
SYSTEM_AUTH="/etc/pam.d/system-auth"
PASSWORD_AUTH="/etc/pam.d/password-auth"

# Authselect peut déplacer la “vraie” pile PAM dans un profil. On tente de la détecter.
if have authselect; then
  # `authselect current` affiche le profil (ex: sssd)
  PROFILE_DIR="$(authselect current 2>/dev/null | awk '/Profile ID:/ {print $3}')"
  if [[ -n "$PROFILE_DIR" && -d "/etc/authselect/$PROFILE_DIR" ]]; then
    SYSTEM_AUTH="/etc/authselect/$PROFILE_DIR/system-auth"
    PASSWORD_AUTH="/etc/authselect/$PROFILE_DIR/password-auth"
  fi
fi

# ------------------------- Listes optionnelles --------------------------------

# On charge (facultatif) les listes explicites d’utilisateurs service / privilégiés.
SERVICE_LIST="$(read_list /etc/policy_audit/service_accounts.list || true)"
PRIV_LIST="$(read_list /etc/policy_audit/privileged_accounts.list || true)"

# -------------------------- Rapport CSV (entête) ------------------------------

# Le CSV permet des agrégations et filtres faciles (Excel/LibreOffice, SIEM, etc.)
echo "host,check_id,description,status,details" > "$CSV_REPORT"

# Helper d'ajout de ligne CSV
csv() {
  # Paramètres : $1=id, $2=description, $3=status(OK/FAIL/WARN), $4=details libres
  echo "$HOST,$1,$2,$3,$4" >> "$CSV_REPORT"
}

# -------------------------- Inventaire des comptes ----------------------------

# On récupère tous les noms d’utilisateurs connus du système (base : /etc/passwd).
# Note : getent passwd renverrait aussi des comptes distants (LDAP/SSSD) si configuré,
# mais ici on préfère auditer les comptes locaux pour l’âge du mot de passe, etc.
mapfile -t ALL_USERS < <(awk -F: '{print $1}' /etc/passwd)

# Heuristiques pour classer les comptes :
#  - "service" si UID < 1000 (hors root) OU shell nologin/false
#  - on pourrait aussi forcer via SERVICE_LIST (si tu souhaites, tu peux étendre is_service)
is_service() {
  local u="$1"
  local entry
  entry="$(getent passwd "$u" || true)"
  [[ -z "$entry" ]] && return 1
  IFS=: read -r _ _ uid _ _ _ shell <<< "$entry"

  # Compte système (UID < 1000) différent de root => généralement service
  if (( uid < 1000 )) && [[ "$u" != "root" ]]; then
    return 0
  fi

  # Shell de connexion inactif => souvent service
  if [[ "$shell" =~ /(nologin|false)$ ]]; then
    return 0
  fi

  # Si fourni, considère explicitement les comptes listés comme "service"
  if [[ -n "$SERVICE_LIST" ]] && grep -qx "$u" <<< "$SERVICE_LIST"; then
    return 0
  fi

  return 1
}

# Un "humain" est tout ce qui n’est pas classé "service" par nos règles.
is_human() {
  ! is_service "$1"
}

# Un "privilégié" est un utilisateur listé dans PRIV_LIST (optionnel).
is_priv() {
  local u="$1"
  [[ -n "$PRIV_LIST" ]] && grep -qx "$u" <<< "$PRIV_LIST"
}

# ==============================================================================
#                             DÉBUT DES CONTRÔLES
# ==============================================================================

# -------------------- 1) PASS_MAX_DAYS utilisateurs 1..91 ---------------------

# On contrôle par utilisateur via `chage -l <user>` :
#  - “Maximum number of days between password change” => âge max du mot de passe
#  - Si "never" => non conforme
#  - Si non numérique ou hors plage ( <1 ou >91 ) => non conforme
violators_users_max=()  # tableau des comptes non conformes

for u in "${ALL_USERS[@]}"; do
  # on ne cible que les "humains"
  is_human "$u" || continue

  # getent shadow nous confirme l’existence du compte dans la base shadow
  shadow="$(getent shadow "$u" || true)"
  [[ -z "$shadow" ]] && continue

  # chage -l renvoie des lignes "Clé : Valeur". On prend la ligne de l'âge max.
  maxdays="$(chage -l "$u" 2>/dev/null | awk -F: '/Maximum number of days between password change/ {gsub(/^[ \t]+/,"",$2); print $2}')"

  # Traitement des cas "never" ou vides => non conforme
  if [[ "$maxdays" == "never" || -z "$maxdays" ]]; then
    violators_users_max+=("$u:max=never")
  else
    # Si non numérique => non conforme
    if ! [[ "$maxdays" =~ ^[0-9]+$ ]]; then
      violators_users_max+=("$u:max=$maxdays")
    # Si numérique mais hors plage => non conforme
    elif (( maxdays < 1 || maxdays > 91 )); then
      violators_users_max+=("$u:max=$maxdays")
    fi
  fi
done

if ((${#violators_users_max[@]})); then
  line | tee -a "$TXT_REPORT" >/dev/null
  log "1) PASS_MAX_DAYS (utilisateurs) => NON CONFORME"
  printf '   %s\n' "${violators_users_max[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "1" "Users max days between 1..91" "FAIL" "$(IFS=';'; echo "${violators_users_max[*]}")"
else
  line | tee -a "$TXT_REPORT" >/dev/null
  log "1) PASS_MAX_DAYS (utilisateurs) => OK"
  csv "1" "Users max days between 1..91" "OK" "All user accounts within 1..91"
fi

# ------------------ 2) PASS_MAX_DAYS service 1..120 ---------------------------

# Même approche, mais sur comptes "service" et plage 1..120.
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
  line | tee -a "$TXT_REPORT" >/dev/null
  log "2) PASS_MAX_DAYS (service) => NON CONFORME"
  printf '   %s\n' "${violators_svc_max[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "2" "Service max days 1..120" "FAIL" "$(IFS=';'; echo "${violators_svc_max[*]}")"
else
  line | tee -a "$TXT_REPORT" >/dev/null
  log "2) PASS_MAX_DAYS (service) => OK"
  csv "2" "Service max days 1..120" "OK" "All service accounts within 1..120"
fi

# ------------------ 3) difok >= 1 (au moins 1 caractère diffère) --------------

# difok est paramétré dans /etc/security/pwquality.conf
# - difok = nombre minimum de caractères différents par rapport à l’ancien mot de passe.
difok="$(kv "$PWQUALITY_CONF" "difok" || true)"

if [[ -n "$difok" && "$difok" =~ ^[0-9]+$ && "$difok" -ge 1 ]]; then
  line | tee -a "$TXT_REPORT" >/dev/null
  log "3) difok (pwquality) >= 1 => OK (difok=$difok)"
  csv "3" "At least one char changes (difok>=1)" "OK" "difok=$difok"
else
  line | tee -a "$TXT_REPORT" >/dev/null
  log "3) difok (pwquality) >= 1 => NON CONFORME (valeur actuelle: ${difok:-unset})"
  csv "3" "At least one char changes (difok>=1)" "FAIL" "difok=${difok:-unset}"
fi

# ------------- 4) Comptes inactifs désactivés après 90 jours ------------------

# Deux angles :
#  - Valeur par défaut à la création de comptes: INACTIVE=90 dans /etc/default/useradd
#  - Valeur au niveau de chaque utilisateur déjà existant : chage -l => "Password inactive"

inactive_def="$(kv "$USERADD_DEF" "INACTIVE" || true)"
inactive_def="${inactive_def:-}"

# Vérifie la valeur par défaut INACTIVE=90 (utilisée par useradd pour nouveaux comptes)
if [[ -n "$inactive_def" && "$inactive_def" =~ ^-?[0-9]+$ && "$inactive_def" -eq 90 ]]; then
  def_status="OK"
else
  def_status="FAIL(INACTIVE=${inactive_def:-unset})"
fi

# Pour les comptes existants, on regarde la valeur “Password inactive”
# (nombre de jours après expiration du password avant désactivation du compte).
# Si chiffré et différent de 90 => non conforme.
violators_inactive=()

for u in "${ALL_USERS[@]}"; do
  val="$(chage -l "$u" 2>/dev/null | awk -F: '/Password inactive/ {gsub(/^[ \t]+/,"",$2); print $2}')"
  # On ignore "never" et "password must be changed" (cas particuliers)
  if [[ -n "$val" && "$val" != "never" && "$val" != "password must be changed" ]]; then
    if [[ "$val" =~ ^[0-9]+$ ]] && (( val != 90 )); then
      violators_inactive+=("$u:inactive=$val")
    fi
  fi
done

if [[ "$def_status" == "OK" && ${#violators_inactive[@]} -eq 0 ]]; then
  line | tee -a "$TXT_REPORT" >/dev/null
  log "4) Inactivité 90j => OK (défaut useradd + comptes existants)"
  csv "4" "Inactive disabled after 90 days" "OK" "INACTIVE=90; per-user ok"
else
  line | tee -a "$TXT_REPORT" >/dev/null
  log "4) Inactivité 90j => NON CONFORME"
  log "   Défaut useradd: $def_status"
  ((${#violators_inactive[@]})) && printf '   %s\n' "${violators_inactive[@]}" | tee -a "$TXT_REPORT" >/dev/null
  csv "4" "Inactive disabled after 90 days" "FAIL" "useradd:${def_status}; users:$(IFS=';'; echo "${violators_inactive[*]:-none}")"
fi

# --- 5) Verrouillage après 10 échecs / 15 min, blocage 60 min (faillock) -----

# Deux sources possibles des paramètres :
#  - /etc/security/faillock.conf (centralisé sur RHEL récents)
#  - lignes pam_faillock.so dans system-auth/password-auth (héritage / compléments)

# read_faillock : récupère la valeur d’une clé dans faillock.conf si présent.
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

# check_pam_faillock : lit un fichier PAM pour trouver deny/fail_interval/unlock_time.
#  - essaie d'abord d'extraire dans le PAM
#  - sinon (si manquant) réutilise les valeurs de faillock.conf si définies
#  - vérifie la conformité (10, 900, 3600)
check_pam_faillock() {
  local file="$1"
  [[ -r "$file" ]] || return 1

  local d fi ut
  d="$(grep -E 'pam_faillock\.so.*deny=' "$file" -h 2>/dev/null | sed -n 's/.*deny=\([0-9]\+\).*/\1/p' | head -1)"
  fi="$(grep -E 'pam_faillock\.so.*fail_interval=' "$file" -h 2>/dev/null | sed -n 's/.*fail_interval=\([0-9]\+\).*/\1/p' | head -1)"
  ut="$(grep -E 'pam_faillock\.so.*unlock_time=' "$file" -h 2>/dev/null | sed -n 's/.*unlock_time=\([0-9]\+\).*/\1/p' | head -1)"

  # Si la ligne PAM ne contient pas tout, on complète avec faillock.conf si dispo
  [[ -z "$d"  && -n "$deny"         ]] && d="$deny"
  [[ -z "$fi" && -n "$fail_interval" ]] && fi="$fail_interval"
  [[ -z "$ut" && -n "$unlock_time"   ]] && ut="$unlock_time"

  # Contrôle final : si on a bien des valeurs numériques pour les 3 paramètres
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

# On teste sur les deux piles PAM principales.
pam_sys="$(check_pam_faillock "$SYSTEM_AUTH")"; rc1=$?
pam_pwd="$(check_pam_faillock "$PASSWORD_AUTH")"; rc2=$?

# Conforme si au moins une pile est conforme (cas fréquent).
if (( rc1==0 || rc2==0 )); then
  line | tee -a "$TXT_REPORT" >/dev/null
  log "5) Faillock 10 échecs/15min, blocage 60min => OK"
  csv "5" "Lockout deny=10 in 15m, unlock 60m" "OK" "$pam_sys | $pam_pwd"
else
  line | tee -a "$TXT_REPORT" >/dev/null
  log "5) Faillock => NON CONFORME: $pam_sys | $pam_pwd"
  csv "5" "Lockout deny=10 in 15m, unlock 60m" "FAIL" "$pam_sys | $pam_pwd"
fi

# ---- 6) Réutilisation des 10 derniers mdp interdite (pam_pwhistory remember) --

# check_pwhistory : cherche pam_pwhistory.so ... remember=<N> et valide N>=10
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
  line | tee -a "$TXT_REPORT" >/dev/null
  log "6) Historique des mdp (≥10) => OK"
  csv "6" "No reuse last 10 passwords" "OK" "$pwh_sys | $pwh_pwd"
else
  line | tee -a "$TXT_REPORT" >/dev/null
  log "6) Historique des mdp (≥10) => NON CONFORME: $pwh_sys | $pwh_pwd"
  csv "6" "No reuse last 10 passwords" "FAIL" "$pwh_sys | $pwh_pwd"
fi

# -------- 7) Complexité utilisateurs : minlen>=8 + 4 classes de car. ---------

# Les paramètres de complexité pwquality possibles :
#   - minlen : longueur minimale absolue
#   - minclass : nombre de classes (maj, min, chiffres, autres)
#   - ucredit/lcredit/dcredit/ocredit :
#       * valeur négative => exige au moins |valeur| caractères de cette classe
#       * par convention “-1” => au moins 1 caractère de cette classe
get_pwq() { kv "$PWQUALITY_CONF" "$1" || true; }

minlen="$(get_pwq minlen)"
minclass="$(get_pwq minclass)"
ucredit="$(get_pwq ucredit)"; lcredit="$(get_pwq lcredit)"; dcredit="$(get_pwq dcredit)"; ocredit="$(get_pwq ocredit)"

classes_ok=false

# Deux façons d'être conforme sur les classes :
#   A) minclass >= 4 (global)
#   B) ucredit<=-1, lcredit<=-1, dcredit<=-1, ocredit<=-1 (au moins 1 de chaque)
if [[ "$minclass" =~ ^[0-9]+$ && "$minclass" -ge 4 ]]; then
  classes_ok=true
elif [[ "$ucredit" =~ ^-?[0-9]+$ && "$lcredit" =~ ^-?[0-9]+$ && "$dcredit" =~ ^-?[0-9]+$ && "$ocredit" =~ ^-?[0-9]+$ ]]; then
  if (( ucredit<=-1 && lcredit<=-1 && dcredit<=-1 && ocredit<=-1 )); then
    classes_ok=true
  fi
fi

if [[ "$minlen" =~ ^[0-9]+$ && "$minlen" -ge 8 ]] && $classes_ok; then
  line | tee -a "$TXT_REPORT" >/dev/null
  log "7) Complexité UTILISATEURS (≥8 + AZ/az/09/spécial) => OK"
  csv "7" "User complexity: minlen>=8 + 4 classes" "OK" "minlen=$minlen; minclass=${minclass:-}; u=$ucredit l=$lcredit d=$dcredit o=$ocredit"
else
  line | tee -a "$TXT_REPORT" >/dev/null
  log "7) Complexité UTILISATEURS => NON CONFORME (minlen=${minlen:-unset}, minclass=${minclass:-unset}, u=$ucredit l=$lcredit d=$dcredit o=$ocredit)"
  csv "7" "User complexity: minlen>=8 + 4 classes" "FAIL" "minlen=${minlen:-unset}; minclass=${minclass:-unset}; u=$ucredit l=$lcredit d=$dcredit o=$ocredit"
fi

# --- 8) Complexité service/privilégiés : minlen >= 15 (par design PAM) -------

# RHEL applique typiquement une politique globale dans pwquality.conf.
# Avoir minlen>=15 global => conforme.
# Si on veut un minlen différent pour un groupe (ex: “priv”),
#   il faut une pile PAM par condition (pam_succeed_if + pwquality), ce qui est rare.
pam_per_user_detected="no"
if [[ -r "$SYSTEM_AUTH"   ]] && grep -qE 'pam_succeed_if\.so.*(user|uid|group)' "$SYSTEM_AUTH";   then pam_per_user_detected="yes"; fi
if [[ -r "$PASSWORD_AUTH" ]] && grep -qE 'pam_succeed_if\.so.*(user|uid|group)' "$PASSWORD_AUTH"; then pam_per_user_detected="yes"; fi

if [[ "$minlen" =~ ^[0-9]+$ && "$minlen" -ge 15 ]]; then
  line | tee -a "$TXT_REPORT" >/dev/null
  log "8) Complexité SERVICE/PRIV (minlen≥15) => OK (minlen global=$minlen)"
  csv "8" "Service/privileged minlen>=15" "OK" "global minlen=$minlen"
else
  if [[ -n "${SERVICE_LIST}${PRIV_LIST}" && "$pam_per_user_detected" == "no" ]]; then
    line | tee -a "$TXT_REPORT" >/dev/null
    log "8) Complexité SERVICE/PRIV (minlen≥15) => NON CONFORME (minlen global=${minlen:-unset})"
    log "   NOTE: pour appliquer minlen≥15 aux seuls comptes service/privilégiés,"
    log "         mettez en place une pile PAM conditionnelle (ex: pam_succeed_if + pwquality)."
    csv "8" "Service/privileged minlen>=15" "FAIL" "global minlen=${minlen:-unset}; no per-user PAM detected"
  else
    line | tee -a "$TXT_REPORT" >/dev/null
    log "8) Complexité SERVICE/PRIV: IMPOSSIBLE À VALIDER précisément (minlen global=${minlen:-unset}; PAM per-user=${pam_per_user_detected})"
    csv "8" "Service/privileged minlen>=15" "WARN" "Cannot verify per-user policy reliably"
  fi
fi

# ------------------------------- Récapitulatif --------------------------------

line | tee -a "$TXT_REPORT" >/dev/null
log "Rapport texte : $TXT_REPORT"
log "Rapport CSV   : $CSV_REPORT"
line | tee -a "$TXT_REPORT" >/dev/null

exit 0
