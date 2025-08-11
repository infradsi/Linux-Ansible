#!/usr/bin/env bash
# check_disk_usage.sh
# Diagnose space usage on Linux. Supports single FS, all mounts, or per-FS iteration.

set -euo pipefail

TARGET="/"
DEPTH=2
TOP=20
CSV_OUT=""
MODE="single"   # single | all | each-fs
VERBOSE=0

usage() {
  cat <<EOF
Usage: $(basename "$0") [-p PATH] [-d DEPTH] [-n TOP] [-o CSV] [--all-mounts|--each-fs] [-v]
  -p PATH         Start path (default: /)
  -d DEPTH        du --max-depth (default: 2)
  -n TOP          How many items to show (default: 20)
  -o CSV          Also write CSV report to this file
  --all-mounts    Traverse ALL mounts in one pass (MODE=all)
  --each-fs       Run a separate report per real filesystem (MODE=each-fs)
  -v              Verbose
  -h, --help      This help
EOF
  exit "${1:-0}"
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p) TARGET="${2:-/}"; shift 2 ;;
    -d) DEPTH="${2:-2}"; shift 2 ;;
    -n) TOP="${2:-20}"; shift 2 ;;
    -o) CSV_OUT="${2:-}"; shift 2 ;;
    --all-mounts) MODE="all"; shift ;;
    --each-fs) MODE="each-fs"; shift ;;
    -v) VERBOSE=$((VERBOSE+1)); shift ;;
    -h|--help) usage 0 ;;
    *) echo "Unknown arg: $1" >&2; usage 1 ;;
  esac
done

[[ -d "$TARGET" ]] || { echo "Path not found: $TARGET" >&2; exit 1; }

log(){ [[ $VERBOSE -gt 0 ]] && echo "[*] $*"; }

HRT() {
  if command -v numfmt >/dev/null 2>&1; then numfmt --to=iec --suffix=B "$1"
  else awk -v s="$1" 'function hr(x){split("B,KB,MB,GB,TB,PB",u,",");i=1;while(x>=1024&&i<6){x/=1024;i++} printf("%.1f%s",x,u[i]);} BEGIN{hr(s)}'
  fi
}

csv_header(){
  [[ -n "$CSV_OUT" ]] || return 0
  mkdir -p "$(dirname "$CSV_OUT")"
  echo "type,fs,base,size_bytes,size_human,path" > "$CSV_OUT"
}

csv_row(){ # type, fs, base, bytes, hr, path
  [[ -n "$CSV_OUT" ]] && printf '%s,"%s","%s",%s,"%s","%s"\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$CSV_OUT"
}

du_top_dirs(){
  local base="$1" fsname="$2" du_x=()
  [[ "$MODE" == "single" ]] && du_x=(--one-file-system)
  # prefer -B1; fallback -b
  if du -B1 --version >/dev/null 2>&1; then
    du -B1 "${du_x[@]}" --max-depth="$DEPTH" -- "$base"
  else
    du -b  "${du_x[@]}" --max-depth="$DEPTH" -- "$base"
  fi | sort -nr | head -n "$TOP" | while read -r bytes path; do
      printf "%8s  %s\n" "$(HRT "$bytes")" "$path"
      csv_row directory "$fsname" "$base" "$bytes" "$(HRT "$bytes")" "$path"
    done
}

find_top_files(){
  local base="$1" fsname="$2" ; local -a fopts=("$base" -type f)
  [[ "$MODE" == "single" ]] && fopts=("$base" -xdev -type f)
  LC_ALL=C find "${fopts[@]}" -printf '%s\t%p\n' 2>/dev/null \
    | sort -nr | head -n "$TOP" | while IFS=$'\t' read -r bytes path; do
        printf "%8s  %s\n" "$(HRT "$bytes")" "$path"
        csv_row file "$fsname" "$base" "$bytes" "$(HRT "$bytes")" "$path"
      done
}

overview(){
  echo "=== Disk overview ($(date -u '+%Y-%m-%d %H:%M:%S UTC')) ==="
  df -hT "$1" || df -h "$1" || true
  echo
}

journal_diag(){
  if command -v journalctl >/dev/null 2>&1; then
    echo "=== systemd-journald usage ==="; journalctl --disk-usage || true; echo
  fi
}

packages_diag(){
  if command -v rpm >/dev/null 2>&1; then
    echo "=== Top $TOP installed RPMs by package size (approx) ==="
    rpm -qa --queryformat '%{SIZE}\t%{NAME}\n' | sort -nr | head -n "$TOP" \
      | while IFS=$'\t' read -r bytes name; do
          printf "%8s  %s\n" "$(HRT "$bytes")" "$name"
          csv_row rpm "-" "-" "$bytes" "$(HRT "$bytes")" "$name"
        done
    echo
  fi
}

docker_diag(){
  if command -v docker >/dev/null 2>&1; then
    echo "=== Docker disk usage (if Docker is running) ==="
    docker system df || true
    echo
  fi
}

lvm_diag(){
  if command -v lvs >/dev/null 2>&1; then
    echo "=== LVM logical volumes (size and data% if thinp) ==="
    lvs --noheadings -o vg_name,lv_name,lv_size,data_percent 2>/dev/null | sed 's/^ *//'
    echo
  fi
}

# Enumerate real filesystems (skip virtual)
list_mounts(){
  local EXCLUDE='^(tmpfs|devtmpfs|proc|sysfs|cgroup|cgroup2|pstore|debugfs|tracefs|ramfs|squashfs|overlayfs|efivarfs|fusectl)$'
  if command -v findmnt >/dev/null 2>&1; then
    findmnt -rn -o TARGET,FSTYPE | awk -v rx="$EXCLUDE" '$2 !~ rx {print $1 "|" $2}'
  else
    df -PT | awk 'NR>1{print $6"|"$2}' | awk -F'|' -v rx="$EXCLUDE" '$2 !~ rx'
  fi
}

run_single(){
  local base="$1"
  overview "$base"
  echo "=== Top $TOP directories under $base (depth=$DEPTH) ==="
  du_top_dirs "$base" "-"
  echo
  echo "=== Top $TOP files under $base ==="
  find_top_files "$base" "-"
  echo
  journal_diag
  packages_diag
  docker_diag
  lvm_diag
  echo "Done."
}

run_each_fs(){
  local line mp fstype
  while IFS= read -r line; do
    mp="${line%%|*}"; fstype="${line##*|}"
    echo ">>> Filesystem: $mp  (type: $fstype)"
    overview "$mp"
    echo "=== Top $TOP directories under $mp (depth=$DEPTH) ==="
    du_top_dirs "$mp" "$fstype"
    echo
    echo "=== Top $TOP files under $mp ==="
    find_top_files "$mp" "$fstype"
    echo
  done < <(list_mounts)
  journal_diag
  packages_diag
  docker_diag
  lvm_diag
  echo "Done."
}

csv_header
case "$MODE" in
  single)   run_single "$TARGET" ;;
  all)      # same as single, but without one-file-system restriction
            run_single "$TARGET" ;;
  each-fs)  run_each_fs ;;
esac
[[ -n "$CSV_OUT" ]] && echo "CSV written to: $CSV_OUT"
