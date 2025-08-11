#!/usr/bin/env bash
# disk_usage_audit.sh
# Find what's taking space on a Linux server (RHEL/CentOS/Alma/Rocky/Ubuntu).
# Requires: coreutils (du, sort, head), findutils; optional: numfmt, journalctl, rpm.

set -euo pipefail

TARGET="/"
DEPTH=2            # du depth for directory breakdown
TOP=20             # how many top items to show for dirs/files
CSV_OUT=""         # optional CSV path
ALL_MOUNTS=0       # 0 = stay on same FS (-xdev); 1 = traverse all mounts

usage() {
  cat <<EOF
Usage: $(basename "$0") [-p PATH] [-d DEPTH] [-n TOP] [-o CSV] [--all-mounts]
  -p PATH       Start path (default: /)
  -d DEPTH      Max depth for directory sizes (default: 2)
  -n TOP        How many top items to list (default: 20)
  -o CSV        Also write a CSV report to this path
  --all-mounts  Traverse all mount points (default: off, i.e. stay on one FS)
EOF
  exit 0
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -p) TARGET="${2:-/}"; shift 2 ;;
    -d) DEPTH="${2:-2}"; shift 2 ;;
    -n) TOP="${2:-20}"; shift 2 ;;
    -o) CSV_OUT="${2:-}"; shift 2 ;;
    --all-mounts) ALL_MOUNTS=1; shift ;;
    -h|--help) usage ;;
    *) echo "Unknown arg: $1"; usage ;;
  endcase
done 2>/dev/null || true

[[ -d "$TARGET" ]] || { echo "Path not found: $TARGET" >&2; exit 1; }

HRT() { # human readable size
  if command -v numfmt >/dev/null 2>&1; then numfmt --to=iec --suffix=B "$1"; else
    awk -v s="$1" 'function hr(x){split("B,KB,MB,GB,TB,PB",u,",");i=1;while(x>=1024&&i<6){x/=1024;i++} printf("%.1f%s",x,u[i]);}
                   BEGIN{hr(s)}'
  fi
}

XDEV=()
[[ $ALL_MOUNTS -eq 0 ]] && XDEV=(-x)

echo "=== Disk overview ($(date -u '+%Y-%m-%d %H:%M:%S UTC')) ==="
df -hT "$TARGET"
echo

# CSV header if requested
if [[ -n "$CSV_OUT" ]]; then
  mkdir -p "$(dirname "$CSV_OUT")"
  echo "type,size_bytes,size_human,path" > "$CSV_OUT"
fi

echo "=== Top $TOP directories under $TARGET (depth=$DEPTH) ==="
# Use bytes for numeric sort, then render human
# -x: stay on one FS (emulated via --one-file-system = -x)
# RHEL: du supports -B1 and --max-depth
if du -B1 --version >/dev/null 2>&1; then
  DU_CMD=(du -B1 "${XDEV[@]/#/-x}" --max-depth="$DEPTH" -- "$TARGET")
else
  DU_CMD=(du -b "${XDEV[@]/#/-x}" --max-depth="$DEPTH" -- "$TARGET")
fi

# shellcheck disable=SC2068
"${DU_CMD[@]}" 2>/dev/null | sort -nr | head -n "$TOP" | while read -r bytes path; do
  printf "%8s  %s\n" "$(HRT "$bytes")" "$path"
  [[ -n "$CSV_OUT" ]] && printf "directory,%s,%s,%s\n" "$bytes" "$(HRT "$bytes")" "$path" >> "$CSV_OUT"
done
echo

echo "=== Top $TOP files under $TARGET ==="
# Note: uses newline delimiter; unusual filenames with newlines may render oddly.
# Stay on one FS via -xdev unless --all-mounts given.
FIND_OPTS=("$TARGET" -type f)
[[ $ALL_MOUNTS -eq 0 ]] && FIND_OPTS=("$TARGET" -xdev -type f)

LC_ALL=C find "${FIND_OPTS[@]}" -printf '%s\t%p\n' 2>/dev/null \
  | sort -nr \
  | head -n "$TOP" \
  | while IFS=$'\t' read -r bytes path; do
      printf "%8s  %s\n" "$(HRT "$bytes")" "$path"
      [[ -n "$CSV_OUT" ]] && printf "file,%s,%s,%s\n" "$bytes" "$(HRT "$bytes")" "$path" >> "$CSV_OUT"
    done
echo

# Extra diagnostics (best-effort, skip if tools missing)
if command -v journalctl >/dev/null 2>&1; then
  echo "=== systemd-journald usage ==="
  journalctl --disk-usage || true
  echo
fi

if command -v rpm >/dev/null 2>&1; then
  echo "=== Top $TOP installed RPMs by package size (not exact on-disk usage) ==="
  rpm -qa --queryformat '%{SIZE}\t%{NAME}\n' \
    | sort -nr | head -n "$TOP" \
    | while IFS=$'\t' read -r bytes name; do
        printf "%8s  %s\n" "$(HRT "$bytes")" "$name"
        [[ -n "$CSV_OUT" ]] && printf "rpm,%s,%s,%s\n" "$bytes" "$(HRT "$bytes")" "$name" >> "$CSV_OUT"
      done
  echo
fi

if command -v docker >/dev/null 2>&1; then
  echo "=== Docker disk usage (if Docker is running) ==="
  docker system df || true
  echo
fi

if command -v lvs >/dev/null 2>&1; then
  echo "=== LVM logical volumes (size and data% if thinp) ==="
  lvs --noheadings -o vg_name,lv_name,lv_size,data_percent 2>/dev/null | sed 's/^ *//'
  echo
fi

echo "Done."
[[ -n "$CSV_OUT" ]] && echo "CSV written to: $CSV_OUT"
