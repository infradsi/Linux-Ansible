!/usr/bin/env bash
# fait_le_job.sh
# Script Template For Linux v1

set -euo pipefail


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