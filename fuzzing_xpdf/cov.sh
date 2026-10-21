#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "Usage: bash cov.sh <corpus_dir> <report_name>"
    exit 1
fi

CORPUS="$(realpath "$1")"
NAME="$2"

BIN="$HOME/fuzzing_xpdf/llvm_install/bin/pdfinfo"
REPORT="$HOME/fuzzing_xpdf/cov_reports/$NAME"

mkdir -p "$REPORT/profiles"
rm -f "$REPORT/profiles/"*.profraw

ulimit -c 0

count=0

for f in "$CORPUS"/*; do
    [ -f "$f" ] || continue

    LLVM_PROFILE_FILE="$REPORT/profiles/${count}.profraw" \
        timeout 5s "$BIN" "$f" >/dev/null 2>&1 || true

    count=$((count + 1))
done

echo "Processed $count corpus files"

shopt -s nullglob
profiles=("$REPORT"/profiles/*.profraw)

if [ "${#profiles[@]}" -eq 0 ]; then
    echo "No profile data collected"
    exit 1
fi

llvm-profdata merge -sparse \
    "${profiles[@]}" \
    -o "$REPORT/merged.profdata"

llvm-cov report "$BIN" \
    -instr-profile="$REPORT/merged.profdata" \
    > "$REPORT/summary.txt"

cat "$REPORT/summary.txt"

echo
echo "Report saved: $REPORT/summary.txt"
