#!/usr/bin/env bash
set -euo pipefail

CORPUS=${1:?Usage: cov.sh <corpus_dir> [label]}
LABEL=${2:-$(basename "$CORPUS")}
LAB=${LAB:-$HOME/xpdf-lab}
BIN=${BIN:-$LAB/install_cov/bin/pdfinfo}
SRC=${SRC:-$LAB/cov/xpdf-3.02}
FILES=${FILES:-"XRef.cc Parser.cc Lexer.cc Catalog.cc PDFDoc.cc Decrypt.cc Object.cc Dict.cc Array.cc Page.cc Stream.cc"}
TOP=${TOP:-12}
PER_FILE_TIMEOUT=${PER_FILE_TIMEOUT:-5}

[ -d "$CORPUS" ] || { echo "Corpus directory not found: $CORPUS" >&2; exit 1; }
[ -x "$BIN" ]    || { echo "$BIN not found, run tools/build_cov.sh first" >&2; exit 1; }

pick() { for c in "$@"; do if command -v "$c" >/dev/null 2>&1; then echo "$c"; return 0; fi; done; return 1; }
if [ -z "${LLVM_PROFDATA:-}" ]; then
  LLVM_PROFDATA=$(pick llvm-profdata llvm-profdata-19 llvm-profdata-18 llvm-profdata-17 llvm-profdata-16 llvm-profdata-15 llvm-profdata-14) \
    || { echo "llvm-profdata not found (install the llvm package or set LLVM_PROFDATA=...)" >&2; exit 1; }
fi
if [ -z "${LLVM_COV:-}" ]; then
  LLVM_COV=$(pick llvm-cov llvm-cov-19 llvm-cov-18 llvm-cov-17 llvm-cov-16 llvm-cov-15 llvm-cov-14) \
    || { echo "llvm-cov not found (install the llvm package or set LLVM_COV=...)" >&2; exit 1; }
fi
TO=$(command -v timeout || command -v gtimeout || true)

OUT=$LAB/cov_reports/$LABEL
rm -rf "$OUT"
mkdir -p "$OUT/prof"

total=$(find "$CORPUS" -maxdepth 1 -type f | wc -l)
echo "Measuring $total files from $CORPUS (this can take a few minutes) ..." >&2

n=0; bad=0
while IFS= read -r -d '' f; do
  n=$((n + 1))
  rc=0
  LLVM_PROFILE_FILE="$OUT/prof/cov-%m.profraw" ${TO:+$TO $PER_FILE_TIMEOUT} "$BIN" "$f" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ge 124 ]; then bad=$((bad + 1)); fi
  if [ $((n % 200)) -eq 0 ]; then echo "  $n / $total files done" >&2; fi
done < <(find "$CORPUS" -maxdepth 1 -type f -print0)

[ "$n" -gt 0 ] || { echo "No files in $CORPUS" >&2; exit 1; }
ls "$OUT"/prof/*.profraw >/dev/null 2>&1 || { echo "No profile data was produced (did every run crash or time out?)" >&2; exit 1; }

"$LLVM_PROFDATA" merge -sparse "$OUT"/prof/*.profraw -o "$OUT/cov.profdata"
"$LLVM_COV" export "$BIN" -instr-profile="$OUT/cov.profdata" > "$OUT/export.json"

python3 -I - "$OUT" "$SRC" "$FILES" "$TOP" "$n" "$bad" "$CORPUS" <<'PY'
import json, os, shutil, subprocess, sys

out, src, files, top, nfiles, nbad, corpus = sys.argv[1:8]
top, nfiles, nbad = int(top), int(nfiles), int(nbad)
wanted = set(files.split())
data = json.load(open(os.path.join(out, "export.json")))["data"][0]


def base(p):
    return os.path.basename(p)


def read_lines(path):
    for cand in (path, os.path.join(src, "xpdf", base(path)), os.path.join(src, base(path))):
        if os.path.isfile(cand):
            with open(cand, errors="replace") as fh:
                return fh.read().split("\n")
    return None


rows, tot_cnt, tot_cov = [], 0, 0
for f in data["files"]:
    if base(f["filename"]) not in wanted:
        continue
    ln = f["summary"]["lines"]
    rows.append((base(f["filename"]), ln["covered"], ln["count"], ln["percent"]))
    tot_cnt += ln["count"]
    tot_cov += ln["covered"]
rows.sort()
pct = 100.0 * tot_cov / tot_cnt if tot_cnt else 0.0
all_ln = data["totals"]["lines"]

lines = []
lines.append("Corpus: %s  (%d files, %d crashes/timeouts)" % (corpus, nfiles, nbad))
lines.append("%-14s %8s %8s %8s" % ("File", "Covered", "Lines", "%"))
for name, c, t, p in rows:
    lines.append("%-14s %8d %8d %7.2f%%" % (name, c, t, p))
lines.append("-" * 42)
lines.append("%-14s %8d %8d %7.2f%%" % ("TOTAL", tot_cov, tot_cnt, pct))
lines.append("Whole program: %.2f%% (%d/%d lines)" % (
    all_ln["percent"], all_ln["covered"], all_ln["count"]))
text = "\n".join(lines)
print(text)
open(os.path.join(out, "summary.txt"), "w").write(text + "\n")

funcs = []
for fn in data["functions"]:
    fns = fn["filenames"]
    if not fns or base(fns[0]) not in wanted:
        continue
    regs = [r for r in fn["regions"] if r[5] == 0 and r[7] == 0]
    if not regs:
        continue
    start = min(r[0] for r in regs)
    end = max(r[2] for r in regs)
    funcs.append({"name": fn["name"], "file": fns[0], "count": fn["count"],
                  "start": start, "end": end, "regs": regs})

for f in funcs:
    prefix = base(f["file"]) + ":"
    if f["name"].startswith(prefix):
        f["name"] = f["name"][len(prefix):]

names = [f["name"] for f in funcs]
filt = shutil.which("llvm-cxxfilt") or shutil.which("c++filt")
if filt and names:
    try:
        dem = subprocess.run([filt], input="\n".join(names), capture_output=True, text=True).stdout.split("\n")
        if len(dem) >= len(names):
            for f, d in zip(funcs, dem):
                f["name"] = d
    except OSError:
        pass

never = sorted((f for f in funcs if f["count"] == 0), key=lambda f: f["end"] - f["start"], reverse=True)
partial = []
for f in funcs:
    if f["count"] > 0:
        miss = [r for r in f["regs"] if r[4] == 0]
        if miss:
            partial.append((len(miss), f, miss))
partial.sort(key=lambda x: x[0], reverse=True)

rep = []
rep.append("# Xpdf 3.02 source regions NOT reached by corpus '%s'" % corpus)
rep.append("# (files considered: %s)" % " ".join(sorted(wanted)))
rep.append("# Note: pdfinfo does NOT render page content, so many functions below may be unreachable from pdfinfo.")
rep.append("")
rep.append("## A. Functions never called (top %d by length)" % top)
for f in never[:top]:
    rep.append("")
    rep.append("### %s   [%s:%d-%d]" % (f["name"], base(f["file"]), f["start"], f["end"]))
    sl = read_lines(f["file"])
    if sl:
        seg = sl[f["start"] - 1:min(f["end"], f["start"] + 39)]
        rep.extend(seg)
        if f["end"] - f["start"] >= 40:
            rep.append("... (truncated)")
rep.append("")
rep.append("## B. Functions that ran but have uncovered branches (top %d by number of uncovered regions)" % top)
for nmiss, f, miss in partial[:top]:
    rep.append("")
    rep.append("### %s   [%s:%d-%d]  (%d uncovered regions)" % (f["name"], base(f["file"]), f["start"], f["end"], nmiss))
    sl = read_lines(f["file"])
    seen = set()
    for r in sorted(miss)[:8]:
        if r[0] in seen:
            continue
        seen.add(r[0])
        txt = sl[r[0] - 1].strip() if sl and r[0] - 1 < len(sl) else ""
        rep.append("  L%d: %s" % (r[0], txt))
open(os.path.join(out, "uncovered.txt"), "w").write("\n".join(rep) + "\n")
print("\nWrote: %s/summary.txt, uncovered.txt" % out)
PY
