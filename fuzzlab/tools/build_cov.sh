#!/usr/bin/env bash
set -euo pipefail

LAB=${LAB:-$HOME/xpdf-lab}
TARBALL=${TARBALL:-$HOME/fuzzlab/xpdf-3.02.tar.gz}
JOBS=${JOBS:-$(nproc 2>/dev/null || echo 2)}

[ -f "$TARBALL" ] || { echo "Cannot find $TARBALL (set TARBALL=... if it is elsewhere)" >&2; exit 1; }
command -v clang >/dev/null || { echo "clang is required (sudo apt install clang llvm)" >&2; exit 1; }

mkdir -p "$LAB/cov"
cd "$LAB/cov"
rm -rf xpdf-3.02
tar -xzf "$TARBALL"
cd xpdf-3.02

export CC=clang CXX=clang++
export CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping"
export CXXFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping"
export LDFLAGS="-fprofile-instr-generate"

./configure --prefix="$LAB/install_cov" --without-x
make -j"$JOBS"
make install

if [ "$(nm "$LAB/install_cov/bin/pdfinfo" | grep -c __llvm_profile)" -gt 0 ]; then
  echo "[OK] $LAB/install_cov/bin/pdfinfo was built with coverage instrumentation"
else
  echo "[ERROR] no __llvm_profile symbols found in pdfinfo" >&2
  exit 1
fi
