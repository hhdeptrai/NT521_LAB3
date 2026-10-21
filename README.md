# NT521_LAB3

Lab 3 - Fuzzing, NT521. Snapshot of the work performed in Ubuntu on WSL2.

## Contents

- `xpdf-lab/`: the complete local lab snapshot, including Xpdf 3.02 sources,
  instrumented executables, seed PDF, fuzzing corpora, workspaces/crash reports,
  and logs of the independent 1, 3, and 5 minute runs.
- `fuzzlab/`: the original Xpdf source archive and the supplied coverage scripts.
- `fuzzlab.zip`: the original lab resource package.
- `honggfuzz/`: upstream tool as a Git submodule, pinned to the exact source
  revision used locally (`940b958dfeb6f9131fd846cae31fcc0fe996ae98`).
- `docs/`: dashboard screenshot and an inventory of the uploaded snapshot.

The duplicate resources found in `~/NT521/fuzzlab` match `~/fuzzlab` and have
been consolidated into a single folder. Original working folders are preserved.
The submodule stores honggfuzz's tracked source, not its generated build files.
Xpdf build outputs are included to preserve the original lab work.

## Clone

```bash
git clone --recurse-submodules https://github.com/hhdeptrai/NT521_LAB3.git
cd NT521_LAB3
```

## Rebuild honggfuzz

```bash
sudo apt update
sudo apt install -y git build-essential clang llvm binutils-dev libunwind-dev libblocksruntime-dev python3 unzip xxd
cd honggfuzz
make -j"$(nproc)" CC=clang CXX=clang++
```

The archived Xpdf build configuration records the original absolute paths under
`/home/lehuuhoang/`. Reconfigure and rebuild Xpdf when restoring elsewhere.
Logs produced by `script` contain terminal control sequences.

## Recorded runs

The table below is populated from each log's final `Summary` line. Crash counts
are total events reported by the fuzzer, not counts of distinct confirmed bugs.

| Run | Actual seconds | Iterations | Average exec/s | Crash events | Timeouts | Edge coverage |
|---|---:|---:|---:|---:|---:|---:|
| 1 min | 61 | 10348 | 169 | 4 | 4 | 5% |
| 3 min | 181 | 31815 | 175 | 2 | 3 | 5% |
| 5 min | 301 | 38665 | 128 | 5 | 9 | 5% |

## Snapshot verification

`docs/snapshot_manifest.json` lists the original locations, file sizes and SHA-256
hashes for every copied file. `docs/source_inventory.json` records source-folder
counts and the honggfuzz revision. The original folders were copied without
modifying them. This repository is private.

Xpdf and honggfuzz retain their upstream license notices in their source trees.
