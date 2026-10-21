#!/usr/bin/env python3
import subprocess
from pathlib import Path

HOME = Path.home()
BASE = HOME / "fuzzing_xpdf"

PDFINFO = BASE / "install/bin/pdfinfo"

CORPUS = {
    "Honggfuzz B1": BASE / "honggfuzz_corpus",
    "AFL++ B11": BASE / "output/default/queue",
    "AFL++ B12 Dictionary": BASE / "output_dict/default/queue",
}

for name, folder in CORPUS.items():
    valid = 0
    invalid = 0
    timeout_count = 0
    total = 0

    print(f"\n===== {name} =====")

    for f in sorted(folder.iterdir()):
        if not f.is_file():
            continue

        if f.name.startswith("README"):
            continue

        total += 1

        try:
            result = subprocess.run(
                [str(PDFINFO), str(f)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=3
            )

            if result.returncode == 0:
                valid += 1
            else:
                invalid += 1

        except subprocess.TimeoutExpired:
            timeout_count += 1

    print(f"Total files : {total}")
    print(f"Readable    : {valid}")
    print(f"Rejected    : {invalid}")
    print(f"Timeout     : {timeout_count}")

    if total:
        print(f"Readable %  : {valid / total * 100:.2f}%")
        print(f"Rejected %  : {invalid / total * 100:.2f}%")
        print(f"Timeout %   : {timeout_count / total * 100:.2f}%")
