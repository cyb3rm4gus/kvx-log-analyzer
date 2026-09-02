#!/usr/bin/env python3
"""Regenerate requirements.txt (fully pinned, hashed) for the RUNTIME image (CPython 3.12,
manylinux) — txnscanner's pattern. `pip install --require-hashes` then fails closed on a
tampered or substituted wheel.   python3 scripts/gen_requirements.py"""
from __future__ import annotations

import hashlib
import pathlib
import re
import subprocess
import sys
import tempfile

DEPS = [
    "fastapi==0.141.1",
    "uvicorn[standard]==0.52.4",
    "jinja2==3.1.6",
    "httpx==0.28.1",
    "python-multipart==0.0.32",
    "ua-parser[regex]==1.0.2",
    "dnspython==2.8.0",
]
HEADER = """# Fully pinned dependency closure with hashes, resolved for the RUNTIME image
# (CPython 3.12, manylinux2014_x86_64) -- not for the dev machine.
# Regenerate with:  python3 scripts/gen_requirements.py
# `pip install --require-hashes` fails closed: a tampered or substituted wheel
# aborts the build.
"""


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(
            [sys.executable, "-m", "pip", "download", "-q", "-d", tmp, "--only-binary=:all:",
             "--python-version", "3.12", "--implementation", "cp",
             "--platform", "manylinux2014_x86_64", "--platform", "manylinux_2_17_x86_64",
             "--platform", "manylinux_2_28_x86_64", "--platform", "manylinux_2_34_x86_64", *DEPS],
            check=True,
        )
        rows = []
        for whl in sorted(pathlib.Path(tmp).glob("*.whl")):
            name, version = whl.name.split("-")[0], whl.name.split("-")[1]
            rows.append((re.sub(r"[-_.]+", "-", name).lower(), version,
                         hashlib.sha256(whl.read_bytes()).hexdigest()))
    body = "\n".join(f"{n}=={v} \\\n    --hash=sha256:{h}" for n, v, h in sorted(rows))
    (root / "requirements.txt").write_text(f"{HEADER}\n{body}\n")
    print(f"wrote requirements.txt with {len(rows)} pinned wheels")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
