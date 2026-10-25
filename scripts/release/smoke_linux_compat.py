#!/usr/bin/env python3
"""Run the packaged GNU binary on the supported GLIBC 2.34 baseline."""

import argparse
from pathlib import Path
import subprocess
import tarfile
import tempfile

from generate_manifest import glibc_requirement

BASELINE = "2.34"
IMAGE = "almalinux:9@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--target", required=True, choices=[
        "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"])
    args = parser.parse_args()
    required = glibc_requirement(args.archive, args.target)
    if tuple(map(int, required.split("."))) > tuple(map(int, BASELINE.split("."))):
        raise ValueError(f"ELF needs GLIBC {required}, exceeding supported baseline {BASELINE}")
    platform = "linux/amd64" if args.target.startswith("x86_64-") else "linux/arm64"
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(args.archive) as bundle:
        binary = Path(tmp) / "pybun"
        binary.write_bytes(bundle.extractfile(f"pybun-{args.target}/pybun").read())
        binary.chmod(0o755)
        result = subprocess.run([
            "docker", "run", "--rm", "--platform", platform, "--network", "none",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-v", f"{binary}:/pybun:ro", IMAGE, "sh", "-ec",
            "test \"$(getconf GNU_LIBC_VERSION)\" = 'glibc 2.34'; /pybun --version",
        ], check=True, capture_output=True, text=True, timeout=300)
    if not result.stdout.startswith("pybun "):
        raise ValueError("Packaged binary did not report a PyBun version")
    print(f"{args.target}: ELF GLIBC {required}, runtime GLIBC {BASELINE}: {result.stdout.strip()}")


if __name__ == "__main__":
    main()
