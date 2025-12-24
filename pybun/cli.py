import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

from pybun import bootstrap


def _wants_json(argv: List[str]) -> bool:
    for idx, arg in enumerate(argv):
        if arg == "--format" and idx + 1 < len(argv) and argv[idx + 1] == "json":
            return True
        if arg.startswith("--format=") and arg.split("=", 1)[1] == "json":
            return True
    return False


def _emit_error_json(
    argv: List[str],
    message: str,
    detail: Optional[Dict[str, Any]],
    duration_ms: int,
) -> None:
    payload = {
        "version": "1",
        "command": "pybun" + (" " + " ".join(argv) if argv else ""),
        "status": "error",
        "duration_ms": duration_ms,
        "events": [],
        "diagnostics": [
            {
                "kind": "bootstrap_error",
                "message": message,
            }
        ],
    }
    if detail:
        payload["detail"] = detail
    json.dump(payload, sys.stdout)
    sys.stdout.write("\n")


def main(argv: Optional[List[str]] = None) -> None:
    argv = list(argv or sys.argv[1:])
    wants_json = _wants_json(argv)
    start = time.time()
    try:
        binary_path, _metadata = bootstrap.ensure_binary()
    except bootstrap.BootstrapError as exc:
        if wants_json:
            detail = {"shim": {"error": str(exc)}}
            duration_ms = int((time.time() - start) * 1000)
            _emit_error_json(argv, str(exc), detail, duration_ms)
        else:
            sys.stderr.write(f"error: {exc}\n")
        sys.exit(1)

    try:
        os.execv(binary_path, [binary_path] + argv)
    except FileNotFoundError as exc:
        message = f"failed to execute pybun binary: {exc}"
        if wants_json:
            detail = {"shim": {"binary": binary_path}}
            duration_ms = int((time.time() - start) * 1000)
            _emit_error_json(argv, message, detail, duration_ms)
        else:
            sys.stderr.write(f"error: {message}\n")
        sys.exit(1)
    except OSError as exc:
        message = f"failed to execute pybun binary: {exc}"
        if wants_json:
            detail = {"shim": {"binary": binary_path}}
            duration_ms = int((time.time() - start) * 1000)
            _emit_error_json(argv, message, detail, duration_ms)
        else:
            sys.stderr.write(f"error: {message}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
