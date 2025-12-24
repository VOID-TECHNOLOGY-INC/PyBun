import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import urllib.request
import zipfile
from typing import Any, Dict, Optional, Tuple

DEFAULT_STABLE_MANIFEST = "https://github.com/pybun/pybun/releases/latest/download/pybun-release.json"
DEFAULT_NIGHTLY_MANIFEST = "https://github.com/pybun/pybun/releases/download/nightly/pybun-release.json"


class BootstrapError(RuntimeError):
    pass


def _bool_env(name: str) -> bool:
    value = os.environ.get(name)
    if value is None:
        return False
    return value.lower() in {"1", "true", "yes"}


def cache_root() -> str:
    return os.environ.get("PYBUN_HOME") or os.path.join(os.path.expanduser("~"), ".cache", "pybun")


def detect_musl() -> bool:
    libc, _ = platform.libc_ver()
    if libc and "musl" in libc.lower():
        return True
    ldd = shutil.which("ldd")
    if ldd:
        try:
            output = subprocess.check_output([ldd, "--version"], stderr=subprocess.STDOUT)
            if b"musl" in output.lower():
                return True
        except Exception:
            pass
    return os.path.exists("/lib/ld-musl-x86_64.so.1") or os.path.exists("/lib/ld-musl-aarch64.so.1")


def detect_target(
    system: Optional[str] = None,
    machine: Optional[str] = None,
    is_musl: Optional[bool] = None,
) -> str:
    system = system or platform.system()
    machine = (machine or platform.machine()).lower()

    if system == "Darwin":
        if machine in {"arm64", "aarch64"}:
            return "aarch64-apple-darwin"
        if machine in {"x86_64", "amd64"}:
            return "x86_64-apple-darwin"
        raise BootstrapError(f"unsupported macOS arch: {machine}")

    if system == "Linux":
        if machine in {"x86_64", "amd64"}:
            if is_musl is None:
                is_musl = detect_musl()
            return "x86_64-unknown-linux-musl" if is_musl else "x86_64-unknown-linux-gnu"
        if machine in {"aarch64", "arm64"}:
            return "aarch64-unknown-linux-gnu"
        raise BootstrapError(f"unsupported Linux arch: {machine}")

    if system == "Windows":
        raise BootstrapError("Windows shim not yet available; use install.ps1 or winget")

    raise BootstrapError(f"unsupported OS: {system}")


def resolve_manifest_source() -> str:
    override = os.environ.get("PYBUN_PYPI_MANIFEST") or os.environ.get("PYBUN_INSTALL_MANIFEST")
    if override:
        return override
    channel = os.environ.get("PYBUN_PYPI_CHANNEL", "stable")
    if channel == "nightly":
        return DEFAULT_NIGHTLY_MANIFEST
    return DEFAULT_STABLE_MANIFEST


def _read_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_manifest(source: str) -> Dict[str, Any]:
    if source.startswith("file://"):
        path = source[len("file://") :]
        return _read_json(path)
    if source.startswith("http://") or source.startswith("https://"):
        try:
            with urllib.request.urlopen(source, timeout=30) as resp:
                body = resp.read()
        except Exception as exc:
            raise BootstrapError(f"failed to fetch manifest: {exc}") from exc
        try:
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise BootstrapError(f"failed to parse manifest: {exc}") from exc
    if os.path.exists(source):
        return _read_json(source)
    raise BootstrapError(f"manifest not found: {source}")


def select_asset(manifest: Dict[str, Any], target: str) -> Dict[str, Any]:
    for asset in manifest.get("assets", []):
        if asset.get("target") == target:
            return asset
    raise BootstrapError(f"no asset for target: {target}")


def _download_url(url: str, destination: str) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "file":
        path = urllib.request.url2pathname(parsed.path)
        if not os.path.exists(path):
            raise BootstrapError(f"local asset not found: {path}")
        shutil.copyfile(path, destination)
        return

    if parsed.scheme in {"http", "https"}:
        try:
            with urllib.request.urlopen(url, timeout=300) as resp, open(
                destination, "wb"
            ) as handle:
                shutil.copyfileobj(resp, handle)
        except Exception as exc:
            raise BootstrapError(f"failed to download asset: {exc}") from exc
        return

    raise BootstrapError(f"unsupported asset URL: {url}")


def _verify_checksum(path: str, expected: Optional[str]) -> None:
    if not expected:
        raise BootstrapError("manifest missing sha256 for asset")
    expected_clean = expected
    if expected_clean.startswith("sha256:"):
        expected_clean = expected_clean[len("sha256:") :]
    if expected_clean in {"sha256:placeholder", "placeholder"}:
        return
    hasher = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    actual = hasher.hexdigest()
    if actual != expected_clean:
        raise BootstrapError(f"checksum mismatch: expected {expected_clean}, got {actual}")


def _verify_signature(path: str, signature: Dict[str, Any]) -> None:
    sig_type = signature.get("type")
    sig_value = signature.get("value")
    sig_pub = signature.get("public_key")
    if sig_type != "minisign":
        raise BootstrapError(f"unsupported signature type: {sig_type}")
    if not sig_value or not sig_pub:
        raise BootstrapError("signature missing value or public key")
    if not shutil.which("minisign"):
        raise BootstrapError("minisign is required for signature verification")

    with tempfile.TemporaryDirectory(prefix="pybun-sig-") as tmp:
        sig_path = os.path.join(tmp, "pybun.minisig")
        pub_path = os.path.join(tmp, "pybun.pub")
        with open(sig_path, "w", encoding="utf-8") as handle:
            handle.write(sig_value)
            if not sig_value.endswith("\n"):
                handle.write("\n")
        with open(pub_path, "w", encoding="utf-8") as handle:
            handle.write(sig_pub)
            if not sig_pub.endswith("\n"):
                handle.write("\n")
        result = subprocess.run(
            ["minisign", "-Vm", path, "-x", sig_path, "-P", pub_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    if result.returncode != 0:
        raise BootstrapError(f"minisign verification failed: {result.stderr.strip()}")


def _safe_extract_tar(archive_path: str, dest: str) -> None:
    with tarfile.open(archive_path, "r:*") as tar:
        for member in tar.getmembers():
            member_path = os.path.abspath(os.path.join(dest, member.name))
            if not member_path.startswith(os.path.abspath(dest) + os.sep):
                raise BootstrapError("refusing to extract outside destination")
        tar.extractall(dest)


def _safe_extract_zip(archive_path: str, dest: str) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        for member in archive.namelist():
            member_path = os.path.abspath(os.path.join(dest, member))
            if not member_path.startswith(os.path.abspath(dest) + os.sep):
                raise BootstrapError("refusing to extract outside destination")
        archive.extractall(dest)


def _extract_archive(archive_path: str, dest: str) -> None:
    if archive_path.endswith(".zip"):
        _safe_extract_zip(archive_path, dest)
        return
    if archive_path.endswith(".tar.gz") or archive_path.endswith(".tgz"):
        _safe_extract_tar(archive_path, dest)
        return
    raise BootstrapError(f"unsupported archive format: {archive_path}")


def _find_binary(root: str, name: str) -> Optional[str]:
    for current, _, files in os.walk(root):
        if name in files:
            return os.path.join(current, name)
    return None


def _ensure_executable(path: str) -> None:
    try:
        mode = os.stat(path).st_mode
        os.chmod(path, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except Exception:
        pass


def _metadata_path(root: str) -> str:
    return os.path.join(root, "shim", "current.json")


def load_metadata(root: str) -> Optional[Dict[str, Any]]:
    path = _metadata_path(root)
    if not os.path.exists(path):
        return None
    try:
        return _read_json(path)
    except Exception:
        return None


def write_metadata(root: str, payload: Dict[str, Any]) -> None:
    path = _metadata_path(root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)


def ensure_binary() -> Tuple[str, Optional[Dict[str, Any]]]:
    root = cache_root()
    os.makedirs(root, exist_ok=True)
    target = detect_target()
    verify = not _bool_env("PYBUN_PYPI_NO_VERIFY")
    offline = _bool_env("PYBUN_PYPI_OFFLINE")
    manifest_source = resolve_manifest_source()

    if offline:
        metadata = load_metadata(root)
        if metadata and metadata.get("target") == target:
            binary = metadata.get("binary")
            if binary and os.path.exists(binary):
                return binary, metadata
        raise BootstrapError("offline mode requested but no cached binary available")

    manifest = None
    manifest_error = None
    try:
        manifest = load_manifest(manifest_source)
    except BootstrapError as exc:
        manifest_error = exc

    if manifest is None:
        metadata = load_metadata(root)
        if metadata and metadata.get("target") == target:
            binary = metadata.get("binary")
            if binary and os.path.exists(binary):
                return binary, metadata
        raise manifest_error or BootstrapError("manifest unavailable")

    version = manifest.get("version") or "unknown"
    asset = select_asset(manifest, target)

    binary_name = "pybun.exe" if os.name == "nt" else "pybun"
    install_root = os.path.join(root, "shim", version, target)
    expected_dir = os.path.join(install_root, f"pybun-{target}")
    binary_path = os.path.join(expected_dir, binary_name)

    if os.path.exists(binary_path):
        metadata = {
            "version": version,
            "target": target,
            "binary": binary_path,
            "installed_at": int(time.time()),
            "manifest": manifest_source,
        }
        write_metadata(root, metadata)
        return binary_path, metadata

    tmp_dir = tempfile.mkdtemp(prefix="pybun-shim-")
    try:
        archive_path = os.path.join(tmp_dir, asset.get("name", "pybun-release"))
        _download_url(asset.get("url", ""), archive_path)
        if verify:
            _verify_checksum(archive_path, asset.get("sha256"))
            signature = asset.get("signature")
            if signature:
                _verify_signature(archive_path, signature)
        os.makedirs(install_root, exist_ok=True)
        _extract_archive(archive_path, install_root)
        if not os.path.exists(binary_path):
            found = _find_binary(install_root, binary_name)
            if found:
                binary_path = found
            else:
                raise BootstrapError("pybun binary not found after extraction")
        _ensure_executable(binary_path)
        metadata = {
            "version": version,
            "target": target,
            "binary": binary_path,
            "installed_at": int(time.time()),
            "manifest": manifest_source,
        }
        write_metadata(root, metadata)
        return binary_path, metadata
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
