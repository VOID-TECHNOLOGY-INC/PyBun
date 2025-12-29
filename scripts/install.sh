#!/usr/bin/env sh
set -eu

CHANNEL="stable"
VERSION=""
PREFIX=""
BIN_DIR=""
NO_VERIFY=0
DRY_RUN=0
FORMAT="text"
ALIAS_NAME="pybun-cli"

usage() {
  cat <<'EOF'
PyBun installer (macOS/Linux)

Usage:
  install.sh [options]

Options:
  --version <vX.Y.Z>   Install a specific version (overrides channel)
  --channel <stable|nightly>
  --prefix <path>      Install prefix (default: ~/.local)
  --bin-dir <path>     Install bin directory (overrides prefix)
  --no-verify          Skip checksum/signature verification (dangerous)
  --dry-run            Print plan without downloading/installing
  --format <text|json> Output format (default: text)
  -h, --help           Show this help

Environment:
  PYBUN_INSTALL_MANIFEST   Override manifest source (path, file://, or URL)
  PYBUN_INSTALL_FETCH=1    Fetch manifest even in dry-run
EOF
}

log() {
  printf '%s\n' "$*" >&2
}

die() {
  log "error: $*"
  exit 1
}

expand_path() {
  case "$1" in
    "~") printf '%s\n' "$HOME" ;;
    "~/"*) printf '%s/%s\n' "$HOME" "${1#~/}" ;;
    *) printf '%s\n' "$1" ;;
  esac
}

detect_target() {
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Darwin)
      case "$arch" in
        arm64) printf '%s\n' "aarch64-apple-darwin" ;;
        x86_64) printf '%s\n' "x86_64-apple-darwin" ;;
        *) die "unsupported macOS arch: $arch" ;;
      esac
      ;;
    Linux)
      case "$arch" in
        x86_64)
          if is_musl; then
            printf '%s\n' "x86_64-unknown-linux-musl"
          else
            printf '%s\n' "x86_64-unknown-linux-gnu"
          fi
          ;;
        aarch64|arm64) printf '%s\n' "aarch64-unknown-linux-gnu" ;;
        *) die "unsupported Linux arch: $arch" ;;
      esac
      ;;
    *)
      die "unsupported OS: $os (use install.ps1 on Windows)"
      ;;
  esac
}

is_musl() {
  if command -v ldd >/dev/null 2>&1; then
    if ldd --version 2>&1 | grep -qi musl; then
      return 0
    fi
  fi
  if [ -e /lib/ld-musl-x86_64.so.1 ] || [ -e /lib/ld-musl-aarch64.so.1 ]; then
    return 0
  fi
  return 1
}

download_file() {
  url="$1"
  dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$url" -o "$dest"
    return
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -qO "$dest" "$url"
    return
  fi
  die "curl or wget is required to download $url"
}

mktemp_file() {
  mktemp 2>/dev/null || mktemp -t pybun
}

mktemp_dir() {
  mktemp -d 2>/dev/null || mktemp -d -t pybun
}

sha256sum_file() {
  file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi
  die "sha256sum or shasum is required for verification"
}

detect_existing_pybun() {
  DETECTED_PYBUN_PATH=""
  DETECTED_PYBUN_KIND=""
  DETECTED_PYBUN_MESSAGE=""
  existing="$(command -v pybun 2>/dev/null || true)"
  if [ -z "$existing" ]; then
    return
  fi
  case "$existing" in
    "$INSTALL_PATH"|"$ALIAS_PATH")
      return
      ;;
  esac

  is_bun=0
  if [ -f "$existing" ]; then
    shebang="$(head -n 1 "$existing" 2>/dev/null || true)"
    if printf '%s' "$shebang" | grep -qi "bun"; then
      is_bun=1
    fi
  fi
  case "$existing" in
    *"/.bun/"*|*"bun/"*) is_bun=1 ;;
  esac

  DETECTED_PYBUN_PATH="$existing"
  if [ "$is_bun" -eq 1 ]; then
    DETECTED_PYBUN_KIND="bun-pybun-detected"
    DETECTED_PYBUN_MESSAGE="Detected existing Bun-provided pybun at $existing. Use the pybun-cli alias or adjust PATH to prefer PyBun."
  else
    DETECTED_PYBUN_KIND="pybun-conflict"
    DETECTED_PYBUN_MESSAGE="Detected another pybun on PATH at $existing. Use the pybun-cli alias or adjust PATH."
  fi
}

create_alias() {
  target="$1"
  link="$2"
  ALIAS_STATUS="created"
  if [ -e "$link" ] && [ ! -L "$link" ]; then
    log "warning: alias target already exists at $link (skipping)"
    ALIAS_STATUS="skipped-existing"
    return
  fi
  if ln -sf "$target" "$link" 2>/dev/null; then
    log "Created alias $link -> $(basename "$target")"
    return
  fi
  if cp "$target" "$link" 2>/dev/null; then
    chmod +x "$link" 2>/dev/null || true
    log "Created alias copy at $link"
    return
  fi
  log "warning: failed to create alias at $link"
  ALIAS_STATUS="error"
}

parse_manifest() {
  manifest_path="$1"
  target="$2"
  python3 - "$manifest_path" "$target" <<'PY'
import json
import shlex
import sys

manifest_path = sys.argv[1]
target = sys.argv[2]
with open(manifest_path, "r", encoding="utf-8") as handle:
    manifest = json.load(handle)

asset = None
for item in manifest.get("assets", []):
    if item.get("target") == target:
        asset = item
        break

if not asset:
    sys.exit(2)

release_notes = manifest.get("release_notes") or {}
sig = asset.get("signature") or {}
def emit(name, value):
    print(f"{name}={shlex.quote(value or '')}")

emit("MANIFEST_VERSION", manifest.get("version", ""))
emit("MANIFEST_CHANNEL", manifest.get("channel", ""))
emit("MANIFEST_RELEASE_URL", manifest.get("release_url", ""))
emit("ASSET_NAME_FROM_MANIFEST", asset.get("name", ""))
emit("ASSET_URL_FROM_MANIFEST", asset.get("url", ""))
emit("ASSET_SHA_FROM_MANIFEST", asset.get("sha256", ""))
emit("SIG_TYPE_FROM_MANIFEST", sig.get("type", ""))
emit("SIG_VALUE_FROM_MANIFEST", sig.get("value", ""))
emit("SIG_PUB_FROM_MANIFEST", sig.get("public_key", ""))
emit("RELEASE_NOTES_NAME_FROM_MANIFEST", release_notes.get("name", ""))
emit("RELEASE_NOTES_URL_FROM_MANIFEST", release_notes.get("url", ""))
emit("RELEASE_NOTES_SHA_FROM_MANIFEST", release_notes.get("sha256", ""))
PY
}

emit_json() {
  if ! command -v python3 >/dev/null 2>&1; then
    die "python3 is required for JSON output"
  fi
  PYBUN_JSON_STATUS="$1" \
  PYBUN_JSON_TARGET="$2" \
  PYBUN_JSON_CHANNEL="$3" \
  PYBUN_JSON_VERSION="$4" \
  PYBUN_JSON_BIN_DIR="$5" \
  PYBUN_JSON_INSTALL_PATH="$6" \
  PYBUN_JSON_VERIFY="$7" \
  PYBUN_JSON_NO_VERIFY="$8" \
  PYBUN_JSON_DRY_RUN="$9" \
  PYBUN_JSON_MANIFEST_SOURCE="${10}" \
  PYBUN_JSON_MANIFEST_VERSION="${11}" \
  PYBUN_JSON_MANIFEST_CHANNEL="${12}" \
  PYBUN_JSON_MANIFEST_RELEASE_URL="${13}" \
  PYBUN_JSON_ASSET_NAME="${14}" \
  PYBUN_JSON_ASSET_URL="${15}" \
  PYBUN_JSON_ASSET_SHA="${16}" \
  PYBUN_JSON_SIG_TYPE="${17}" \
  PYBUN_JSON_SIG_VALUE="${18}" \
  PYBUN_JSON_SIG_PUB="${19}" \
  PYBUN_JSON_RELEASE_NOTES_NAME="${20}" \
  PYBUN_JSON_RELEASE_NOTES_URL="${21}" \
  PYBUN_JSON_RELEASE_NOTES_SHA="${22}" \
  PYBUN_JSON_ALIAS_NAME="${23}" \
  PYBUN_JSON_ALIAS_PATH="${24}" \
  PYBUN_JSON_ALIAS_STATUS="${25}" \
  PYBUN_JSON_WARNING_KIND="${26}" \
  PYBUN_JSON_WARNING_MESSAGE="${27}" \
  PYBUN_JSON_WARNING_PATH="${28}" \
  python3 - <<'PY'
import json
import os

def env(name):
    return os.environ.get(name) or None

def env_bool(name):
    value = os.environ.get(name)
    if value is None:
        return None
    return value.lower() in ("1", "true", "yes")

asset = {
    "name": env("PYBUN_JSON_ASSET_NAME"),
    "url": env("PYBUN_JSON_ASSET_URL"),
    "sha256": env("PYBUN_JSON_ASSET_SHA"),
}

sig_type = env("PYBUN_JSON_SIG_TYPE")
sig_value = env("PYBUN_JSON_SIG_VALUE")
sig_pub = env("PYBUN_JSON_SIG_PUB")
if sig_type or sig_value or sig_pub:
    asset["signature"] = {
        "type": sig_type,
        "value": sig_value,
        "public_key": sig_pub,
    }

manifest = {
    "source": env("PYBUN_JSON_MANIFEST_SOURCE"),
    "version": env("PYBUN_JSON_MANIFEST_VERSION"),
    "channel": env("PYBUN_JSON_MANIFEST_CHANNEL"),
    "release_url": env("PYBUN_JSON_MANIFEST_RELEASE_URL"),
}
manifest = {k: v for k, v in manifest.items() if v}

release_notes = {
    "name": env("PYBUN_JSON_RELEASE_NOTES_NAME"),
    "url": env("PYBUN_JSON_RELEASE_NOTES_URL"),
    "sha256": env("PYBUN_JSON_RELEASE_NOTES_SHA"),
}
release_notes = {k: v for k, v in release_notes.items() if v}
if release_notes:
    manifest["release_notes"] = release_notes

payload = {
    "status": env("PYBUN_JSON_STATUS"),
    "dry_run": env_bool("PYBUN_JSON_DRY_RUN"),
    "verify": env_bool("PYBUN_JSON_VERIFY"),
    "no_verify": env_bool("PYBUN_JSON_NO_VERIFY"),
    "channel": env("PYBUN_JSON_CHANNEL"),
    "version": env("PYBUN_JSON_VERSION"),
    "target": env("PYBUN_JSON_TARGET"),
    "bin_dir": env("PYBUN_JSON_BIN_DIR"),
    "install_path": env("PYBUN_JSON_INSTALL_PATH"),
    "manifest": manifest or None,
    "asset": asset,
}

aliases = []
alias_name = env("PYBUN_JSON_ALIAS_NAME")
alias_path = env("PYBUN_JSON_ALIAS_PATH")
alias_status = env("PYBUN_JSON_ALIAS_STATUS")
if alias_name or alias_path:
    alias_entry = {"name": alias_name, "path": alias_path, "status": alias_status}
    alias_entry = {k: v for k, v in alias_entry.items() if v}
    aliases.append(alias_entry)
payload["aliases"] = aliases

warnings = []
warning_kind = env("PYBUN_JSON_WARNING_KIND")
warning_message = env("PYBUN_JSON_WARNING_MESSAGE")
warning_path = env("PYBUN_JSON_WARNING_PATH")
if warning_kind or warning_message:
    warning = {"kind": warning_kind, "message": warning_message}
    if warning_path:
        warning["path"] = warning_path
    warnings.append(warning)
payload["warnings"] = warnings

print(json.dumps(payload))
PY
}

while [ $# -gt 0 ]; do
  case "$1" in
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --version=*)
      VERSION="${1#*=}"
      shift 1
      ;;
    --channel)
      CHANNEL="${2:-}"
      shift 2
      ;;
    --channel=*)
      CHANNEL="${1#*=}"
      shift 1
      ;;
    --prefix)
      PREFIX="${2:-}"
      shift 2
      ;;
    --prefix=*)
      PREFIX="${1#*=}"
      shift 1
      ;;
    --bin-dir)
      BIN_DIR="${2:-}"
      shift 2
      ;;
    --bin-dir=*)
      BIN_DIR="${1#*=}"
      shift 1
      ;;
    --no-verify)
      NO_VERIFY=1
      shift 1
      ;;
    --dry-run)
      DRY_RUN=1
      shift 1
      ;;
    --format)
      FORMAT="${2:-}"
      shift 2
      ;;
    --format=*)
      FORMAT="${1#*=}"
      shift 1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

if [ "$CHANNEL" != "stable" ] && [ "$CHANNEL" != "nightly" ]; then
  die "channel must be stable or nightly"
fi

if [ -z "${HOME:-}" ] && [ -z "$PREFIX" ] && [ -z "$BIN_DIR" ]; then
  die "HOME is not set; pass --prefix or --bin-dir"
fi

if [ -n "$BIN_DIR" ]; then
  BIN_DIR="$(expand_path "$BIN_DIR")"
  if [ -z "$PREFIX" ]; then
    PREFIX="$(dirname "$BIN_DIR")"
  else
    PREFIX="$(expand_path "$PREFIX")"
  fi
else
  if [ -n "$PREFIX" ]; then
    PREFIX="$(expand_path "$PREFIX")"
  else
    if [ "$(id -u)" -eq 0 ]; then
      PREFIX="/usr/local"
    else
      PREFIX="$(expand_path "~/.local")"
    fi
  fi
  BIN_DIR="$PREFIX/bin"
fi

TARGET="$(detect_target)"
ARCHIVE_EXT="tar.gz"
ASSET_NAME="pybun-${TARGET}.${ARCHIVE_EXT}"
INSTALL_PATH="$BIN_DIR/pybun"
ALIAS_PATH="$BIN_DIR/$ALIAS_NAME"

MANIFEST_SOURCE="${PYBUN_INSTALL_MANIFEST:-}"
if [ -z "$MANIFEST_SOURCE" ]; then
  if [ -n "$VERSION" ]; then
    VERSION="${VERSION#v}"
    RELEASE_TAG="v$VERSION"
    MANIFEST_SOURCE="https://github.com/pybun/pybun/releases/download/${RELEASE_TAG}/pybun-release.json"
  elif [ "$CHANNEL" = "nightly" ]; then
    MANIFEST_SOURCE="https://github.com/pybun/pybun/releases/download/nightly/pybun-release.json"
  else
    MANIFEST_SOURCE="https://github.com/pybun/pybun/releases/latest/download/pybun-release.json"
  fi
fi

if [ -n "$VERSION" ]; then
  RELEASE_TAG="v${VERSION#v}"
  ASSET_URL="https://github.com/pybun/pybun/releases/download/${RELEASE_TAG}/${ASSET_NAME}"
elif [ "$CHANNEL" = "nightly" ]; then
  ASSET_URL="https://github.com/pybun/pybun/releases/download/nightly/${ASSET_NAME}"
else
  ASSET_URL="https://github.com/pybun/pybun/releases/latest/download/${ASSET_NAME}"
fi

MANIFEST_PATH=""
case "$MANIFEST_SOURCE" in
  file://*)
    MANIFEST_PATH="${MANIFEST_SOURCE#file://}"
    ;;
  http://*|https://*)
    if [ "${PYBUN_INSTALL_FETCH:-}" = "1" ] || { [ "$NO_VERIFY" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; }; then
      tmp_manifest="$(mktemp_file)"
      download_file "$MANIFEST_SOURCE" "$tmp_manifest"
      MANIFEST_PATH="$tmp_manifest"
    fi
    ;;
  *)
    if [ -f "$MANIFEST_SOURCE" ]; then
      MANIFEST_PATH="$MANIFEST_SOURCE"
    fi
    ;;
esac

MANIFEST_VERSION=""
MANIFEST_CHANNEL=""
MANIFEST_RELEASE_URL=""
ASSET_SHA=""
SIG_TYPE=""
SIG_VALUE=""
SIG_PUB=""
RELEASE_NOTES_NAME=""
RELEASE_NOTES_URL=""
RELEASE_NOTES_SHA=""

if [ -n "$MANIFEST_PATH" ]; then
  if ! command -v python3 >/dev/null 2>&1; then
    die "python3 is required to parse the release manifest"
  fi
  if manifest_vars="$(parse_manifest "$MANIFEST_PATH" "$TARGET")"; then
    eval "$manifest_vars"
    MANIFEST_VERSION="${MANIFEST_VERSION:-}"
    MANIFEST_CHANNEL="${MANIFEST_CHANNEL:-}"
    MANIFEST_RELEASE_URL="${MANIFEST_RELEASE_URL:-}"
    ASSET_NAME="${ASSET_NAME_FROM_MANIFEST:-$ASSET_NAME}"
    ASSET_URL="${ASSET_URL_FROM_MANIFEST:-$ASSET_URL}"
    ASSET_SHA="${ASSET_SHA_FROM_MANIFEST:-}"
    SIG_TYPE="${SIG_TYPE_FROM_MANIFEST:-}"
    SIG_VALUE="${SIG_VALUE_FROM_MANIFEST:-}"
    SIG_PUB="${SIG_PUB_FROM_MANIFEST:-}"
    RELEASE_NOTES_NAME="${RELEASE_NOTES_NAME_FROM_MANIFEST:-}"
    RELEASE_NOTES_URL="${RELEASE_NOTES_URL_FROM_MANIFEST:-}"
    RELEASE_NOTES_SHA="${RELEASE_NOTES_SHA_FROM_MANIFEST:-}"
    if [ -n "$MANIFEST_VERSION" ] && [ -z "$VERSION" ]; then
      VERSION="$MANIFEST_VERSION"
    fi
  else
    die "no asset found in manifest for target: $TARGET"
  fi
elif [ "$NO_VERIFY" -eq 0 ] && [ "$DRY_RUN" -eq 0 ]; then
  die "manifest required for verification (set PYBUN_INSTALL_MANIFEST or use --no-verify)"
fi

ALIAS_STATUS="planned"
detect_existing_pybun

if [ "$DRY_RUN" -eq 1 ]; then
  if [ "$FORMAT" = "json" ]; then
    emit_json \
      "dry-run" \
      "$TARGET" \
      "$CHANNEL" \
      "${VERSION:-}" \
      "$BIN_DIR" \
      "$INSTALL_PATH" \
      "$([ "$NO_VERIFY" -eq 0 ] && printf 'true' || printf 'false')" \
      "$([ "$NO_VERIFY" -eq 1 ] && printf 'true' || printf 'false')" \
      "true" \
      "$MANIFEST_SOURCE" \
      "$MANIFEST_VERSION" \
      "$MANIFEST_CHANNEL" \
      "$MANIFEST_RELEASE_URL" \
      "$ASSET_NAME" \
      "$ASSET_URL" \
      "$ASSET_SHA" \
      "$SIG_TYPE" \
      "$SIG_VALUE" \
      "$SIG_PUB" \
      "$RELEASE_NOTES_NAME" \
      "$RELEASE_NOTES_URL" \
      "$RELEASE_NOTES_SHA" \
      "$ALIAS_NAME" \
      "$ALIAS_PATH" \
      "$ALIAS_STATUS" \
      "$DETECTED_PYBUN_KIND" \
      "$DETECTED_PYBUN_MESSAGE" \
      "$DETECTED_PYBUN_PATH"
    exit 0
  fi

  log "PyBun installer dry-run"
  log "Target: $TARGET"
  log "Manifest: $MANIFEST_SOURCE"
  log "Asset: $ASSET_URL"
  log "Install path: $INSTALL_PATH"
  log "Verify: $([ "$NO_VERIFY" -eq 0 ] && printf 'enabled' || printf 'disabled')"
  if [ -n "$DETECTED_PYBUN_MESSAGE" ]; then
    log "warning: $DETECTED_PYBUN_MESSAGE"
  fi
  exit 0
fi

if [ "$NO_VERIFY" -eq 1 ]; then
  log "warning: verification disabled (--no-verify)"
fi

tmp_dir="$(mktemp_dir)"
trap 'rm -rf "$tmp_dir"' EXIT
artifact_path="$tmp_dir/$ASSET_NAME"

log "Downloading $ASSET_URL"
download_file "$ASSET_URL" "$artifact_path"

if [ "$NO_VERIFY" -eq 0 ]; then
  if [ -z "$ASSET_SHA" ]; then
    die "manifest missing sha256 for asset"
  fi
  log "Verifying SHA256"
  computed_sha="$(sha256sum_file "$artifact_path")"
  if [ "$computed_sha" != "$ASSET_SHA" ]; then
    die "checksum mismatch: expected $ASSET_SHA, got $computed_sha"
  fi
  if [ -n "$SIG_VALUE" ] && [ -n "$SIG_PUB" ]; then
    if ! command -v minisign >/dev/null 2>&1; then
      die "minisign is required for signature verification (install minisign or use --no-verify)"
    fi
    sig_path="$tmp_dir/${ASSET_NAME}.minisig"
    pub_path="$tmp_dir/pybun-release.pub"
    printf '%s\n' "$SIG_VALUE" > "$sig_path"
    printf '%s\n' "$SIG_PUB" > "$pub_path"
    log "Verifying signature (minisign)"
    minisign -Vm "$artifact_path" -x "$sig_path" -P "$pub_path" >/dev/null
  fi
fi

log "Extracting archive"
tar -xzf "$artifact_path" -C "$tmp_dir"
extracted_dir="$tmp_dir/pybun-${TARGET}"
bin_source="$extracted_dir/pybun"
if [ ! -f "$bin_source" ]; then
  die "expected binary not found in archive: $bin_source"
fi

mkdir -p "$BIN_DIR"
if command -v install >/dev/null 2>&1; then
  install -m 0755 "$bin_source" "$INSTALL_PATH"
else
  cp "$bin_source" "$INSTALL_PATH"
  chmod +x "$INSTALL_PATH"
fi

log "Installed pybun to $INSTALL_PATH"
create_alias "$INSTALL_PATH" "$ALIAS_PATH"
if [ -n "$DETECTED_PYBUN_MESSAGE" ]; then
  log "warning: $DETECTED_PYBUN_MESSAGE"
fi

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    log "Add $BIN_DIR to your PATH to use pybun:"
    log "  export PATH=\"$BIN_DIR:\$PATH\""
    ;;
esac
