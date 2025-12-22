# PyBun Installation Guide (Qiita draft)

This note aligns the public install steps with the signed release artifacts.

## Recommended install (macOS / Linux)

```bash
curl -LsSf https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.sh | sh

# Nightly channel
curl -LsSf https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.sh | sh -s -- --channel nightly

# Custom prefix
curl -LsSf https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.sh | sh -s -- --prefix ~/.local
```

## Recommended install (Windows PowerShell)

```powershell
irm https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.ps1 | iex

# With options
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.ps1))) -Channel nightly -Prefix "$env:LOCALAPPDATA\pybun"
```

## Verification-first

The installer verifies SHA256 checksums and minisign signatures by default.
Use `--no-verify` only if you understand the risks.

## Development install

```bash
cargo install --path .
```
