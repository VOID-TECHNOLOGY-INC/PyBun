# Upgrade to GA

Guidance for moving from the preview builds to the GA (stable) channel.

## Breaking changes
- Release manifests now ship a `release_notes` attachment; installers and `pybun self update` surface it in JSON output. Pin a manifest (via `PYBUN_INSTALL_MANIFEST`) instead of relying on unsigned downloads.
- JSON schema v1 is frozen for GA. Automation should consume the v1 envelope (`version`, `status`, `events`, `diagnostics`) and the new release-notes metadata surfaced by installers/self-update.
- Verified downloads are the default; offline or manifest-less installs will fail unless `--no-verify` is explicitly set.

## Migration steps
1) Pin the GA manifest in CI/dev shells:
   ```bash
   export PYBUN_INSTALL_MANIFEST="https://github.com/pybun/pybun/releases/latest/download/pybun-release.json"
   curl -LsSf https://raw.githubusercontent.com/pybun/pybun/main/scripts/install.sh | sh
   ```
2) Regenerate lockfiles with the GA toolchain (`pybun install --require ...` or `pybun lock --index ...`) and commit the refreshed `pybun.lockb`.
3) Update automation to call `pybun --format=json` (see README's JSON output examples) and to respect the `release_notes` attachment surfaced in JSON.
4) Add GA doc linting to CI: `cargo test --test docs` for markdown/link checks and `python -m unittest scripts/release/tests/test_release_notes.py` for release-note automation.
5) Attach release notes to the manifest when cutting a release:
   ```bash
   python scripts/release/generate_release_notes.py --repo . --previous-tag v0.1.0 --tag v0.2.0 --notes-output release/RELEASE_NOTES.md --changelog CHANGELOG.md
   python scripts/release/generate_manifest.py --assets-dir release --version 0.2.0 --channel stable --base-url https://github.com/pybun/pybun/releases/download/v0.2.0 --output pybun-release.json --release-notes release/RELEASE_NOTES.md
   ```

## Compatibility notes
- Telemetry stays opt-in; `PYBUN_TELEMETRY=0|1` still overrides config.
- The default profile is `dev`; use `--profile=prod` for optimized runs or `--profile=benchmark` for reproducible timing.
- For untrusted code, prefer `pybun run --sandbox` (add `--allow-network` only when required).
