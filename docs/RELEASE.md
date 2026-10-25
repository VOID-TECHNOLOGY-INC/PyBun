# Release Process

## Overview

Releases are tag-driven. Pushing a `v*` tag to `main` triggers `release.yml`, which builds binaries for all platforms, signs them, creates a GitHub Release draft, and updates package manager manifests. PyPI is published automatically when the Release is made public.

## Prerequisites

- GitHub Secrets:
  - `PYBUN_MINISIGN_PRIVATE_KEY` — minisign private key for artifact signing
- PyPI Trusted Publisher configured for `VOID-TECHNOLOGY-INC/PyBun` on the `pybun-cli` project
- GNU/Linux metadata generation requires GNU binutils `readelf` (Ubuntu runners include it).
  `generate_manifest.py` reads each packaged ELF's version requirements independently;
  `verify_security_artifacts.py` rejects compatibility metadata that disagrees with the ELF.
- Each target build records Cargo's compiler artifact messages. `generate_sbom.py`
  combines those messages with `cargo metadata --locked` and `Cargo.lock` to
  publish the crates actually compiled for each archive. The generated CycloneDX
  document binds each target inventory to its archive digest and rejects empty
  inventories. It describes compiled dependencies, including build tools; it
  is not a byte-level inventory of code linked into the executable.

## Linux compatibility

The GNU/Linux release baseline is GLIBC 2.34 for x86_64 and aarch64. The old
hard-coded GLIBC 2.31 declaration did not match the released binary requirements.
The manifest now records the actual requirement for each target. On older x86_64
glibc hosts the Python shim selects the musl archive; no aarch64 musl archive is
currently published.

PR CI and release builds run the packaged GNU binaries in a digest-pinned
AlmaLinux 9 container with GLIBC 2.34, and reject binaries requiring a newer
version. Both architectures use native Ubuntu 22.04 runners. For a local check:

```sh
python3 scripts/release/smoke_linux_compat.py \
  --archive dist/pybun-x86_64-unknown-linux-gnu.tar.gz \
  --target x86_64-unknown-linux-gnu
```

This needs Docker and `readelf`; cross-architecture local checks also need
container emulation. Change the baseline only with a documented compatibility
decision and matching runtime smoke tests. Generated release metadata and package
manager files remain CI-owned.

## Step-by-Step

### 1. Merge feature branches

Merge all PRs for this release into `main` via GitHub. Confirm CI is green on `main`.

### 2. Checkout and update local `main`

```bash
git checkout main
git pull origin main
```

### 3. Bump versions (2 files)

Update `Cargo.toml` and `pyproject.toml`:

```toml
# Cargo.toml
version = "X.Y.Z"

# pyproject.toml
version = "X.Y.Z"
```

Regenerate `Cargo.lock`:

```bash
cargo update --workspace
```

### 4. Update CHANGELOG.md

Add a new section at the top:

```markdown
## vX.Y.Z

### Features
- ...

### Fixes
- ...
```

Use `git log vX.Y.(Z-1)..HEAD --oneline` to list commits since the previous tag.

### 5. Update compat snapshot

The snapshot at `tests/snapshots/compat/json_self_update_dry_run.json` hardcodes the version. Update `current_version`, `latest_version`, and `release_url` to match the new version, then verify locally:

```bash
cargo test --test compat_snapshots
```

### 6. Commit

```bash
git add Cargo.toml pyproject.toml Cargo.lock CHANGELOG.md \
        tests/snapshots/compat/json_self_update_dry_run.json
git commit -m "chore(release): bump version to X.Y.Z"
git push origin main
```

### 7. Tag and push

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

This triggers `release.yml`. Monitor progress:

```bash
gh run list -R VOID-TECHNOLOGY-INC/PyBun --limit 5
```

### 8. Publish the GitHub Release draft

Once `release.yml` completes, a draft Release is created in GitHub. Review the release notes and click **Publish release**.

Publishing triggers `publish-pypi.yml`, which uploads `pybun-cli` to PyPI automatically.

### 9. Verify PyPI

```bash
curl -s https://pypi.org/pypi/pybun-cli/json | python3 -c \
  "import sys,json; print(json.load(sys.stdin)['info']['version'])"
```

Expected output: `X.Y.Z`

---

## Workflow Summary

| Trigger | Workflow | Output |
|---------|----------|--------|
| Tag push `v*` | `release.yml` | Binaries, signatures, SBOM, GitHub Release draft, package manager PR |
| Release published | `publish-pypi.yml` | `pybun-cli` on PyPI |

## Common Pitfalls

- **Snapshot mismatch in CI**: `tests/snapshots/compat/json_self_update_dry_run.json` must be updated on every version bump (step 5). Forgetting this causes `compat_snapshots` to fail on all platforms.
- **PyPI Trusted Publisher not configured**: The `publish-pypi` workflow will fail on first run for a new repo fork. Configure the trusted publisher at pypi.org before releasing.
- **`PYBUN_MINISIGN_PRIVATE_KEY` missing**: Tagged and non-dry-run releases fail before signing. Dummy keys are allowed only for an explicit `workflow_dispatch` dry run.
