# Security Policy

## Reporting a Vulnerability
- Email: security@pybun.dev (preferred). If confidentiality is required, request a secure channel in your first message.
- GitHub: https://github.com/VOID-TECHNOLOGY-INC/PyBun/security/advisories/new
- Please include: affected version/commit, platform, reproduction steps, expected vs. actual behavior, and any known mitigations.
- SLA: acknowledge within **2 business days**, initial triage within **5 business days**, and provide fix/mitigation timelines once impact is confirmed (critical/high targeted within 14 days, medium within 30 days, low best-effort in the next release).

## Supported Versions
- Latest tagged release and the `main` branch snapshots receive security fixes.
- Older releases are unsupported unless a critical issue is discovered and backported at the maintainers' discretion.

## Supply Chain Guarantees
- Release artifacts are built in GitHub Actions (`.github/workflows/release.yml`), signed with minisign, and paired with checksums in `pybun-release.json`.
- Public signing key: `security/pybun-release.pub`. Verify with `minisign -Vm <artifact> -p security/pybun-release.pub`.
- Each release ships `pybun-sbom.json` (CycloneDX) and `pybun-provenance.json` (SLSA provenance). You can verify attestations with `gh attestation verify --repo VOID-TECHNOLOGY-INC/PyBun --release <tag>`.
- Release CI fails if SBOM, provenance, or signatures are missing or inconsistent.

## Minisign Key Rotation
1. Generate a new key: `minisign -G -p security/pybun-release.pub -s /tmp/pybun-release.key -c "pybun release"`.
2. Rotate secrets: store the private key as `PYBUN_MINISIGN_PRIVATE_KEY` in GitHub repository secrets (or environment-specific secret for dry runs).
3. Commit the updated `security/pybun-release.pub` and note the rotation in `SECURITY.md`/release notes.
4. Run the release workflow to publish artifacts signed with the new key; invalidate the previous key in downstream distribution channels if applicable.

## Dependency and License Scanning
- CI enforces `cargo audit`, `cargo deny check licenses`, and `pip-audit --project .` to block known vulnerabilities and incompatible licenses before merge.
