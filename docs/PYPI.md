# PyPI Shim Publishing

The pip/pipx shim is published under the **`pybun-cli`** distribution name (the module and command are still `pybun`). The `pybun` name is already taken on PyPI, so installs must use `pip install pybun-cli`.

## Build and test locally
```bash
python -m pip install --upgrade pip build
python -m build
python -m pip install dist/pybun_cli-*.whl
pybun --version
```
`PYBUN_PYPI_MANIFEST` or `PYBUN_INSTALL_MANIFEST` can point the shim at a custom release manifest for testing.

## Prerequisite: minisign

The shim downloads a PyBun binary from the release manifest and verifies its
minisign signature before executing it. `minisign` must be installed and on
`PATH`; otherwise the first `pybun` invocation fails closed, and MCP clients
such as Claude Desktop only see the server exit:

| Platform | Command |
| --- | --- |
| macOS | `brew install minisign` |
| Debian/Ubuntu | `apt-get install minisign` |
| Alpine | `apk add minisign` |
| Windows | `scoop install minisign` |

`PYBUN_PYPI_NO_VERIFY=1` skips checksum/signature verification. It is insecure
and intended only for offline testing, not as a normal installation step.

## Publishing flow
1) Align versions in `Cargo.toml` and `pyproject.toml` with the release tag (`vX.Y.Z`).
2) Create/publish the GitHub Release (or dispatch the workflow) to trigger the `publish-pypi` workflow.
3) The workflow builds `sdist`/`wheel` via `python -m build` and uploads them to PyPI using trusted publishing (`id-token` OIDC). Configure the `pybun-cli` project on PyPI as a trusted publisher for `VOID-TECHNOLOGY-INC/PyBun` before the first run.

Re-runs of the workflow set `skip-existing` so uploading the same version is non-fatal.
