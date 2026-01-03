# PyPI Shim Publishing

The pip/pipx shim is published under the **`pybun-cli`** distribution name (the module and command are still `pybun`). The `pybun` name is already taken on PyPI, so installs must use `pip install pybun-cli`.

## Build and test locally
```bash
python -m pip install --upgrade pip build
python -m build
python -m pip install dist/pybun_cli-*.whl
pybun --version
```
`PYBUN_PYPI_MANIFEST` or `PYBUN_INSTALL_MANIFEST` can point the shim at a custom release manifest for testing, and `PYBUN_PYPI_NO_VERIFY=1` skips checksum/signature verification when working offline.

## Publishing flow
1) Align versions in `Cargo.toml` and `pyproject.toml` with the release tag (`vX.Y.Z`).
2) Create/publish the GitHub Release (or dispatch the workflow) to trigger the `publish-pypi` workflow.
3) The workflow builds `sdist`/`wheel` via `python -m build` and uploads them to PyPI using trusted publishing (`id-token` OIDC). Configure the `pybun-cli` project on PyPI as a trusted publisher for `pybun/pybun` before the first run.

Re-runs of the workflow set `skip-existing` so uploading the same version is non-fatal.
