# Demonstrate dependency-change evidence for one Python task

In this disposable repository, run `uv build helper --wheel`, `uv lock`, and `uv sync`, then verify that `pybun --format=json run task.py` succeeds with `evidence-helper` declared. Capture the latest `pybun history --format=json` run receipt and `pybun why evidence-helper --format=json` locally. Then replace `pyproject.toml` with `without-helper.toml`, run `uv lock` and `uv sync`, and verify that the same task exits 23. Capture the failed run receipt and compare the two receipts with `pybun environment diff before.json after.json --format=json`.

Record only a sanitized summary of exit codes, backend and tool versions, dependency provenance, lock-change and package-removal reason codes, and missing evidence. Do not commit raw history, program output, environment variables, credentials, or local paths. State that the diff does not infer causality. Record any human decision needed and measured investigation time, with the timed interval stated.

Finally, restore the original dependency declaration, run `uv lock` and `uv sync`, and make `pybun --format=json run task.py` pass again. Keep the change within this one Issue. Confirm the scheduler's final task state, verification result, PR, and CI separately.
