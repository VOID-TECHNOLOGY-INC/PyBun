# Investigate a failed Python task with PyBun evidence

This small project models one agent-scheduler task whose verification runs `pybun --format=json run task.py`. The task succeeds with the local `evidence-helper` distribution, then exits 23 after that declared dependency is removed. The failure is intentional; restoring the declaration is a human decision after investigation.

## Local reproduction

Use PyBun 0.2.5 or later, uv `>=0.12.0,<0.13.0`, and a Python interpreter satisfying `>=3.12`. Run this from the PyBun repository root. The commands keep receipts and raw JSON in a disposable directory because they contain local paths and arguments. Do not publish those raw files.

```sh
DEMO_DIR="$(mktemp -d)"
cp -R examples/agent_scheduler_evidence/. "$DEMO_DIR/"
cd "$DEMO_DIR"
export PYBUN_HOME="$DEMO_DIR/.pybun-home"
export PYBUN_PYPI_CACHE_DIR="$DEMO_DIR/.pypi-cache"
uv build helper --wheel --offline
uv lock --offline
uv sync --offline
pybun --format=json run task.py                   # exit 0
pybun history --format=json > history-success.json
python3 -c 'import json; from pathlib import Path; d=json.loads(Path("history-success.json").read_text()); Path("before.json").write_text(json.dumps(d["detail"]["records"][-1]))'
pybun why evidence-helper --format=json > why-success.json
cp without-helper.toml pyproject.toml
uv lock --offline
uv sync --offline
pybun --format=json run task.py                   # expected exit 23
pybun history --format=json > history-failure.json
python3 -c 'import json; from pathlib import Path; d=json.loads(Path("history-failure.json").read_text()); Path("after.json").write_text(json.dumps(d["detail"]["records"][-1]))'
pybun environment diff before.json after.json --format=json > diff.json
pybun why evidence-helper --format=json           # expected E_WHY_PACKAGE_NOT_FOUND
```

If offline mode lacks a cached interpreter or build dependency, rerun `uv build`, `uv lock`, and `uv sync` without `--offline` in this disposable project. The source is a locally built wheel so frozen `pybun why` can inspect the graph without building a source directory. Inspect `history-success.json`, `history-failure.json`, and `diff.json` locally. The two expected nonzero commands can interrupt a shell using `set -e`; run them in a normal interactive shell or handle their statuses explicitly.

The `why-success.json` result has a dependency path with `provenance: ["direct", "workspace"]`. The first receipt has `command: "run"`, `exit_code: 0`, backend `uv`, and an installed `evidence-helper` entry. The second receipt has `exit_code: 23` and lacks that installed package. The diff contains `LOCK_CHANGED` for `lock.digest` and `PACKAGE_REMOVED` for both the locked and installed package. `complete: false` and `causality: "not_inferred"` mean that the diff identifies changed evidence, not the sole cause of failure. `why` explains locked declarations and no longer finds the helper after its removal. PyBun history does not store program output or environment variables; it cannot prove what the program printed, what an agent reasoned, or whether restoration is the right production fix.

## agent-scheduler task

Use [scheduler-task.md](scheduler-task.md) as the body of **one disposable GitHub Issue** in a repository containing this example. Configure that repository's agent-scheduler `verification.commands` to include `pybun --format=json run task.py`, and make PyBun plus supported uv available inside its pinned worker image. Run `subsched doctor --config subsched.yaml` first. With the scheduler's documented container isolation, provider credentials, and subscription billing prerequisites satisfied, dispatch only that Issue with `subsched run --repo OWNER/REPO --issues NUMBER --config subsched.yaml --allow-native --subscription-billing-verified --watch`. Inspect its persistent task state, run summary, PR, and CI rather than treating dispatch acceptance as completion. The task asks the agent to capture the deliberate failure and restore the working declaration before completing verification.

**Observed on 2026-10-25:** the local PyBun sequence above ran with PyBun 0.2.5, agent-scheduler 0.6.1, uv 0.12.13, and CPython 3.13.14 selected by uv. The success run exited 0, the deliberate failure exited 23, and restoring the declaration followed by `uv lock`/`uv sync` returned the task to exit 0. The investigation commands completed in 0.314 seconds of measured CLI time (post-failure `history`, `environment diff`, and `why` only) on this Mac; setup, agent work, and human review were not timed, so this is not a productivity comparison. A human must decide whether restoring the helper matches the task requirement. The local `subsched doctor` failed because CLI inspection and native isolation runtime inspection were not ready, so native scheduler dispatch was **not observed**. No scheduler completion or time saving is claimed.

The published [evidence summary](evidence-summary.json) contains only package names, status codes, reason codes, tool versions, and a bounded CLI timing. It contains no receipts, local paths, credentials, environment variables, or program output.
