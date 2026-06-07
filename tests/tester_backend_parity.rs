//! E2E parity suite: compares `pybun test --backend=pybun` (native Rust executor)
//! against `pybun test --backend=pytest` (wrapper around `python -m pytest`) on a
//! set of representative fixture projects (Issue #169).
//!
//! Issue #117 called for "fixtures/E2E suites that compare native vs wrapper
//! behavior on representative projects" so `--backend=pybun` can be trusted to
//! have execution parity with the existing wrapper path. PR #167 hardened the
//! native executor (timeout/retries/skip_reason/snapshot wiring) but explicitly
//! deferred this comparison suite — this file fills that gap.
//!
//! Scope: today the two backends emit structurally different JSON envelopes —
//! the native backend reports rich per-test data (`results` + `summary` with
//! passed/failed/skipped/xfail/xpass counts), while the wrapper backend reports
//! only a coarse `passed`/`exit_code` pair (it shells out to `python -m pytest`
//! and does not parse structured per-test results). Rather than silently
//! comparing only what happens to overlap, this suite:
//!
//! 1. Asserts the property that actually matters for agent edit-test-fix loops:
//!    both backends agree on the overall pass/fail verdict (`status` in the JSON
//!    envelope and the process exit code) for representative project shapes
//!    (plain functions, classes, skip/xfail, parametrize, fixtures).
//! 2. Explicitly documents and asserts the known structural envelope difference
//!    (native-only `results`/`summary`) so a future change that silently closes
//!    or widens that gap is caught here rather than going unnoticed.

use assert_cmd::Command;
use assert_cmd::cargo::cargo_bin_cmd;
use serde_json::Value;
use std::fs;
use std::path::Path;
use tempfile::TempDir;

fn pybun() -> Command {
    cargo_bin_cmd!("pybun")
}

/// Returns true when pytest is importable in the default Python interpreter.
/// Both backends under comparison ultimately depend on pytest being present
/// (the wrapper invokes it directly; the native executor shells out to it per
/// test), so the whole suite is skipped in environments that lack it.
fn pytest_available() -> bool {
    std::process::Command::new("python3")
        .args(["-c", "import pytest"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Runs `pybun test --backend=<backend> --format=json` in `dir` and returns the
/// parsed JSON envelope alongside whether the process exited successfully.
fn run_backend(dir: &Path, backend: &str) -> (Value, bool) {
    let output = pybun()
        .current_dir(dir)
        .args(["test", &format!("--backend={backend}"), "--format=json"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: Value = serde_json::from_str(&stdout)
        .unwrap_or_else(|e| panic!("backend {backend} produced invalid JSON: {e}\n{stdout}"));
    (json, output.status.success())
}

/// A representative fixture project: a single test file plus the overall
/// pass/fail verdict both backends are expected to agree on.
struct ParityCase {
    name: &'static str,
    file_name: &'static str,
    source: &'static str,
    expect_overall_pass: bool,
}

const PARITY_CASES: &[ParityCase] = &[
    ParityCase {
        name: "plain_functions_all_passing",
        file_name: "test_plain_pass.py",
        source: "\ndef test_one():\n    assert 1 + 1 == 2\n\ndef test_two():\n    assert \"hi\".upper() == \"HI\"\n",
        expect_overall_pass: true,
    },
    ParityCase {
        name: "plain_functions_with_failure",
        file_name: "test_plain_fail.py",
        source: "\ndef test_passes():\n    assert True\n\ndef test_fails():\n    assert 1 == 2, \"intentional failure\"\n",
        expect_overall_pass: false,
    },
    ParityCase {
        name: "skip_marker",
        file_name: "test_skip.py",
        source: "\nimport pytest\n\n@pytest.mark.skip(reason=\"not ready yet\")\ndef test_skipped():\n    raise AssertionError(\"should never run\")\n\ndef test_runs():\n    assert True\n",
        expect_overall_pass: true,
    },
    ParityCase {
        name: "xfail_marker",
        file_name: "test_xfail.py",
        source: "\nimport pytest\n\n@pytest.mark.xfail(reason=\"known bug\")\ndef test_known_bug():\n    assert False\n\ndef test_other():\n    assert True\n",
        expect_overall_pass: true,
    },
    ParityCase {
        name: "class_methods_with_failure",
        file_name: "test_class_methods.py",
        source: "\nclass TestExample:\n    def test_passing_method(self):\n        assert True\n\n    def test_failing_method(self):\n        assert False, \"method failure\"\n",
        expect_overall_pass: false,
    },
    ParityCase {
        name: "fixtures_with_dependency",
        file_name: "test_fixtures_dep.py",
        source: "\nimport pytest\n\n@pytest.fixture\ndef value():\n    return 42\n\ndef test_uses_fixture(value):\n    assert value == 42\n",
        expect_overall_pass: true,
    },
    ParityCase {
        name: "parametrize_all_passing",
        file_name: "test_parametrize_pass.py",
        source: "\nimport pytest\n\n@pytest.mark.parametrize(\"x\", [1, 2, 3])\ndef test_positive(x):\n    assert x > 0\n",
        expect_overall_pass: true,
    },
    ParityCase {
        name: "parametrize_some_failing",
        file_name: "test_parametrize_fail.py",
        source: "\nimport pytest\n\n@pytest.mark.parametrize(\"x\", [1, 2, -1])\ndef test_positive(x):\n    assert x > 0\n",
        expect_overall_pass: false,
    },
];

/// Core parity property: for every representative project shape, the native
/// (`--backend=pybun`) and wrapper (`--backend=pytest`) backends must agree on
/// the overall pass/fail verdict — both in the JSON envelope's `status` field
/// and in the process exit code — and that verdict must match what the fixture
/// is actually designed to produce. A mismatch here means `--backend=pybun`
/// cannot yet be trusted as a drop-in replacement for the wrapper path.
#[test]
fn test_backend_parity_overall_outcome_agrees() {
    if !pytest_available() {
        eprintln!("Skipping test_backend_parity_overall_outcome_agrees: pytest not installed");
        return;
    }

    for case in PARITY_CASES {
        let temp = TempDir::new().unwrap();
        fs::write(temp.path().join(case.file_name), case.source).unwrap();

        let (native_json, native_success) = run_backend(temp.path(), "pybun");
        let (wrapper_json, wrapper_success) = run_backend(temp.path(), "pytest");

        assert_eq!(
            native_success,
            wrapper_success,
            "case '{}': exit-code success mismatch (native={}, wrapper={}); native detail={:?}, wrapper detail={:?}",
            case.name,
            native_success,
            wrapper_success,
            native_json["detail"],
            wrapper_json["detail"]
        );
        assert_eq!(
            native_success, case.expect_overall_pass,
            "case '{}': expected overall pass={}, but native backend reported success={}",
            case.name, case.expect_overall_pass, native_success
        );

        let native_status = native_json.get("status").and_then(|v| v.as_str());
        let wrapper_status = wrapper_json.get("status").and_then(|v| v.as_str());
        assert_eq!(
            native_status, wrapper_status,
            "case '{}': JSON envelope `status` mismatch (native={:?}, wrapper={:?})",
            case.name, native_status, wrapper_status
        );

        let expected_status = if case.expect_overall_pass {
            Some("ok")
        } else {
            Some("error")
        };
        assert_eq!(
            native_status,
            expected_status,
            "case '{}': expected status={:?} for a {} fixture, got native status={:?}",
            case.name,
            expected_status,
            if case.expect_overall_pass {
                "passing"
            } else {
                "failing"
            },
            native_status
        );
    }
}

/// Both backends must echo the requested backend name and shared CLI flags
/// (fail-fast, shard, filter, parallel) into their JSON envelopes identically —
/// these fields are part of the agent-facing contract regardless of which
/// executor actually ran the tests.
#[test]
fn test_backend_parity_shared_envelope_fields_agree() {
    if !pytest_available() {
        eprintln!(
            "Skipping test_backend_parity_shared_envelope_fields_agree: pytest not installed"
        );
        return;
    }

    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("test_shared_fields.py"),
        "\ndef test_a():\n    assert True\n\ndef test_b():\n    assert True\n",
    )
    .unwrap();

    for backend in ["pybun", "pytest"] {
        let output = pybun()
            .current_dir(temp.path())
            .args([
                "test",
                &format!("--backend={backend}"),
                "--fail-fast",
                "--shard=1/1",
                "--filter=test_",
                "--format=json",
            ])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: Value = serde_json::from_str(&stdout).expect("valid JSON");
        let detail = &json["detail"];

        assert_eq!(
            detail.get("backend").and_then(|v| v.as_str()),
            Some(backend),
            "backend '{}': `backend` field should echo the requested backend",
            backend
        );
        assert_eq!(
            detail.get("fail_fast").and_then(|v| v.as_bool()),
            Some(true),
            "backend '{}': `fail_fast` should be true",
            backend
        );
        assert_eq!(
            detail.get("shard").and_then(|v| v.as_str()),
            Some("1/1"),
            "backend '{}': `shard` should reflect the requested shard",
            backend
        );
        assert_eq!(
            detail.get("filter").and_then(|v| v.as_str()),
            Some("test_"),
            "backend '{}': `filter` should reflect the requested filter",
            backend
        );
    }
}

/// Documents and locks in the known structural difference between the two
/// envelopes: only the native backend exposes per-test `results` (with
/// `outcome`/`skip_reason`/`retries`) and an aggregate `summary` with
/// passed/failed/skipped/xfail/xpass counts. The wrapper backend shells out to
/// `python -m pytest`/`unittest` and reports only a coarse `passed`/`exit_code`
/// pair. This is intentional (see Issue #169's "Proposed Solution" note on
/// allow-listing intentional differences) — but it must stay an explicit,
/// asserted fact rather than something a future refactor can silently change
/// in either direction without anyone noticing.
#[test]
fn test_backend_parity_documents_structural_envelope_differences() {
    if !pytest_available() {
        eprintln!(
            "Skipping test_backend_parity_documents_structural_envelope_differences: pytest not installed"
        );
        return;
    }

    let temp = TempDir::new().unwrap();
    fs::write(
        temp.path().join("test_envelope_shape.py"),
        "\ndef test_pass():\n    assert True\n",
    )
    .unwrap();

    let (native_json, _) = run_backend(temp.path(), "pybun");
    let (wrapper_json, _) = run_backend(temp.path(), "pytest");
    let native_detail = &native_json["detail"];
    let wrapper_detail = &wrapper_json["detail"];

    // Native-only: structured per-test results and an aggregate summary.
    assert!(
        native_detail
            .get("results")
            .and_then(|v| v.as_array())
            .is_some(),
        "native backend should expose a `results` array: {native_detail:?}"
    );
    assert!(
        native_detail
            .get("summary")
            .and_then(|v| v.as_object())
            .is_some(),
        "native backend should expose a `summary` object: {native_detail:?}"
    );
    assert!(
        wrapper_detail.get("results").is_none(),
        "wrapper backend is not expected to expose a `results` array — \
         if it now does, this is a parity improvement that should be reflected \
         in test_backend_parity_overall_outcome_agrees and this assertion updated: {wrapper_detail:?}"
    );
    assert!(
        wrapper_detail.get("summary").is_none(),
        "wrapper backend is not expected to expose a `summary` object — \
         if it now does, this is a parity improvement that should be reflected \
         in test_backend_parity_overall_outcome_agrees and this assertion updated: {wrapper_detail:?}"
    );

    // Wrapper-only: AST-discovery bookkeeping fields surfaced alongside the
    // delegated run (the native backend reports its own per-test results
    // instead, so it doesn't need this summary view).
    assert!(
        wrapper_detail
            .get("tests_found")
            .and_then(|v| v.as_u64())
            .is_some(),
        "wrapper backend should expose `tests_found`: {wrapper_detail:?}"
    );
    assert!(
        native_detail.get("tests_found").is_none(),
        "native backend is not expected to expose `tests_found` (it reports \
         per-test `results` instead) — if it now does, this is a parity \
         improvement that should be reflected in the comparison above: {native_detail:?}"
    );

    // Both report a single discovered/executed test for this fixture, just
    // through different fields — confirming the structural difference isn't
    // hiding a discovery mismatch.
    let native_result_count = native_detail["results"].as_array().unwrap().len();
    let wrapper_tests_found = wrapper_detail["tests_found"].as_u64().unwrap();
    assert_eq!(
        native_result_count as u64, wrapper_tests_found,
        "native `results` count ({native_result_count}) and wrapper `tests_found` \
         ({wrapper_tests_found}) should agree on a single-test fixture"
    );
}
