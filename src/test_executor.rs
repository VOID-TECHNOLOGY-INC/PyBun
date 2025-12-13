//! Parallel test executor for PyBun test runner.
//!
//! This module provides a parallel test execution engine that:
//! - Runs tests concurrently across multiple workers
//! - Supports sharding for distributed test runs
//! - Implements fail-fast behavior
//! - Collects and aggregates test results

use crate::test_discovery::{TestItem, TestItemType};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

/// Configuration for the test executor
#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    /// Number of parallel workers (default: number of CPUs)
    pub workers: usize,
    /// Stop on first failure
    pub fail_fast: bool,
    /// Shard configuration (current shard, total shards)
    pub shard: Option<(u32, u32)>,
    /// Verbose output
    pub verbose: bool,
    /// Timeout per test in seconds
    pub timeout: Option<u64>,
    /// Python executable path
    pub python: String,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        Self {
            workers: num_cpus(),
            fail_fast: false,
            shard: None,
            verbose: false,
            timeout: None,
            python: "python3".to_string(),
        }
    }
}

/// Get number of CPUs (simple cross-platform approximation)
fn num_cpus() -> usize {
    // Default to 4 if we can't determine
    std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
}

/// Result of executing a single test
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    /// Test name
    pub name: String,
    /// Path to the test file
    pub path: PathBuf,
    /// Line number in the file
    pub line: usize,
    /// Test outcome
    pub outcome: TestOutcome,
    /// Duration in milliseconds
    pub duration_ms: u64,
    /// Stdout from the test
    pub stdout: String,
    /// Stderr from the test
    pub stderr: String,
    /// Worker ID that ran this test
    pub worker_id: usize,
}

/// Possible test outcomes
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TestOutcome {
    /// Test passed
    Passed,
    /// Test failed
    Failed,
    /// Test was skipped
    Skipped,
    /// Expected failure (xfail) - failed as expected
    XFail,
    /// Expected failure that unexpectedly passed
    XPass,
    /// Test encountered an error
    Error,
    /// Test timed out
    Timeout,
}

/// Summary of test execution
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionSummary {
    /// Total number of tests
    pub total: usize,
    /// Tests that passed
    pub passed: usize,
    /// Tests that failed
    pub failed: usize,
    /// Tests that were skipped
    pub skipped: usize,
    /// Expected failures (xfail)
    pub xfail: usize,
    /// Unexpected passes (xpass)
    pub xpass: usize,
    /// Tests that errored
    pub errors: usize,
    /// Tests that timed out
    pub timeouts: usize,
    /// Total duration in milliseconds
    pub duration_ms: u64,
    /// Whether execution was stopped due to fail-fast
    pub stopped_early: bool,
    /// Shard info if sharding was used
    pub shard: Option<ShardInfo>,
}

/// Shard information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardInfo {
    /// Current shard (1-indexed)
    pub current: u32,
    /// Total number of shards
    pub total: u32,
    /// Tests assigned to this shard
    pub tests_count: usize,
}

impl ExecutionSummary {
    /// Check if all tests passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.errors == 0 && self.timeouts == 0
    }

    /// Get exit code based on results
    pub fn exit_code(&self) -> i32 {
        if self.all_passed() { 0 } else { 1 }
    }
}

/// Message types for worker communication
#[derive(Debug)]
#[allow(dead_code)]
#[allow(clippy::large_enum_variant)]
enum WorkerMessage {
    /// A test to execute
    Test(TestItem),
    /// Signal to stop (fail-fast triggered)
    Stop,
    /// Signal that worker is done
    Done,
}

/// Result message from worker
#[derive(Debug)]
#[allow(dead_code)]
enum ResultMessage {
    /// Test result
    Result(TestResult),
    /// Worker is idle
    Idle(()),
    /// Worker encountered an error
    Error(usize, String),
}

/// Parallel test executor
pub struct TestExecutor {
    config: ExecutorConfig,
}

impl TestExecutor {
    /// Create a new test executor with the given configuration
    pub fn new(config: ExecutorConfig) -> Self {
        Self { config }
    }

    /// Apply sharding to tests
    pub fn shard_tests(&self, tests: Vec<TestItem>) -> Vec<TestItem> {
        match self.config.shard {
            Some((current, total)) => tests
                .into_iter()
                .enumerate()
                .filter(|(i, _)| (*i as u32 % total) + 1 == current)
                .map(|(_, t)| t)
                .collect(),
            None => tests,
        }
    }

    /// Execute tests in parallel
    pub fn execute(&self, tests: Vec<TestItem>) -> ExecutionResult {
        let start = Instant::now();

        // Filter to only runnable tests (functions and methods, not classes)
        let runnable_tests: Vec<TestItem> = tests
            .into_iter()
            .filter(|t| t.item_type != TestItemType::Class)
            .collect();

        // Apply sharding
        let sharded_tests = self.shard_tests(runnable_tests);
        let total_tests = sharded_tests.len();

        if total_tests == 0 {
            return ExecutionResult {
                results: Vec::new(),
                summary: ExecutionSummary {
                    shard: self.config.shard.map(|(c, t)| ShardInfo {
                        current: c,
                        total: t,
                        tests_count: 0,
                    }),
                    ..Default::default()
                },
            };
        }

        // For single-threaded or small test counts, run sequentially
        if self.config.workers <= 1 || total_tests <= 2 {
            return self.execute_sequential(sharded_tests, start);
        }

        // Parallel execution
        self.execute_parallel(sharded_tests, start)
    }

    /// Execute tests sequentially (simpler, used for small test counts)
    fn execute_sequential(&self, tests: Vec<TestItem>, start: Instant) -> ExecutionResult {
        let mut results = Vec::new();
        let mut stopped_early = false;
        let total = tests.len();

        for test in tests {
            if self.config.verbose {
                eprintln!("Running: {}...", test.name);
            }

            let result = self.run_single_test(&test, 0);

            let failed = matches!(
                result.outcome,
                TestOutcome::Failed | TestOutcome::Error | TestOutcome::Timeout
            );

            results.push(result);

            // Fail-fast check
            if self.config.fail_fast && failed {
                stopped_early = true;
                break;
            }
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let summary = self.compute_summary(&results, duration_ms, stopped_early, total);

        ExecutionResult { results, summary }
    }

    /// Execute tests in parallel using worker threads
    fn execute_parallel(&self, tests: Vec<TestItem>, start: Instant) -> ExecutionResult {
        let total_tests = tests.len();
        let workers = self.config.workers.min(total_tests);

        // Shared state
        let test_queue = Arc::new(Mutex::new(tests.into_iter().collect::<Vec<_>>()));
        let stop_flag = Arc::new(Mutex::new(false));

        // Result collection
        let (result_tx, result_rx): (Sender<ResultMessage>, Receiver<ResultMessage>) = channel();

        // Spawn workers
        let mut handles = Vec::new();

        for worker_id in 0..workers {
            let queue = Arc::clone(&test_queue);
            let stop = Arc::clone(&stop_flag);
            let tx = result_tx.clone();
            let config = self.config.clone();

            let handle = thread::spawn(move || {
                loop {
                    // Check stop flag
                    if *stop.lock().unwrap() {
                        break;
                    }

                    // Get next test
                    let test = {
                        let mut q = queue.lock().unwrap();
                        q.pop()
                    };

                    match test {
                        Some(t) => {
                            let result = Self::run_test_static(&config, &t, worker_id);
                            let _ = tx.send(ResultMessage::Result(result));
                        }
                        None => {
                            // No more tests
                            break;
                        }
                    }
                }
                let _ = tx.send(ResultMessage::Idle(()));
            });

            handles.push(handle);
        }

        // Drop our sender so the receiver knows when all workers are done
        drop(result_tx);

        // Collect results
        let mut results = Vec::new();
        let mut stopped_early = false;

        for msg in result_rx {
            match msg {
                ResultMessage::Result(result) => {
                    let failed = matches!(
                        result.outcome,
                        TestOutcome::Failed | TestOutcome::Error | TestOutcome::Timeout
                    );

                    if self.config.verbose {
                        let status = match &result.outcome {
                            TestOutcome::Passed => "✓",
                            TestOutcome::Failed => "✗",
                            TestOutcome::Skipped => "○",
                            TestOutcome::XFail => "x",
                            TestOutcome::XPass => "X",
                            TestOutcome::Error => "E",
                            TestOutcome::Timeout => "T",
                        };
                        eprintln!("{} {} ({}ms)", status, result.name, result.duration_ms);
                    }

                    results.push(result);

                    // Fail-fast
                    if self.config.fail_fast && failed {
                        *stop_flag.lock().unwrap() = true;
                        stopped_early = true;
                    }
                }
                ResultMessage::Idle(_) => {
                    // Worker finished
                }
                ResultMessage::Error(id, msg) => {
                    eprintln!("Worker {} error: {}", id, msg);
                }
            }
        }

        // Wait for all workers
        for handle in handles {
            let _ = handle.join();
        }

        let duration_ms = start.elapsed().as_millis() as u64;
        let summary = self.compute_summary(&results, duration_ms, stopped_early, total_tests);

        ExecutionResult { results, summary }
    }

    /// Run a single test (static method for use in worker threads)
    fn run_test_static(config: &ExecutorConfig, test: &TestItem, worker_id: usize) -> TestResult {
        let start = Instant::now();

        // Handle skipped tests
        if test.skipped {
            return TestResult {
                name: test.name.clone(),
                path: test.path.clone(),
                line: test.line,
                outcome: TestOutcome::Skipped,
                duration_ms: 0,
                stdout: String::new(),
                stderr: test.skip_reason.clone().unwrap_or_default(),
                worker_id,
            };
        }

        // Build the pytest command to run this specific test
        let test_spec = format!("{}::{}", test.path.display(), test.name);

        let output = Command::new(&config.python)
            .args(["-m", "pytest", "-xvs", &test_spec])
            .output();

        let duration_ms = start.elapsed().as_millis() as u64;

        match output {
            Ok(output) => Self::parse_test_output(test, output, duration_ms, worker_id),
            Err(e) => TestResult {
                name: test.name.clone(),
                path: test.path.clone(),
                line: test.line,
                outcome: TestOutcome::Error,
                duration_ms,
                stdout: String::new(),
                stderr: format!("Failed to execute test: {}", e),
                worker_id,
            },
        }
    }

    /// Run a single test (instance method)
    fn run_single_test(&self, test: &TestItem, worker_id: usize) -> TestResult {
        Self::run_test_static(&self.config, test, worker_id)
    }

    /// Parse pytest output to determine test outcome
    fn parse_test_output(
        test: &TestItem,
        output: Output,
        duration_ms: u64,
        worker_id: usize,
    ) -> TestResult {
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        let outcome = if output.status.success() {
            if test.xfail {
                TestOutcome::XPass
            } else {
                TestOutcome::Passed
            }
        } else {
            // Check for various failure modes
            let combined = format!("{}{}", stdout, stderr);

            if combined.contains("SKIPPED") {
                TestOutcome::Skipped
            } else if test.xfail && combined.contains("XFAIL") {
                TestOutcome::XFail
            } else if combined.contains("ERROR") {
                TestOutcome::Error
            } else {
                TestOutcome::Failed
            }
        };

        TestResult {
            name: test.name.clone(),
            path: test.path.clone(),
            line: test.line,
            outcome,
            duration_ms,
            stdout,
            stderr,
            worker_id,
        }
    }

    /// Compute summary from results
    fn compute_summary(
        &self,
        results: &[TestResult],
        duration_ms: u64,
        stopped_early: bool,
        total: usize,
    ) -> ExecutionSummary {
        let mut summary = ExecutionSummary {
            total,
            duration_ms,
            stopped_early,
            shard: self.config.shard.map(|(c, t)| ShardInfo {
                current: c,
                total: t,
                tests_count: total,
            }),
            ..Default::default()
        };

        for result in results {
            match result.outcome {
                TestOutcome::Passed => summary.passed += 1,
                TestOutcome::Failed => summary.failed += 1,
                TestOutcome::Skipped => summary.skipped += 1,
                TestOutcome::XFail => summary.xfail += 1,
                TestOutcome::XPass => summary.xpass += 1,
                TestOutcome::Error => summary.errors += 1,
                TestOutcome::Timeout => summary.timeouts += 1,
            }
        }

        summary
    }
}

/// Result of test execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Individual test results
    pub results: Vec<TestResult>,
    /// Execution summary
    pub summary: ExecutionSummary,
}

impl ExecutionResult {
    /// Get failed tests
    pub fn failed_tests(&self) -> Vec<&TestResult> {
        self.results
            .iter()
            .filter(|r| matches!(r.outcome, TestOutcome::Failed | TestOutcome::Error))
            .collect()
    }

    /// Convert to JSON value
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "results": self.results,
            "summary": self.summary,
        })
    }
}

/// Validate shard specification
pub fn validate_shard(shard_str: &str) -> Result<(u32, u32), String> {
    let parts: Vec<&str> = shard_str.split('/').collect();
    if parts.len() != 2 {
        return Err(format!(
            "Invalid shard format '{}': expected N/M (e.g., 1/4)",
            shard_str
        ));
    }

    let current: u32 = parts[0].parse().map_err(|_| {
        format!(
            "Invalid shard number '{}': must be a positive integer",
            parts[0]
        )
    })?;

    let total: u32 = parts[1].parse().map_err(|_| {
        format!(
            "Invalid shard total '{}': must be a positive integer",
            parts[1]
        )
    })?;

    if current == 0 || total == 0 {
        return Err("Shard values must be greater than 0".to_string());
    }

    if current > total {
        return Err(format!(
            "Shard {} cannot be greater than total {}",
            current, total
        ));
    }

    Ok((current, total))
}

/// Distribute tests evenly across shards with deterministic ordering
pub fn distribute_tests_for_shard(tests: &[TestItem], current: u32, total: u32) -> Vec<TestItem> {
    // Sort tests by name for deterministic distribution
    let mut sorted: Vec<_> = tests.to_vec();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));

    // Distribute using round-robin
    sorted
        .into_iter()
        .enumerate()
        .filter(|(i, _)| (*i as u32 % total) + 1 == current)
        .map(|(_, t)| t)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_test(name: &str) -> TestItem {
        TestItem {
            name: name.to_string(),
            short_name: name.to_string(),
            path: PathBuf::from("test_example.py"),
            line: 1,
            item_type: TestItemType::Function,
            markers: Vec::new(),
            fixtures: Vec::new(),
            class_name: None,
            skipped: false,
            skip_reason: None,
            xfail: false,
            parametrize: None,
        }
    }

    #[test]
    fn test_validate_shard_valid() {
        assert_eq!(validate_shard("1/2").unwrap(), (1, 2));
        assert_eq!(validate_shard("3/4").unwrap(), (3, 4));
        assert_eq!(validate_shard("1/1").unwrap(), (1, 1));
    }

    #[test]
    fn test_validate_shard_invalid() {
        assert!(validate_shard("invalid").is_err());
        assert!(validate_shard("1").is_err());
        assert!(validate_shard("a/b").is_err());
        assert!(validate_shard("0/2").is_err());
        assert!(validate_shard("3/2").is_err());
    }

    #[test]
    fn test_distribute_tests_shard_1_of_2() {
        let tests = vec![
            make_test("test_a"),
            make_test("test_b"),
            make_test("test_c"),
            make_test("test_d"),
        ];

        let shard = distribute_tests_for_shard(&tests, 1, 2);
        assert_eq!(shard.len(), 2);
        assert!(shard.iter().any(|t| t.name == "test_a"));
        assert!(shard.iter().any(|t| t.name == "test_c"));
    }

    #[test]
    fn test_distribute_tests_shard_2_of_2() {
        let tests = vec![
            make_test("test_a"),
            make_test("test_b"),
            make_test("test_c"),
            make_test("test_d"),
        ];

        let shard = distribute_tests_for_shard(&tests, 2, 2);
        assert_eq!(shard.len(), 2);
        assert!(shard.iter().any(|t| t.name == "test_b"));
        assert!(shard.iter().any(|t| t.name == "test_d"));
    }

    #[test]
    fn test_distribute_tests_deterministic() {
        let tests = vec![
            make_test("test_z"),
            make_test("test_a"),
            make_test("test_m"),
        ];

        let shard1_run1 = distribute_tests_for_shard(&tests, 1, 2);
        let shard1_run2 = distribute_tests_for_shard(&tests, 1, 2);

        assert_eq!(shard1_run1.len(), shard1_run2.len());
        for (a, b) in shard1_run1.iter().zip(shard1_run2.iter()) {
            assert_eq!(a.name, b.name);
        }
    }

    #[test]
    fn test_executor_config_default() {
        let config = ExecutorConfig::default();
        assert!(!config.fail_fast);
        assert!(config.shard.is_none());
        assert!(!config.verbose);
    }

    #[test]
    fn test_execution_summary_all_passed() {
        let summary = ExecutionSummary {
            total: 10,
            passed: 10,
            ..Default::default()
        };
        assert!(summary.all_passed());
        assert_eq!(summary.exit_code(), 0);
    }

    #[test]
    fn test_execution_summary_with_failures() {
        let summary = ExecutionSummary {
            total: 10,
            passed: 8,
            failed: 2,
            ..Default::default()
        };
        assert!(!summary.all_passed());
        assert_eq!(summary.exit_code(), 1);
    }

    #[test]
    fn test_shard_info() {
        let info = ShardInfo {
            current: 1,
            total: 4,
            tests_count: 25,
        };
        assert_eq!(info.current, 1);
        assert_eq!(info.total, 4);
        assert_eq!(info.tests_count, 25);
    }

    #[test]
    fn test_test_outcome_serialization() {
        let passed = TestOutcome::Passed;
        let json = serde_json::to_string(&passed).unwrap();
        assert_eq!(json, "\"passed\"");

        let failed = TestOutcome::Failed;
        let json = serde_json::to_string(&failed).unwrap();
        assert_eq!(json, "\"failed\"");
    }

    #[test]
    fn test_executor_shard_tests() {
        let config = ExecutorConfig {
            shard: Some((1, 2)),
            ..Default::default()
        };
        let executor = TestExecutor::new(config);

        let tests = vec![
            make_test("test_a"),
            make_test("test_b"),
            make_test("test_c"),
            make_test("test_d"),
        ];

        let sharded = executor.shard_tests(tests);
        assert_eq!(sharded.len(), 2);
    }

    #[test]
    fn test_executor_no_shard() {
        let config = ExecutorConfig {
            shard: None,
            ..Default::default()
        };
        let executor = TestExecutor::new(config);

        let tests = vec![make_test("test_a"), make_test("test_b")];

        let sharded = executor.shard_tests(tests.clone());
        assert_eq!(sharded.len(), tests.len());
    }
}
