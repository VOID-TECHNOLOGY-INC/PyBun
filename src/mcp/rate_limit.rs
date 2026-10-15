//! Atomic, bounded, monotonic MCP admission. Session identity is server-owned.
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

const MAX_NAMESPACES: usize = 64;
const MAX_SESSIONS: usize = 512;
const SESSION_IDLE_MS: u64 = 120_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Window {
    pub calls: u64,
    pub window_secs: u64,
}
impl Window {
    fn valid(&self) -> bool {
        (1..=1_000_000).contains(&self.calls) && (1..=86400).contains(&self.window_secs)
    }
    fn ms(&self) -> u64 {
        self.window_secs * 1000
    }
    fn value(&self) -> Value {
        json!({"calls":self.calls,"window_ms":self.ms(),"burst":self.calls})
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub(super) struct Config {
    pub calls_per_minute: u64,
    pub global_calls_per_minute: u64,
    pub pybun_run_per_minute: u64,
    pub pybun_install_per_hour: u64,
    pub per_tool: BTreeMap<String, Window>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            calls_per_minute: 60,
            global_calls_per_minute: 600,
            pybun_run_per_minute: 10,
            pybun_install_per_hour: 20,
            per_tool: BTreeMap::new(),
        }
    }
}
impl Config {
    fn session(&self) -> Window {
        Window {
            calls: self.calls_per_minute,
            window_secs: 60,
        }
    }
    fn global(&self) -> Window {
        Window {
            calls: self.global_calls_per_minute,
            window_secs: 60,
        }
    }
    fn tool(&self, tool: &str) -> Option<Window> {
        self.per_tool.get(tool).cloned().or(match tool {
            "pybun_run" => Some(Window {
                calls: self.pybun_run_per_minute,
                window_secs: 60,
            }),
            "pybun_install" => Some(Window {
                calls: self.pybun_install_per_hour,
                window_secs: 3600,
            }),
            _ => None,
        })
    }
    pub fn validate(&self, tools: &[String]) -> bool {
        self.session().valid()
            && self.global().valid()
            && self.tool("pybun_run").is_some_and(|window| window.valid())
            && self
                .tool("pybun_install")
                .is_some_and(|window| window.valid())
            && (1..=1_000_000).contains(&self.pybun_run_per_minute)
            && (1..=1_000_000).contains(&self.pybun_install_per_hour)
            && self
                .per_tool
                .iter()
                .all(|(tool, window)| tools.contains(tool) && window.valid())
    }
    pub fn describe(&self, tool: &str) -> Value {
        json!({"session":self.session().value(),"global":self.global().value(),"tool":self.tool(tool).map(|window|window.value())})
    }
    pub fn namespace(&self, root: &std::path::Path) -> String {
        use sha2::{Digest, Sha256};
        let mut hash = Sha256::new();
        hash.update(root.as_os_str().as_encoded_bytes());
        hash.update([0]);
        hash.update(serde_json::to_vec(self).expect("rate configuration is serializable"));
        hex::encode(hash.finalize())
    }
    fn idle_ms(&self) -> u64 {
        self.per_tool
            .values()
            .map(Window::ms)
            .chain([3_600_000])
            .max()
            .unwrap()
            * 2
    }
}
trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}
struct MonotonicClock(Instant);
impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        self.0.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
    }
}
#[derive(Debug)]
pub(super) struct Rejected {
    pub scope: &'static str,
    pub retry_after_ms: u64,
}
impl Rejected {
    pub fn value(&self, config: &Config, tool: &str) -> Value {
        json!({"contract_version":"2","status":"error","retry_after_ms":self.retry_after_ms,
            "rate_limit_applied":{"admitted":false,"scope":self.scope,"limits":config.describe(tool)},
            "diagnostics":[{"level":"error","code":"mcp.rate_limit_exceeded","message":"Tool admission is rate limited; retry after the indicated delay.","retry_after_ms":self.retry_after_ms,"next_action":null}]})
    }
}
struct Bucket {
    window: Window,
    credit: u128,
    updated: u64,
    used: u64,
}
impl Bucket {
    fn new(window: Window, now: u64) -> Self {
        let credit = u128::from(window.calls) * u128::from(window.ms());
        Self {
            window,
            credit,
            updated: now,
            used: now,
        }
    }
    fn retry(&mut self, now: u64) -> u64 {
        self.credit = (self.credit
            + u128::from(now.saturating_sub(self.updated)) * u128::from(self.window.calls))
        .min(u128::from(self.window.calls) * u128::from(self.window.ms()));
        self.updated = self.updated.max(now);
        self.used = self.used.max(now);
        let missing = u128::from(self.window.ms()).saturating_sub(self.credit);
        missing
            .div_ceil(u128::from(self.window.calls))
            .try_into()
            .unwrap_or(u64::MAX)
    }
    fn consume(&mut self) {
        self.credit -= u128::from(self.window.ms());
    }
}
struct Namespace {
    global: Bucket,
    sessions: BTreeMap<String, Bucket>,
    tools: BTreeMap<String, Bucket>,
    used: u64,
    idle_ms: u64,
}
#[derive(Default)]
struct State {
    namespaces: BTreeMap<String, Namespace>,
}
pub(super) struct Limiter {
    clock: Arc<dyn Clock>,
    state: Mutex<State>,
}
impl Limiter {
    fn new(clock: Arc<dyn Clock>) -> Self {
        Self {
            clock,
            state: Mutex::new(State::default()),
        }
    }
    pub fn global() -> &'static Self {
        static LIMITER: OnceLock<Limiter> = OnceLock::new();
        LIMITER.get_or_init(|| Self::new(Arc::new(MonotonicClock(Instant::now()))))
    }
    pub fn admit(
        &self,
        namespace: &str,
        session: &str,
        tool: &str,
        config: &Config,
    ) -> Result<(), Rejected> {
        let now = self.clock.now_ms();
        let mut state = self.state.lock().map_err(|_| Rejected {
            scope: "unavailable",
            retry_after_ms: 1,
        })?;
        state
            .namespaces
            .retain(|_, state| state.used.saturating_add(state.idle_ms) > now);
        if !state.namespaces.contains_key(namespace) && state.namespaces.len() >= MAX_NAMESPACES {
            let retry = state
                .namespaces
                .values()
                .map(|state| state.used.saturating_add(state.idle_ms).saturating_sub(now))
                .min()
                .unwrap_or(1);
            return Err(Rejected {
                scope: "capacity",
                retry_after_ms: retry.max(1),
            });
        }
        let state = state
            .namespaces
            .entry(namespace.into())
            .or_insert_with(|| Namespace {
                global: Bucket::new(config.global(), now),
                sessions: BTreeMap::new(),
                tools: BTreeMap::new(),
                used: now,
                idle_ms: config.idle_ms(),
            });
        state.used = state.used.max(now);
        state
            .sessions
            .retain(|_, bucket| bucket.used.saturating_add(SESSION_IDLE_MS) > now);
        let global_retry = state.global.retry(now);
        let session_retry = state
            .sessions
            .get_mut(session)
            .map_or(0, |bucket| bucket.retry(now));
        let tool_retry = config.tool(tool).map_or(0, |window| {
            state
                .tools
                .entry(tool.into())
                .or_insert_with(|| Bucket::new(window, now))
                .retry(now)
        });
        let (scope, retry_after_ms) = [
            ("global", global_retry),
            ("session", session_retry),
            ("tool", tool_retry),
        ]
        .into_iter()
        .max_by_key(|(_, retry)| *retry)
        .unwrap();
        if retry_after_ms > 0 {
            return Err(Rejected {
                scope,
                retry_after_ms,
            });
        }
        if !state.sessions.contains_key(session) && state.sessions.len() >= MAX_SESSIONS {
            let retry = state
                .sessions
                .values()
                .map(|bucket| {
                    bucket
                        .used
                        .saturating_add(SESSION_IDLE_MS)
                        .saturating_sub(now)
                })
                .min()
                .unwrap_or(1);
            return Err(Rejected {
                scope: "capacity",
                retry_after_ms: retry.max(1),
            });
        }
        // One lock covers all checks and debits. Rejections debit no bucket.
        state.global.consume();
        state
            .sessions
            .entry(session.into())
            .or_insert_with(|| Bucket::new(config.session(), now))
            .consume();
        if let Some(bucket) = state.tools.get_mut(tool) {
            bucket.consume();
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    #[derive(Default)]
    struct FakeClock(AtomicU64);
    impl Clock for FakeClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }
    impl FakeClock {
        fn advance(&self, ms: u64) {
            self.0.fetch_add(ms, Ordering::SeqCst);
        }
    }
    fn fixture(config: Config) -> (Arc<FakeClock>, Arc<Limiter>, Config) {
        let clock = Arc::new(FakeClock::default());
        (clock.clone(), Arc::new(Limiter::new(clock)), config)
    }
    #[test]
    fn tokens_refill_monotonically_with_exact_retry_hints() {
        let (clock, limiter, config) = fixture(Config {
            calls_per_minute: 2,
            ..Default::default()
        });
        for _ in 0..2 {
            limiter
                .admit("project", "session", "pybun_gc", &config)
                .unwrap();
        }
        let rejected = limiter
            .admit("project", "session", "pybun_gc", &config)
            .unwrap_err();
        assert_eq!(rejected.scope, "session");
        assert_eq!(rejected.retry_after_ms, 30000);
        clock.advance(29999);
        assert_eq!(
            limiter
                .admit("project", "session", "pybun_gc", &config)
                .unwrap_err()
                .retry_after_ms,
            1
        );
        clock.advance(1);
        limiter
            .admit("project", "session", "pybun_gc", &config)
            .unwrap();
    }
    #[test]
    fn a_rejected_tool_does_not_consume_other_bucket_tokens() {
        let (_, limiter, config) = fixture(Config {
            global_calls_per_minute: 2,
            pybun_run_per_minute: 1,
            ..Default::default()
        });
        limiter.admit("project", "s", "pybun_run", &config).unwrap();
        assert_eq!(
            limiter
                .admit("project", "s", "pybun_run", &config)
                .unwrap_err()
                .scope,
            "tool"
        );
        limiter.admit("project", "s", "pybun_gc", &config).unwrap();
        assert_eq!(
            limiter
                .admit("project", "other", "pybun_gc", &config)
                .unwrap_err()
                .scope,
            "global"
        );
    }
    #[test]
    fn concurrent_sessions_cannot_exceed_the_global_bound() {
        let (_, limiter, config) = fixture(Config {
            global_calls_per_minute: 10,
            ..Default::default()
        });
        let barrier = Arc::new(std::sync::Barrier::new(100));
        let handles: Vec<_> = (0..100)
            .map(|id| {
                let limiter = limiter.clone();
                let barrier = barrier.clone();
                let config = config.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    limiter
                        .admit("project", &format!("session-{id}"), "pybun_gc", &config)
                        .is_ok()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .filter(|admitted| *admitted)
                .count(),
            10
        );
    }
    #[tokio::test]
    async fn cancelled_admitted_work_keeps_its_token_without_holding_a_lock() {
        let (clock, limiter, config) = fixture(Config {
            calls_per_minute: 1,
            ..Default::default()
        });
        let worker = limiter.clone();
        let worker_config = config.clone();
        let (sent, received) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            worker.admit("p", "s", "pybun_gc", &worker_config).unwrap();
            sent.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        received.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(limiter.admit("p", "s", "pybun_gc", &config).is_err());
        clock.advance(60000);
        limiter.admit("p", "s", "pybun_gc", &config).unwrap();
    }
    #[test]
    fn session_budgets_are_independent_and_tool_budgets_are_shared() {
        let (_, limiter, config) = fixture(Config {
            calls_per_minute: 1,
            pybun_run_per_minute: 1,
            ..Default::default()
        });
        limiter.admit("p", "a", "pybun_gc", &config).unwrap();
        limiter.admit("p", "b", "pybun_run", &config).unwrap();
        assert_eq!(
            limiter
                .admit("p", "a", "pybun_gc", &config)
                .unwrap_err()
                .scope,
            "session"
        );
        assert_eq!(
            limiter
                .admit("p", "c", "pybun_run", &config)
                .unwrap_err()
                .scope,
            "tool"
        );
    }
    #[test]
    fn bounded_state_expires_only_after_idle_budgets_can_refill() {
        let (clock, limiter, config) = fixture(Config {
            global_calls_per_minute: 1_000_000,
            ..Default::default()
        });
        for session in 0..MAX_SESSIONS {
            limiter
                .admit("p", &session.to_string(), "pybun_gc", &config)
                .unwrap();
        }
        assert_eq!(
            limiter
                .admit("p", "overflow", "pybun_gc", &config)
                .unwrap_err()
                .scope,
            "capacity"
        );
        clock.advance(SESSION_IDLE_MS);
        limiter.admit("p", "new", "pybun_gc", &config).unwrap();
        assert_eq!(
            limiter.state.lock().unwrap().namespaces["p"].sessions.len(),
            1
        );
        for namespace in 1..MAX_NAMESPACES {
            limiter
                .admit(&namespace.to_string(), "s", "pybun_gc", &config)
                .unwrap();
        }
        assert_eq!(
            limiter
                .admit("overflow", "s", "pybun_gc", &config)
                .unwrap_err()
                .scope,
            "capacity"
        );
        clock.advance(config.idle_ms());
        limiter.admit("new", "s", "pybun_gc", &config).unwrap();
        assert_eq!(limiter.state.lock().unwrap().namespaces.len(), 1);
    }
    #[test]
    fn malformed_limits_and_unknown_tools_fail_validation() {
        let tools = vec![
            "pybun_run".into(),
            "pybun_install".into(),
            "pybun_gc".into(),
        ];
        assert!(Config::default().validate(&tools));
        assert!(
            !Config {
                calls_per_minute: 0,
                ..Default::default()
            }
            .validate(&tools)
        );
        assert!(
            !Config {
                per_tool: BTreeMap::from([(
                    "unknown".into(),
                    Window {
                        calls: 1,
                        window_secs: 60
                    }
                )]),
                ..Default::default()
            }
            .validate(&tools)
        );
        assert!(
            !Config {
                per_tool: BTreeMap::from([(
                    "pybun_gc".into(),
                    Window {
                        calls: 1,
                        window_secs: 0
                    }
                )]),
                ..Default::default()
            }
            .validate(&tools)
        );
    }
}
