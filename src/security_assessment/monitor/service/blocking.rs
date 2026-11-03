//! Deadline-bounded queue admission, followed by terminal atomic classification.
use super::*;
use std::sync::atomic::{AtomicU8, Ordering};

pub(super) async fn task<T: Send + 'static>(
    deadline: Instant,
    write: bool,
    operation: impl FnOnce() -> MonitorResult<T> + Send + 'static,
) -> MonitorResult<T> {
    const PENDING: u8 = 0;
    const ENTERED: u8 = 1;
    const CANCELLED: u8 = 2;
    let admission = Arc::new(AtomicU8::new(PENDING));
    let entry = admission.clone();
    let mut work = tokio::task::spawn_blocking(move || {
        if Instant::now() >= deadline
            || entry
                .compare_exchange(PENDING, ENTERED, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return Err(MonitorError::new("E_SECURITY_DEADLINE"));
        }
        operation()
    });
    let joined = match tokio::time::timeout_at(deadline.into(), &mut work).await {
        Ok(result) => result,
        Err(_)
            if write
                && admission
                    .compare_exchange(PENDING, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
                    .is_err() =>
        {
            // Only already-entered operations can reach here. The store still
            // guards every mutation with the original absolute deadline. Wait
            // for its real outcome rather than detach an atomic write.
            work.await
        }
        Err(_) => {
            admission.store(CANCELLED, Ordering::Release);
            work.abort();
            return Err(MonitorError::new("E_SECURITY_DEADLINE"));
        }
    };
    joined.unwrap_or_else(|_| {
        let error = MonitorError::new("E_MONITOR_STATE");
        Err(if write { error.indeterminate() } else { error })
    })
}
