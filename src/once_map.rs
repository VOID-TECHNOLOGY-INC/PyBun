use dashmap::DashMap;
use std::future::Future;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::OnceCell;

#[derive(Debug)]
pub struct OnceMap<K: Eq + Hash, V> {
    entries: DashMap<K, Arc<OnceCell<V>>>,
}

impl<K, V> Default for OnceMap<K, V>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> OnceMap<K, V>
where
    K: Eq + Hash,
{
    pub fn new() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }
}

impl<K, V> OnceMap<K, V>
where
    K: Clone + Eq + Hash,
    V: Clone,
{
    pub async fn get_or_try_init<F, Fut, E>(&self, key: K, init: F) -> Result<V, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<V, E>>,
    {
        let cell = self
            .entries
            .entry(key.clone())
            .or_insert_with(|| Arc::new(OnceCell::new()))
            .clone();
        let result = cell.get_or_try_init(init).await.cloned();
        // Only remove the entry if it still points to the exact cell this
        // caller waited on. A different waiter may have already removed our
        // generation and a newer caller may have installed a fresh cell
        // under the same key (e.g. after a failed init was retried); removing
        // unconditionally here would evict that newer generation and cause a
        // duplicate initializer to run. Comparing by `Arc::ptr_eq` ensures
        // cleanup only ever removes the generation this caller actually used.
        self.entries
            .remove_if(&key, |_, existing| Arc::ptr_eq(existing, &cell));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::OnceMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn dedupes_parallel_inits() {
        let map = Arc::new(OnceMap::new());
        let counter = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(8));

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let map = Arc::clone(&map);
            let counter = Arc::clone(&counter);
            let barrier = Arc::clone(&barrier);
            tasks.push(tokio::spawn(async move {
                barrier.wait().await;
                map.get_or_try_init("key".to_string(), || async {
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(42usize)
                })
                .await
                .unwrap()
            }));
        }

        let results = futures::future::join_all(tasks).await;
        for result in results {
            assert_eq!(result.unwrap(), 42);
        }
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_after_failure() {
        let map = OnceMap::new();
        let counter = AtomicUsize::new(0);

        let _ = map
            .get_or_try_init("key".to_string(), || async {
                counter.fetch_add(1, Ordering::SeqCst);
                Err::<usize, _>("boom")
            })
            .await;

        let value = map
            .get_or_try_init("key".to_string(), || async {
                counter.fetch_add(1, Ordering::SeqCst);
                Ok::<_, &str>(99usize)
            })
            .await
            .unwrap();

        assert_eq!(value, 99);
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    /// Regression test for Issue #400: an old waiter (B) that joined
    /// generation #1 must not evict a newer generation (#2, started by C)
    /// installed under the same key after generation #1's owner (A) already
    /// cleaned it up. See the issue for the full interleaving this
    /// reproduces.
    #[tokio::test]
    async fn old_waiter_does_not_evict_newer_generation() {
        use tokio::sync::Notify;

        let map = Arc::new(OnceMap::new());
        let counter = Arc::new(AtomicUsize::new(0));

        // --- A: owns generation #1's initializer. ---
        let a_started = Arc::new(Notify::new());
        let let_a_finish = Arc::new(Notify::new());
        let task_a = {
            let map = Arc::clone(&map);
            let counter = Arc::clone(&counter);
            let a_started = Arc::clone(&a_started);
            let let_a_finish = Arc::clone(&let_a_finish);
            tokio::spawn(async move {
                map.get_or_try_init("key".to_string(), || async move {
                    a_started.notify_one();
                    let_a_finish.notified().await;
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(1usize)
                })
                .await
            })
        };
        a_started.notified().await;

        // --- B: arrives while A is in flight and joins generation #1. ---
        let task_b = {
            let map = Arc::clone(&map);
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                map.get_or_try_init("key".to_string(), || async move {
                    // Must never run: B should join A's cell, not initialize.
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(2usize)
                })
                .await
            })
        };
        // Give B a chance to register on generation #1 before A completes.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        // A completes and (identity-)removes generation #1.
        let_a_finish.notify_one();
        assert_eq!(task_a.await.unwrap().unwrap(), 1);

        // --- C: installs generation #2 under the same key and blocks. ---
        let c_running = Arc::new(Notify::new());
        let let_c_finish = Arc::new(Notify::new());
        let task_c = {
            let map = Arc::clone(&map);
            let counter = Arc::clone(&counter);
            let c_running = Arc::clone(&c_running);
            let let_c_finish = Arc::clone(&let_c_finish);
            tokio::spawn(async move {
                map.get_or_try_init("key".to_string(), || async move {
                    c_running.notify_one();
                    let_c_finish.notified().await;
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(3usize)
                })
                .await
            })
        };
        c_running.notified().await;

        // Let B resume and run its cleanup. With the fix, B's identity-checked
        // removal only targets generation #1 (already gone) and must not
        // evict C's still-running generation #2.
        assert_eq!(task_b.await.unwrap().unwrap(), 1);

        // --- D: joins the same key and must observe C's generation #2. ---
        let task_d = {
            let map = Arc::clone(&map);
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                map.get_or_try_init("key".to_string(), || async move {
                    // Must never run: D should join C's cell, not initialize.
                    counter.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, ()>(4usize)
                })
                .await
            })
        };
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let_c_finish.notify_one();
        assert_eq!(task_c.await.unwrap().unwrap(), 3);
        assert_eq!(
            task_d.await.unwrap().unwrap(),
            3,
            "D must join C's generation instead of starting a duplicate initializer"
        );
        assert_eq!(
            counter.load(Ordering::SeqCst),
            2,
            "exactly two initializers should have run: A and C"
        );
    }
}
