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
        let result = cell.get_or_try_init(init).await.map(Clone::clone);
        self.entries.remove(&key);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::OnceMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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
}
