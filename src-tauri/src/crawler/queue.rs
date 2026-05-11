use super::task::{CrawlTask, Tier};
use std::collections::{BinaryHeap, HashSet};

/// Priority-queue of crawl tasks with built-in URL dedupe.
///
/// Wraps a BinaryHeap<CrawlTask>. URLs are deduped at enqueue time (after
/// fragment stripping) — the same URL can't be enqueued twice.
pub struct CrawlQueue {
    heap: BinaryHeap<CrawlTask>,
    visited: HashSet<String>,
    /// Counts how many tasks of each tier have been popped (telemetry).
    pub tier_counts: [u32; 7],
}

impl Default for CrawlQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl CrawlQueue {
    pub fn new() -> Self {
        Self { heap: BinaryHeap::new(), visited: HashSet::new(), tier_counts: [0; 7] }
    }

    /// Strip the URL fragment (after `#`) for dedupe purposes.
    fn canonical_key(url: &str) -> String {
        match url.find('#') {
            Some(i) => url[..i].to_string(),
            None => url.to_string(),
        }
    }

    /// Insert a task. Duplicate URLs (after fragment strip) are silently dropped.
    /// Returns true iff the task was new.
    pub fn enqueue(&mut self, task: CrawlTask) -> bool {
        let key = Self::canonical_key(&task.url);
        if !self.visited.insert(key) {
            return false;
        }
        self.heap.push(task);
        true
    }

    /// Insert without dedupe (useful for explicit user-input that should re-fire even if seen).
    pub fn enqueue_force(&mut self, task: CrawlTask) {
        self.visited.insert(Self::canonical_key(&task.url));
        self.heap.push(task);
    }

    /// Return true if the URL was already seen / enqueued.
    pub fn was_seen(&self, url: &str) -> bool {
        self.visited.contains(&Self::canonical_key(url))
    }

    pub fn pop(&mut self) -> Option<CrawlTask> {
        let t = self.heap.pop();
        if let Some(t) = &t {
            self.tier_counts[t.tier as usize] = self.tier_counts[t.tier as usize].saturating_add(1);
        }
        t
    }

    pub fn len(&self) -> usize {
        self.heap.len()
    }

    pub fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub fn visited_count(&self) -> usize {
        self.visited.len()
    }

    /// Telemetry helper — number of tasks popped per tier so far.
    pub fn popped_for(&self, tier: Tier) -> u32 {
        self.tier_counts[tier as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dedupes_by_fragment() {
        let mut q = CrawlQueue::new();
        assert!(q.enqueue(CrawlTask::get("https://x/a", Tier::Bfs, 0)));
        assert!(!q.enqueue(CrawlTask::get("https://x/a#main", Tier::Bfs, 0)));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn explicit_pops_first() {
        let mut q = CrawlQueue::new();
        q.enqueue(CrawlTask::get("https://x/a", Tier::Bfs, 0));
        q.enqueue(CrawlTask::get("https://x/b", Tier::Explicit, 0));
        q.enqueue(CrawlTask::get("https://x/c", Tier::JsDiscovered, 0));
        assert_eq!(q.pop().unwrap().tier, Tier::Explicit);
        assert_eq!(q.pop().unwrap().tier, Tier::Bfs);
        assert_eq!(q.pop().unwrap().tier, Tier::JsDiscovered);
    }

    #[test]
    fn telemetry_counters() {
        let mut q = CrawlQueue::new();
        q.enqueue(CrawlTask::get("https://x/1", Tier::Bfs, 0));
        q.enqueue(CrawlTask::get("https://x/2", Tier::Bfs, 0));
        q.pop();
        q.pop();
        assert_eq!(q.popped_for(Tier::Bfs), 2);
        assert_eq!(q.popped_for(Tier::Explicit), 0);
    }
}
