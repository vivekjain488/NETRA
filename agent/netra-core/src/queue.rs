//! The bounded local event queue (spec §15, §37).
//!
//! When the backend is unreachable the agent keeps collecting, but local
//! storage on a government endpoint must never grow without limit. The queue
//! is bounded by both event count and total bytes, and overflow evicts the
//! oldest events while counting the loss so it is visible rather than silent.

use crate::event::{Event, Severity};
use std::collections::VecDeque;

/// A point-in-time view of queue health, reported to the backend so the SOC
/// can see that an endpoint is shedding telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct QueueStats {
    pub len: usize,
    pub bytes: usize,
    pub dropped_total: u64,
    pub capacity_events: usize,
    pub capacity_bytes: usize,
}

impl QueueStats {
    /// Fraction of the tighter of the two limits currently in use, 0.0..=1.0.
    pub fn utilisation(&self) -> f64 {
        let by_count = ratio(self.len, self.capacity_events);
        let by_bytes = ratio(self.bytes, self.capacity_bytes);
        by_count.max(by_bytes)
    }
}

fn ratio(used: usize, capacity: usize) -> f64 {
    if capacity == 0 {
        return 0.0;
    }
    (used as f64 / capacity as f64).min(1.0)
}

/// A bounded FIFO queue of pending events.
#[derive(Debug)]
pub struct EventQueue {
    items: VecDeque<(Event, usize)>,
    bytes: usize,
    max_events: usize,
    max_bytes: usize,
    dropped_total: u64,
}

impl EventQueue {
    /// Creates a queue with the given bounds. Both bounds are clamped to at
    /// least one so a misconfiguration cannot produce a queue that silently
    /// discards everything.
    pub fn new(max_events: usize, max_bytes: usize) -> Self {
        Self {
            items: VecDeque::new(),
            bytes: 0,
            max_events: max_events.max(1),
            max_bytes: max_bytes.max(1),
            dropped_total: 0,
        }
    }

    /// Enqueues an event, evicting the oldest events if a bound is exceeded.
    ///
    /// Returns the number of events evicted to make room.
    pub fn push(&mut self, event: Event) -> usize {
        let size = event.encoded_len();

        // A single event larger than the whole budget cannot be stored at all;
        // dropping it here keeps the invariant that the queue never exceeds
        // its bounds.
        if size > self.max_bytes {
            self.dropped_total += 1;
            return 1;
        }

        self.items.push_back((event, size));
        self.bytes += size;

        let mut evicted = 0;
        while self.items.len() > self.max_events || self.bytes > self.max_bytes {
            match self.items.pop_front() {
                Some((_, evicted_size)) => {
                    self.bytes -= evicted_size;
                    self.dropped_total += 1;
                    evicted += 1;
                }
                None => break,
            }
        }
        evicted
    }

    /// Removes and returns up to `max` events in arrival order, for batching.
    pub fn drain(&mut self, max: usize) -> Vec<Event> {
        let take = max.min(self.items.len());
        let mut batch = Vec::with_capacity(take);
        for _ in 0..take {
            if let Some((event, size)) = self.items.pop_front() {
                self.bytes -= size;
                batch.push(event);
            }
        }
        batch
    }

    /// Returns a drained batch to the front of the queue after a failed send,
    /// preserving order. Bounds still apply, so a batch that no longer fits is
    /// trimmed rather than allowed to exceed the limit.
    pub fn requeue_front(&mut self, batch: Vec<Event>) {
        for event in batch.into_iter().rev() {
            let size = event.encoded_len();
            if size > self.max_bytes {
                self.dropped_total += 1;
                continue;
            }
            self.items.push_front((event, size));
            self.bytes += size;
        }
        while self.items.len() > self.max_events || self.bytes > self.max_bytes {
            // Trim from the back here: the front holds the events that already
            // failed a send attempt and are oldest.
            match self.items.pop_back() {
                Some((_, size)) => {
                    self.bytes -= size;
                    self.dropped_total += 1;
                }
                None => break,
            }
        }
    }

    /// Number of queued events.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Highest severity currently queued, if any. Used to decide whether a
    /// send should be attempted ahead of the normal batching interval.
    pub fn peak_severity(&self) -> Option<Severity> {
        self.items.iter().map(|(e, _)| e.severity).max()
    }

    /// Current queue statistics.
    pub fn stats(&self) -> QueueStats {
        QueueStats {
            len: self.items.len(),
            bytes: self.bytes,
            dropped_total: self.dropped_total,
            capacity_events: self.max_events,
            capacity_bytes: self.max_bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::EventType;

    fn event(severity: Severity) -> Event {
        Event::new(EventType::SecurityEvent, severity)
    }

    #[test]
    fn drains_in_arrival_order() {
        let mut q = EventQueue::new(10, 1_000_000);
        let ids: Vec<String> = (0..3)
            .map(|_| {
                let e = event(Severity::Info);
                let id = e.event_id.clone();
                q.push(e);
                id
            })
            .collect();

        let drained: Vec<String> = q.drain(3).into_iter().map(|e| e.event_id).collect();

        assert_eq!(drained, ids, "queue must be FIFO");
        assert!(q.is_empty());
    }

    #[test]
    fn enforces_event_count_bound() {
        let mut q = EventQueue::new(3, 1_000_000);
        for _ in 0..10 {
            q.push(event(Severity::Info));
        }

        assert_eq!(q.len(), 3, "queue exceeded its event bound");
        assert_eq!(q.stats().dropped_total, 7, "drops must be counted, not silent");
    }

    #[test]
    fn enforces_byte_bound() {
        let one = event(Severity::Info).encoded_len();
        let mut q = EventQueue::new(1_000_000, one * 3);

        for _ in 0..20 {
            q.push(event(Severity::Info));
        }

        let stats = q.stats();
        assert!(stats.bytes <= one * 3, "queue exceeded its byte bound: {stats:?}");
        assert!(stats.dropped_total > 0);
    }

    #[test]
    fn evicts_oldest_first() {
        let mut q = EventQueue::new(2, 1_000_000);
        let first = event(Severity::Info);
        let first_id = first.event_id.clone();
        q.push(first);
        q.push(event(Severity::Info));
        q.push(event(Severity::Info));

        let remaining: Vec<String> = q.drain(10).into_iter().map(|e| e.event_id).collect();

        assert!(!remaining.contains(&first_id), "newest events must be kept");
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn rejects_event_larger_than_whole_budget() {
        let mut q = EventQueue::new(100, 1);

        assert_eq!(q.push(event(Severity::Info)), 1);
        assert!(q.is_empty(), "an oversized event must not be stored");
        assert_eq!(q.stats().dropped_total, 1);
    }

    #[test]
    fn requeue_preserves_order_after_failed_send() {
        let mut q = EventQueue::new(10, 1_000_000);
        for _ in 0..3 {
            q.push(event(Severity::Info));
        }
        let batch = q.drain(2);
        let batch_ids: Vec<String> = batch.iter().map(|e| e.event_id.clone()).collect();

        q.requeue_front(batch);
        let all: Vec<String> = q.drain(10).into_iter().map(|e| e.event_id).collect();

        assert_eq!(&all[..2], &batch_ids[..], "requeued events must return to the front, in order");
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn requeue_still_respects_bounds() {
        let mut q = EventQueue::new(2, 1_000_000);
        let batch: Vec<Event> = (0..5).map(|_| event(Severity::Info)).collect();

        q.requeue_front(batch);

        assert_eq!(q.len(), 2, "requeue must not be a way around the bound");
    }

    #[test]
    fn reports_peak_severity() {
        let mut q = EventQueue::new(10, 1_000_000);
        q.push(event(Severity::Info));
        q.push(event(Severity::Critical));
        q.push(event(Severity::Low));

        assert_eq!(q.peak_severity(), Some(Severity::Critical));
    }

    #[test]
    fn empty_queue_has_no_peak_severity() {
        assert_eq!(EventQueue::new(10, 1000).peak_severity(), None);
    }

    #[test]
    fn utilisation_tracks_the_tighter_bound() {
        let mut q = EventQueue::new(4, 1_000_000);
        q.push(event(Severity::Info));
        q.push(event(Severity::Info));

        let u = q.stats().utilisation();
        assert!((u - 0.5).abs() < 1e-9, "utilisation = {u}, want 0.5");
    }

    #[test]
    fn zero_bounds_are_clamped() {
        // A misconfigured zero bound must not create a queue that discards
        // every event without any record of doing so.
        let mut q = EventQueue::new(0, 0);
        q.push(event(Severity::Info));

        let stats = q.stats();
        assert!(stats.capacity_events >= 1 && stats.capacity_bytes >= 1);
    }
}
