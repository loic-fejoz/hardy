//! Sorted, coalesced, non-overlapping half-open `u64` ranges.
//!
//! Tracks received byte extents for the receiver and cumulative acknowledged claims
//! for the sender (RFC 5326 §6.12, §6.13).

use alloc::vec::Vec;
use core::ops::Range;

/// A set of `u64` values stored as sorted, non-overlapping, coalesced half-open ranges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RangeSet {
    runs: Vec<Range<u64>>,
}

impl RangeSet {
    /// Creates an empty `RangeSet`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a range into the set, coalescing adjacent and overlapping runs.
    ///
    /// Returns the number of newly covered values.
    pub fn insert(&mut self, r: Range<u64>) -> u64 {
        if r.start >= r.end {
            return 0;
        }

        // Fast path 1: Empty set or strictly following last run (sequential arrival)
        if let Some(last) = self.runs.last_mut() {
            if last.end == r.start {
                last.end = r.end;
                return r.end - r.start;
            }
            if last.end < r.start {
                let len = r.end - r.start;
                self.runs.push(r);
                return len;
            }
            if last.start <= r.start && r.end <= last.end {
                return 0;
            }
        } else {
            let len = r.end - r.start;
            self.runs.push(r);
            return len;
        }

        // General path: Find the first run that could touch or follow `r`
        let first = self.runs.partition_point(|run| run.end < r.start);
        let mut new_start = r.start;
        let mut new_end = r.end;
        let mut newly = r.end - r.start;
        let mut last = first;

        while last < self.runs.len() && self.runs[last].start <= new_end {
            let run = &self.runs[last];
            newly -= overlap(run, &r);
            new_start = new_start.min(run.start);
            new_end = new_end.max(run.end);
            last += 1;
        }

        if first == last {
            self.runs.insert(first, new_start..new_end);
        } else if last == first + 1 {
            self.runs[first] = new_start..new_end;
        } else {
            self.runs
                .splice(first..last, core::iter::once(new_start..new_end));
        }
        newly
    }

    /// Returns true if every point in `r` is contained in the set.
    #[must_use]
    pub fn covers(&self, r: &Range<u64>) -> bool {
        if r.start >= r.end {
            return true;
        }
        let i = self.runs.partition_point(|run| run.end < r.end);
        self.runs
            .get(i)
            .is_some_and(|run| run.start <= r.start && r.end <= run.end)
    }

    /// Returns the total count of covered discrete values.
    #[must_use]
    pub fn covered_len(&self) -> u64 {
        self.runs.iter().map(|r| r.end - r.start).sum()
    }

    /// Returns the number of disjoint runs.
    #[must_use]
    pub fn run_count(&self) -> usize {
        self.runs.len()
    }

    /// Returns an iterator over all covered sub-ranges clipped to `scope`, in ascending order.
    pub fn runs_within(&self, scope: Range<u64>) -> impl Iterator<Item = Range<u64>> + '_ {
        let start = self.runs.partition_point(|run| run.end <= scope.start);
        self.runs[start..]
            .iter()
            .take_while(move |run| run.start < scope.end)
            .map(move |run| run.start.max(scope.start)..run.end.min(scope.end))
    }

    /// Returns an iterator over all gaps within `scope` in ascending order.
    pub fn gaps(&self, scope: Range<u64>) -> impl Iterator<Item = Range<u64>> + '_ {
        GapIter {
            inner: self.runs_within(scope.clone()),
            cursor: scope.start,
            end: scope.end,
            done: false,
        }
    }
}

fn overlap(a: &Range<u64>, b: &Range<u64>) -> u64 {
    let start = a.start.max(b.start);
    let end = a.end.min(b.end);
    end.saturating_sub(start)
}

struct GapIter<I> {
    inner: I,
    cursor: u64,
    end: u64,
    done: bool,
}

impl<I> Iterator for GapIter<I>
where
    I: Iterator<Item = Range<u64>>,
{
    type Item = Range<u64>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        for run in self.inner.by_ref() {
            if run.start > self.cursor {
                let gap = self.cursor..run.start;
                self.cursor = run.end;
                return Some(gap);
            }
            self.cursor = run.end;
        }

        if self.cursor < self.end {
            self.done = true;
            Some(self.cursor..self.end)
        } else {
            self.done = true;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_coalesce() {
        let mut set = RangeSet::new();
        assert_eq!(set.insert(10..20), 10);
        assert_eq!(set.insert(20..30), 10); // Coalesces into 10..30
        assert_eq!(set.run_count(), 1);
        assert_eq!(set.covered_len(), 20);
        assert!(set.covers(&(15..25)));

        // Overlapping insert
        assert_eq!(set.insert(5..15), 5); // Coalesces into 5..30
        assert_eq!(set.run_count(), 1);
        assert_eq!(set.covered_len(), 25);
    }

    #[test]
    fn gaps_iteration() {
        let mut set = RangeSet::new();
        set.insert(10..20);
        set.insert(30..40);
        assert_eq!(set.run_count(), 2);

        let gaps: Vec<_> = set.gaps(0..50).collect();
        assert_eq!(gaps, alloc::vec![0..10, 20..30, 40..50]);
    }
}
