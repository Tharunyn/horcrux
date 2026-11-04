use crate::audit::{Entry, EntryKind};
use serde::Serialize;
use std::collections::{BTreeMap, HashSet};

const ONE_HOUR_MS: u64 = 60 * 60 * 1000;
const ONE_MINUTE_MS: u64 = 60 * 1000;

/// Advisory risk classification. This does not control signing permissions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

/// Activity measurements used to explain the risk assessment.
#[derive(Debug, Clone, Serialize)]
pub struct RiskMetrics {
    pub entries_analyzed: usize,
    pub entries_in_window: usize,
    pub failed_decryptions: usize,
    pub failed_attempts: usize,
    pub blocked_attempts: usize,
    pub attempts_in_window: usize,
    pub rapid_attempts: usize,
    pub affected_shards: usize,
    pub odd_hour_events: usize,
}

/// Complete risk assessment returned to the dashboard.
#[derive(Debug, Clone, Serialize)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub score: u8,
    pub reasons: Vec<String>,
    pub recommendations: Vec<String>,
    pub metrics: RiskMetrics,
}

#[derive(Default)]
struct AttemptSignals {
    first_ts: u64,
    failed: bool,
    blocked: bool,
    failed_shards: HashSet<u8>,
}

/// Analyse access-log history and calculate an advisory risk score.
///
/// The one-hour window is measured backwards from the newest timestamp
/// in the supplied entries. Input entries do not need to be chronological.
///
/// Multiple shard events belonging to the same attempt count as one attempt.
pub fn assess(entries: &[Entry]) -> RiskAssessment {
    if entries.is_empty() {
        return RiskAssessment {
            level: RiskLevel::Low,
            score: 0,
            reasons: vec!["No access-log entries are available.".to_string()],
            recommendations: vec![
                "Continue monitoring access activity as log entries accumulate.".to_string(),
            ],
            metrics: RiskMetrics {
                entries_analyzed: 0,
                entries_in_window: 0,
                failed_decryptions: 0,
                failed_attempts: 0,
                blocked_attempts: 0,
                attempts_in_window: 0,
                rapid_attempts: 0,
                affected_shards: 0,
                odd_hour_events: 0,
            },
        };
    }

    // Sort by timestamp so calculations do not depend on file ordering.
    let mut ordered: Vec<&Entry> = entries.iter().collect();
    ordered.sort_by_key(|entry| entry.ts);

    let newest_ts = ordered.last().map(|entry| entry.ts).unwrap_or(0);
    let window_start = newest_ts.saturating_sub(ONE_HOUR_MS);

    let window_entries: Vec<&Entry> = ordered
        .iter()
        .copied()
        .filter(|entry| entry.ts >= window_start)
        .collect();

    let mut attempts: BTreeMap<u64, AttemptSignals> = BTreeMap::new();
    let mut failed_decryptions = 0usize;
    let mut odd_hour_events = 0usize;
    let mut affected_shards = HashSet::new();

    for entry in &window_entries {
        let attempt = attempts
            .entry(entry.attempt)
            .or_insert_with(|| AttemptSignals {
                first_ts: entry.ts,
                ..Default::default()
            });

        attempt.first_ts = attempt.first_ts.min(entry.ts);

        // Unix timestamps are in milliseconds. This calculates UTC hour.
        let utc_hour = (entry.ts / 3_600_000) % 24;
        if utc_hour < 6 {
            odd_hour_events += 1;
        }

        match &entry.kind {
            EntryKind::DecryptFail => {
                failed_decryptions += 1;
                attempt.failed = true;
                attempt.failed_shards.insert(entry.shard_id);
                affected_shards.insert(entry.shard_id);
            }
            EntryKind::Blocked => {
                attempt.blocked = true;
            }
            EntryKind::DecryptOk | EntryKind::Signed => {}
        }
    }

    let failed_attempts = attempts.values().filter(|a| a.failed).count();
    let blocked_attempts = attempts.values().filter(|a| a.blocked).count();

    // Count distinct attempts, not individual shard events.
    let mut attempt_times: Vec<u64> = attempts.values().map(|a| a.first_ts).collect();
    attempt_times.sort_unstable();

    // Find the largest number of distinct attempts within any 60-second span.
    let mut rapid_attempts = 0usize;
    let mut left = 0usize;

    for right in 0..attempt_times.len() {
        while attempt_times[right].saturating_sub(attempt_times[left]) > ONE_MINUTE_MS {
            left += 1;
        }

        rapid_attempts = rapid_attempts.max(right - left + 1);
    }

    let attempts_in_window = attempts.len();
    let affected_shards_count = affected_shards.len();

    // Deterministic scoring rules.
    let mut score = 0u16;
    let mut reasons = Vec::new();
    let mut recommendations = Vec::new();

    if failed_attempts >= 3 {
        score += 30;
        reasons.push(format!(
            "{} distinct attempts had decryption failures in the latest one-hour window.",
            failed_attempts
        ));
        recommendations.push(
            "Review the failed attempts and verify that the correct guardians are using their assigned passwords."
                .to_string(),
        );
    } else if failed_attempts > 0 {
        score += 10;
        reasons.push(format!(
            "{} distinct attempt(s) had decryption failures.",
            failed_attempts
        ));
        recommendations.push(
            "Check whether the decryption failures were caused by incorrect passwords or an unexpected access attempt."
                .to_string(),
        );
    }

    if blocked_attempts >= 3 {
        score += 25;
        reasons.push(format!(
            "{} distinct attempts were blocked by the audit rules.",
            blocked_attempts
        ));
        recommendations.push(
            "Review the blocked attempts and their audit reasons before authorizing further operations."
                .to_string(),
        );
    } else if blocked_attempts > 0 {
        score += 10;
        reasons.push(format!(
            "{} distinct attempt(s) were blocked by the audit rules.",
            blocked_attempts
        ));
        recommendations.push(
            "Inspect the audit warnings associated with the blocked operation(s).".to_string(),
        );
    }

    if rapid_attempts >= 3 {
        score += 20;
        reasons.push(format!(
            "At least {} distinct attempts occurred within a 60-second interval.",
            rapid_attempts
        ));
        recommendations.push(
            "Verify whether the rapid attempts were expected. Pause repeated retries until their cause is understood."
                .to_string(),
        );
    }

    if affected_shards_count >= 3 {
        score += 10;
        reasons.push(format!(
            "Decryption failures affected {} different shards.",
            affected_shards_count
        ));
        recommendations.push(
            "Check the affected shard files and confirm that each guardian is using the correct shard and credentials."
                .to_string(),
        );
    }

    if odd_hour_events >= 3 {
        score += 5;
        reasons.push(format!(
            "{} events occurred between 00:00 and 06:00 UTC.",
            odd_hour_events
        ));
        recommendations.push(
            "Confirm whether the unusual-hour activity matches an authorized signing schedule."
                .to_string(),
        );
    }

    if reasons.is_empty() {
        reasons.push(
            "No configured risk indicators were detected in the analysed window.".to_string(),
        );
        recommendations.push(
            "Continue monitoring the access log and review new alerts when they appear."
                .to_string(),
        );
    }

    let score = score.min(100) as u8;

    let level = match score {
        0..=24 => RiskLevel::Low,
        25..=59 => RiskLevel::Medium,
        _ => RiskLevel::High,
    };

    RiskAssessment {
        level,
        score,
        reasons,
        recommendations,
        metrics: RiskMetrics {
            entries_analyzed: entries.len(),
            entries_in_window: window_entries.len(),
            failed_decryptions,
            failed_attempts,
            blocked_attempts,
            attempts_in_window,
            rapid_attempts,
            affected_shards: affected_shards_count,
            odd_hour_events,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::Entry;

    #[test]
    fn empty_log_has_zero_risk() {
        let result = assess(&[]);

        assert_eq!(result.level, RiskLevel::Low);
        assert_eq!(result.score, 0);
        assert_eq!(result.metrics.entries_analyzed, 0);
    }

    #[test]
    fn normal_activity_has_low_risk() {
        let entries = vec![
            Entry::ok(12 * 3_600_000, 1, 1),
            Entry::signed(12 * 3_600_000, 1),
            Entry::ok(13 * 3_600_000, 2, 2),
            Entry::signed(13 * 3_600_000, 2),
        ];

        let result = assess(&entries);

        assert_eq!(result.level, RiskLevel::Low);
        assert_eq!(result.score, 0);
    }

    #[test]
    fn repeated_failures_increase_risk() {
        let entries = vec![
            Entry::fail(12 * 3_600_000, 1, 1),
            Entry::fail(12 * 3_600_000 + 10_000, 2, 1),
            Entry::fail(12 * 3_600_000 + 20_000, 3, 1),
        ];

        let result = assess(&entries);

        assert_eq!(result.level, RiskLevel::Medium);
        assert_eq!(result.score, 50);
        assert_eq!(result.metrics.failed_attempts, 3);
    }

    #[test]
    fn rapid_failures_and_blocks_produce_high_risk() {
        let base = 12 * 3_600_000;

        let entries = vec![
            Entry::fail(base, 1, 1),
            Entry::blocked(base, 1),
            Entry::fail(base + 10_000, 2, 2),
            Entry::blocked(base + 10_000, 2),
            Entry::fail(base + 20_000, 3, 3),
            Entry::blocked(base + 20_000, 3),
        ];

        let result = assess(&entries);

        assert_eq!(result.level, RiskLevel::High);
        assert_eq!(result.score, 85);
        assert_eq!(result.metrics.failed_attempts, 3);
        assert_eq!(result.metrics.blocked_attempts, 3);
        assert_eq!(result.metrics.rapid_attempts, 3);
        assert_eq!(result.metrics.affected_shards, 3);
    }

    #[test]
    fn multiple_shard_events_are_one_attempt() {
        let base = 12 * 3_600_000;

        let entries = vec![
            Entry::fail(base, 1, 1),
            Entry::fail(base + 1_000, 1, 2),
            Entry::fail(base + 2_000, 1, 3),
        ];

        let result = assess(&entries);

        assert_eq!(result.metrics.failed_decryptions, 3);
        assert_eq!(result.metrics.failed_attempts, 1);
        assert_eq!(result.metrics.attempts_in_window, 1);
        assert_eq!(result.metrics.rapid_attempts, 1);
        assert_eq!(result.score, 20);
        assert_eq!(result.level, RiskLevel::Low);
    }

    #[test]
    fn input_order_does_not_change_assessment() {
        let base = 12 * 3_600_000;

        let entries = vec![
            Entry::fail(base + 20_000, 3, 3),
            Entry::fail(base, 1, 1),
            Entry::fail(base + 10_000, 2, 2),
        ];

        let result = assess(&entries);

        assert_eq!(result.score, 60);
        assert_eq!(result.level, RiskLevel::High);
    }
}
