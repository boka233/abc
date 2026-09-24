//! Host metrics, read from `/proc` on Linux.
//!
//! Deliberately dependency-free. A crate like `sysinfo` brings broad platform
//! support the agent does not need — it runs on Linux servers — and it samples
//! far more than the four numbers shown in the panel.
//!
//! CPU percentage needs two samples to be meaningful, so the previous reading is
//! kept in a static and the first call reports 0 rather than a fabricated value.
//!
//! On non-Linux hosts the fields that cannot be read stay zero. The agent is not
//! *supported* on those platforms, but it must still build and run for
//! development and tests.

use std::sync::atomic::{AtomicU64, Ordering};

use tunnel_common::model::HostStats;

const REL: Ordering = Ordering::Relaxed;

/// Previous `/proc/stat` totals, for the CPU delta.
static PREV_TOTAL: AtomicU64 = AtomicU64::new(0);
static PREV_IDLE: AtomicU64 = AtomicU64::new(0);

pub fn sample() -> HostStats {
    HostStats {
        cpu_percent: cpu_percent(),
        memory_used_bytes: memory().map(|m| m.used).unwrap_or(0),
        memory_total_bytes: memory().map(|m| m.total).unwrap_or(0),
        uptime_secs: 0, // filled in by the supervisor with process uptime
        open_fds: open_fds(),
        load_avg_1m: load_average(),
    }
}

struct Memory {
    total: u64,
    used: u64,
}

/// Parse `/proc/meminfo`.
///
/// Uses `MemAvailable` rather than `MemFree`: free memory excludes the page
/// cache, so reporting it makes a healthy Linux box look like it is out of
/// memory. `MemAvailable` is the kernel's own estimate of what is actually
/// obtainable.
fn memory() -> Option<Memory> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    let mut total_kb = None;
    let mut available_kb = None;

    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total_kb = parse_kb(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available_kb = parse_kb(rest);
        }
        if total_kb.is_some() && available_kb.is_some() {
            break;
        }
    }

    let total = total_kb? * 1024;
    let available = available_kb.unwrap_or(0) * 1024;
    Some(Memory {
        total,
        used: total.saturating_sub(available),
    })
}

fn parse_kb(rest: &str) -> Option<u64> {
    rest.split_whitespace().next()?.parse().ok()
}

/// CPU utilisation since the previous call, from `/proc/stat`.
fn cpu_percent() -> f32 {
    let Ok(text) = std::fs::read_to_string("/proc/stat") else {
        return 0.0;
    };
    let Some(line) = text.lines().next() else {
        return 0.0;
    };
    if !line.starts_with("cpu ") {
        return 0.0;
    }

    // user nice system idle iowait irq softirq steal ...
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|f| f.parse().ok())
        .collect();
    if fields.len() < 4 {
        return 0.0;
    }

    let total: u64 = fields.iter().sum();
    // idle + iowait: a process blocked on disk is not consuming CPU.
    let idle = fields[3] + fields.get(4).copied().unwrap_or(0);

    let prev_total = PREV_TOTAL.swap(total, REL);
    let prev_idle = PREV_IDLE.swap(idle, REL);

    // First call has no baseline; a fabricated number would be worse than zero.
    if prev_total == 0 || total <= prev_total {
        return 0.0;
    }

    let total_delta = (total - prev_total) as f32;
    let idle_delta = idle.saturating_sub(prev_idle) as f32;
    if total_delta <= 0.0 {
        return 0.0;
    }
    (((total_delta - idle_delta) / total_delta) * 100.0).clamp(0.0, 100.0)
}

/// Open descriptors for this process.
///
/// Worth surfacing: descriptor exhaustion is the most common way a busy relay
/// starts refusing connections, and the count makes it obvious.
fn open_fds() -> Option<u64> {
    let dir = std::fs::read_dir("/proc/self/fd").ok()?;
    Some(dir.count() as u64)
}

fn load_average() -> Option<f32> {
    let text = std::fs::read_to_string("/proc/loadavg").ok()?;
    text.split_whitespace().next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_never_panics_on_any_platform() {
        // On Windows and macOS every /proc read fails; the result must be zeros,
        // not a panic.
        let stats = sample();
        assert!(stats.cpu_percent >= 0.0 && stats.cpu_percent <= 100.0);
        // `.max(u64::MAX)` 会让整个断言恒真 —— 原意是「读不到总量时不做比较」，
        // 应当显式写出这个条件，而不是靠一个永远取到上界的 max。
        if stats.memory_total_bytes > 0 {
            assert!(stats.memory_used_bytes <= stats.memory_total_bytes);
        }
    }

    #[test]
    fn cpu_percent_stays_in_range_across_repeated_calls() {
        for _ in 0..5 {
            let value = cpu_percent();
            assert!(
                (0.0..=100.0).contains(&value),
                "cpu_percent out of range: {value}"
            );
        }
    }

    #[test]
    fn meminfo_parsing() {
        assert_eq!(parse_kb("   16384000 kB"), Some(16_384_000));
        assert_eq!(parse_kb(" 123 kB"), Some(123));
        assert_eq!(parse_kb("garbage"), None);
        assert_eq!(parse_kb(""), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reports_real_memory() {
        let m = memory().expect("/proc/meminfo should be readable on Linux");
        assert!(m.total > 0);
        assert!(m.used <= m.total, "used {} exceeds total {}", m.used, m.total);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_reports_descriptors_and_load() {
        assert!(open_fds().unwrap_or(0) > 0);
        assert!(load_average().is_some());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn non_linux_degrades_to_zero_rather_than_failing() {
        let stats = sample();
        assert_eq!(stats.memory_total_bytes, 0);
        assert_eq!(stats.cpu_percent, 0.0);
    }
}
