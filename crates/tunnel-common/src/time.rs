//! Time helpers for metrics and heartbeats.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Wall-clock milliseconds since the Unix epoch.
///
/// Used for PING payloads so both ends can compute an RTT without a shared
/// clock assumption (the initiator compares against its own later reading).
pub fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u64
}

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Human-friendly byte rendering for logs and the UI fallback.
pub fn fmt_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.2} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn millis_is_after_2020() {
        assert!(now_millis() > 1_577_836_800_000);
        assert!(now_secs() > 1_577_836_800);
    }

    #[test]
    fn byte_formatting() {
        assert_eq!(fmt_bytes(512), "512 B");
        assert_eq!(fmt_bytes(1024), "1.00 KiB");
        assert_eq!(fmt_bytes(1536), "1.50 KiB");
        assert_eq!(fmt_bytes(1024 * 1024), "1.00 MiB");
    }
}
