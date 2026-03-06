// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// Copyright 2026 Paolo Vella

//! Shared ISO 8601 timestamp parsing utilities.
//!
//! Provides a single, reusable parser for converting ISO 8601 timestamps
//! (format `YYYY-MM-DDTHH:MM:SS...`) to approximate Unix epoch seconds.
//! Used by both `etdi` and `minja` modules to avoid duplicated validation logic.

/// Parse an ISO 8601 timestamp to approximate Unix epoch seconds.
///
/// Accepts timestamps in the format `YYYY-MM-DDTHH:MM:SS` (with optional
/// trailing characters like `Z` or fractional seconds). Returns `Err` with
/// a description if the timestamp is malformed or contains invalid values.
///
/// SECURITY (FIND-P1-6): Validates that year >= 1970, month in 1..=12,
/// day in 1..=31, hour in 0..=23, minute in 0..=59, second in 0..=60
/// (allowing leap seconds). Rejects values that would cause underflow
/// in the epoch calculation.
///
/// Note: The calculation is approximate (assumes 365-day years and 30-day
/// months) but is consistent and monotonic, which is sufficient for
/// relative time comparisons (trust decay, expiry checks).
pub fn parse_iso8601_secs(ts: &str) -> Result<u64, String> {
    if ts.len() < 19 {
        return Err(format!(
            "Timestamp too short ({} chars, need at least 19)",
            ts.len()
        ));
    }

    let year: u64 = ts
        .get(0..4)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid year".to_string())?;
    let month: u64 = ts
        .get(5..7)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid month".to_string())?;
    let day: u64 = ts
        .get(8..10)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid day".to_string())?;
    let hour: u64 = ts
        .get(11..13)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid hour".to_string())?;
    let min: u64 = ts
        .get(14..16)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid minute".to_string())?;
    let sec: u64 = ts
        .get(17..19)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| "Invalid second".to_string())?;

    if year < 1970 {
        return Err(format!("Year {year} is before Unix epoch (1970)"));
    }
    if month == 0 || month > 12 {
        return Err(format!("Month {month} out of range 1..=12"));
    }
    // SECURITY (R226-TYP-1): Validate day against actual month length, including
    // leap year support. Previously accepted Feb 31, Apr 31, etc., enabling
    // credential expiry bypass via artificially large timestamps.
    let is_leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let max_day: u64 = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap {
                29
            } else {
                28
            }
        }
        _ => return Err(format!("Month {month} out of range 1..=12")),
    };
    if day == 0 || day > max_day {
        return Err(format!(
            "Day {day} out of range for month {month} (max {max_day})"
        ));
    }
    if hour > 23 {
        return Err(format!("Hour {hour} out of range 0..=23"));
    }
    if min > 59 {
        return Err(format!("Minute {min} out of range 0..=59"));
    }
    // sec == 60 is valid for leap seconds in ISO 8601, but > 60 is not
    if sec > 60 {
        return Err(format!("Second {sec} out of range 0..=60"));
    }

    // SECURITY (R226-TYP-2): Use correct cumulative day-of-year offsets instead
    // of 30-day approximation. The old formula `(month-1)*30` caused ~99-day skew
    // by December, enabling time-window policy bypass.
    let month_offsets: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let day_of_year = month_offsets[(month - 1) as usize] + (day - 1);
    // Add leap day if past February in a leap year
    let leap_adjustment = if is_leap && month > 2 { 1 } else { 0 };

    // Count leap years between 1970 and (year-1) for correct epoch offset
    let leap_years_since_epoch = if year > 1970 {
        let y = year - 1; // count up to previous year
        let from_1970 = 1969u64; // year before epoch
        (y / 4 - from_1970 / 4) - (y / 100 - from_1970 / 100) + (y / 400 - from_1970 / 400)
    } else {
        0
    };
    let days_since_epoch =
        (year - 1970) * 365 + leap_years_since_epoch + day_of_year + leap_adjustment;
    Ok(days_since_epoch * 86400 + hour * 3600 + min * 60 + sec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iso8601_secs_valid_timestamp() {
        let result = parse_iso8601_secs("2026-02-01T00:00:00Z");
        assert!(result.is_ok());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn test_parse_iso8601_secs_valid_without_z() {
        // Parser accepts timestamps without trailing Z (minja use case)
        let result = parse_iso8601_secs("2026-02-01T12:30:45");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_iso8601_secs_too_short() {
        let result = parse_iso8601_secs("2026-02");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_month_zero() {
        let result = parse_iso8601_secs("2026-00-15T12:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Month"));
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_month_13() {
        let result = parse_iso8601_secs("2026-13-01T00:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Month"));
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_year_before_epoch() {
        let result = parse_iso8601_secs("1969-06-15T12:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("before Unix epoch"));
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_day_zero() {
        let result = parse_iso8601_secs("2026-01-00T12:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Day"));
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_hour_25() {
        let result = parse_iso8601_secs("2026-01-01T25:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Hour"));
    }

    #[test]
    fn test_parse_iso8601_secs_allows_leap_second() {
        let result = parse_iso8601_secs("2026-01-01T23:59:60Z");
        assert!(result.is_ok());
    }

    #[test]
    fn test_parse_iso8601_secs_rejects_second_61() {
        let result = parse_iso8601_secs("2026-01-01T23:59:61Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Second"));
    }

    #[test]
    fn test_parse_iso8601_secs_monotonic() {
        let t1 = parse_iso8601_secs("2026-01-01T00:00:00Z").unwrap();
        let t2 = parse_iso8601_secs("2026-01-02T00:00:00Z").unwrap();
        let t3 = parse_iso8601_secs("2026-02-01T00:00:00Z").unwrap();
        assert!(t1 < t2);
        assert!(t2 < t3);
    }

    /// R226-TYP-1: Feb 31 must be rejected (invalid date).
    #[test]
    fn test_parse_iso8601_secs_rejects_feb_31() {
        let result = parse_iso8601_secs("2026-02-31T00:00:00Z");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Day"), "Must reject Feb 31");
    }

    /// R226-TYP-1: Feb 29 in non-leap year must be rejected.
    #[test]
    fn test_parse_iso8601_secs_rejects_feb_29_non_leap() {
        let result = parse_iso8601_secs("2026-02-29T00:00:00Z");
        assert!(result.is_err(), "2026 is not a leap year — Feb 29 invalid");
    }

    /// R226-TYP-1: Feb 29 in leap year must be accepted.
    #[test]
    fn test_parse_iso8601_secs_accepts_feb_29_leap() {
        let result = parse_iso8601_secs("2024-02-29T00:00:00Z");
        assert!(result.is_ok(), "2024 is a leap year — Feb 29 valid");
    }

    /// R226-TYP-1: Apr 31, Jun 31, Sep 31, Nov 31 must be rejected.
    #[test]
    fn test_parse_iso8601_secs_rejects_day_31_in_30day_months() {
        for month in &["04", "06", "09", "11"] {
            let ts = format!("2026-{}-31T00:00:00Z", month);
            let result = parse_iso8601_secs(&ts);
            assert!(result.is_err(), "Month {} has only 30 days", month);
        }
    }

    /// R226-TYP-2: Epoch accuracy — 2026-01-01 should be close to actual epoch.
    #[test]
    fn test_parse_iso8601_secs_epoch_accuracy() {
        // 2026-01-01T00:00:00Z actual Unix epoch = 1767225600
        let result = parse_iso8601_secs("2026-01-01T00:00:00Z").unwrap();
        let actual_epoch = 1767225600u64;
        let diff = result.abs_diff(actual_epoch);
        // Should be within 1 day of actual epoch (86400 seconds)
        assert!(
            diff < 86400,
            "Epoch calculation off by {} seconds (result={}, expected={})",
            diff,
            result,
            actual_epoch
        );
    }

    /// R226-TYP-2: Monotonic across all months (regression for 30-day approx fix).
    #[test]
    fn test_parse_iso8601_secs_monotonic_all_months() {
        let mut prev = 0u64;
        for month in 1..=12 {
            let ts = format!("2026-{:02}-01T00:00:00Z", month);
            let val = parse_iso8601_secs(&ts).unwrap();
            assert!(
                val > prev,
                "Month {} must be greater than previous (got {} <= {})",
                month,
                val,
                prev
            );
            prev = val;
        }
    }

    /// R226-TYP-1: Century leap year rules (2000 is leap, 1900 is not, 2100 is not).
    #[test]
    fn test_parse_iso8601_secs_century_leap_years() {
        // 2000 is a leap year (divisible by 400)
        assert!(parse_iso8601_secs("2000-02-29T00:00:00Z").is_ok());
        // 2100 is NOT a leap year (divisible by 100 but not 400)
        assert!(parse_iso8601_secs("2100-02-29T00:00:00Z").is_err());
    }
}
