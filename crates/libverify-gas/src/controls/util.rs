/// Parse an RFC 3339 timestamp to epoch seconds (second-level precision).
/// Returns None if the string is missing or malformed.
pub fn parse_epoch(ts: &str) -> Option<i64> {
    let ts = ts.trim();
    if ts.len() < 19 {
        return None;
    }
    let year: i64 = ts[0..4].parse().ok()?;
    let month: i64 = ts[5..7].parse().ok()?;
    let day: i64 = ts[8..10].parse().ok()?;
    let hour: i64 = ts[11..13].parse().ok()?;
    let min: i64 = ts[14..16].parse().ok()?;
    let sec: i64 = ts[17..19].parse().ok()?;

    let days = (year - 1970) * 365 + (year - 1969) / 4 + day_of_year(month, day);
    Some(days * 86400 + hour * 3600 + min * 60 + sec)
}

fn day_of_year(month: i64, day: i64) -> i64 {
    const CUMULATIVE: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    CUMULATIVE.get((month - 1) as usize).copied().unwrap_or(0) + day - 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_difference() {
        let a = parse_epoch("2025-06-01T10:00:00.000Z").unwrap();
        let b = parse_epoch("2025-06-01T10:00:05.000Z").unwrap();
        assert_eq!(b - a, 5);
    }

    #[test]
    fn returns_none_for_short_string() {
        assert!(parse_epoch("2025").is_none());
    }

    #[test]
    fn returns_none_for_malformed() {
        assert!(parse_epoch("not-a-timestamp!!!!!").is_none());
    }
}
