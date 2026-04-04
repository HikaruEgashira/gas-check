/// Compute Shannon entropy of a byte string (log₂ scale, 0..~8).
///
/// Higher entropy indicates more randomness, which is characteristic of real secrets.
/// Typical thresholds: 3.0–3.5 for mixed alphanumeric, 4.0+ for high-quality random tokens.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let len = s.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_for_empty() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn zero_for_single_char() {
        assert!(shannon_entropy("a") < f64::EPSILON);
    }

    #[test]
    fn low_for_repeated() {
        assert!(shannon_entropy("aaaaaaaaaaaa") < 1.0);
    }

    #[test]
    fn high_for_random() {
        assert!(shannon_entropy("a9ZkL3xQ7mR5wB2iP4nT") > 3.5);
    }

    #[test]
    fn moderate_for_hex() {
        let e = shannon_entropy("deadbeef12345678");
        assert!(e > 2.5 && e < 4.0);
    }
}
