//! Small HTTP helpers that need no Worker runtime.

/// `Retry-After` in delay-seconds form, as milliseconds. HTTP-date values are ignored:
/// the retry policy's own backoff applies instead.
pub fn parse_retry_after(value: &str) -> Option<i64> {
    let secs: i64 = value.trim().parse().ok()?;
    (secs >= 0).then(|| secs.saturating_mul(1000))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_seconds_only() {
        assert_eq!(parse_retry_after("120"), Some(120_000));
        assert_eq!(parse_retry_after(" 0 "), Some(0));
        assert_eq!(parse_retry_after("-1"), None);
        assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), None);
    }
}
