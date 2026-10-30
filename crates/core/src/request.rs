use crate::limits::{
    DEFAULT_MAX_ATTEMPTS, MAX_ATTEMPTS, MAX_BODY_BYTES, MAX_HEADERS, MAX_HEADER_BYTES,
    MAX_IDEMPOTENCY_KEY_BYTES, MAX_SCHEDULE_AHEAD_MS,
};
use runlater_egress::{validate_header, Destination, DestinationError, HeaderError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    Get,
    #[default]
    Post,
    Put,
    Patch,
    Delete,
}

impl Method {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// `schedule_http` input exactly as the caller sent it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleRequest {
    pub url: String,
    #[serde(default)]
    pub method: Method,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    /// Unix milliseconds. Absent or in the past means "as soon as possible".
    #[serde(default)]
    pub run_at_ms: Option<i64>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub max_attempts: Option<u32>,
}

/// A validated request, ready to become a task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskSpec {
    pub destination: Destination,
    pub method: Method,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub run_at_ms: i64,
    pub max_attempts: u32,
    pub idempotency_key: Option<String>,
    /// Hash of the request as submitted. A repeated idempotency key with a different
    /// fingerprint is a conflict, not a replay.
    pub fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    Destination(DestinationError),
    Header(HeaderError),
    DuplicateHeader(String),
    TooManyHeaders,
    HeadersTooLarge,
    BodyTooLarge,
    BodyNotAllowed,
    RunAtNegative,
    RunAtTooFar,
    MaxAttempts,
    IdempotencyKey,
}

impl ValidationError {
    /// The request field at fault, for error responses.
    pub fn field(&self) -> &'static str {
        match self {
            Self::Destination(_) => "url",
            Self::Header(_) | Self::DuplicateHeader(_) | Self::TooManyHeaders => "headers",
            Self::HeadersTooLarge => "headers",
            Self::BodyTooLarge | Self::BodyNotAllowed => "body",
            Self::RunAtNegative | Self::RunAtTooFar => "run_at_ms",
            Self::MaxAttempts => "max_attempts",
            Self::IdempotencyKey => "idempotency_key",
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Destination(e) => e.fmt(f),
            Self::Header(e) => e.fmt(f),
            Self::DuplicateHeader(n) => write!(f, "header {n:?} is given more than once"),
            Self::TooManyHeaders => write!(f, "at most {MAX_HEADERS} headers are allowed"),
            Self::HeadersTooLarge => write!(f, "headers exceed {MAX_HEADER_BYTES} bytes"),
            Self::BodyTooLarge => write!(f, "body exceeds {MAX_BODY_BYTES} bytes"),
            Self::BodyNotAllowed => f.write_str("GET requests cannot have a body"),
            Self::RunAtNegative => f.write_str("run_at_ms must not be negative"),
            Self::RunAtTooFar => f.write_str("run_at_ms is more than 7 days away"),
            Self::MaxAttempts => write!(f, "max_attempts must be between 1 and {MAX_ATTEMPTS}"),
            Self::IdempotencyKey => write!(
                f,
                "idempotency_key must be 1-{MAX_IDEMPOTENCY_KEY_BYTES} characters of A-Z a-z 0-9 _ -"
            ),
        }
    }
}

impl std::error::Error for ValidationError {}

impl ScheduleRequest {
    pub fn validate(self, now_ms: i64) -> Result<TaskSpec, ValidationError> {
        let destination = Destination::parse(&self.url).map_err(ValidationError::Destination)?;

        if self.headers.len() > MAX_HEADERS {
            return Err(ValidationError::TooManyHeaders);
        }
        let mut seen = BTreeSet::new();
        let mut header_bytes = 0;
        for (name, value) in &self.headers {
            validate_header(name, value).map_err(ValidationError::Header)?;
            if !seen.insert(name.to_ascii_lowercase()) {
                return Err(ValidationError::DuplicateHeader(name.clone()));
            }
            header_bytes += name.len() + value.len();
        }
        if header_bytes > MAX_HEADER_BYTES {
            return Err(ValidationError::HeadersTooLarge);
        }

        if let Some(body) = &self.body {
            if self.method == Method::Get {
                return Err(ValidationError::BodyNotAllowed);
            }
            if body.len() > MAX_BODY_BYTES {
                return Err(ValidationError::BodyTooLarge);
            }
        }

        let run_at_ms = match self.run_at_ms {
            Some(t) if t < 0 => return Err(ValidationError::RunAtNegative),
            Some(t) if t > now_ms.saturating_add(MAX_SCHEDULE_AHEAD_MS) => {
                return Err(ValidationError::RunAtTooFar)
            }
            Some(t) => t.max(now_ms),
            None => now_ms,
        };

        let max_attempts = self.max_attempts.unwrap_or(DEFAULT_MAX_ATTEMPTS);
        if !(1..=MAX_ATTEMPTS).contains(&max_attempts) {
            return Err(ValidationError::MaxAttempts);
        }

        if let Some(key) = &self.idempotency_key {
            if key.is_empty()
                || key.len() > MAX_IDEMPOTENCY_KEY_BYTES
                || !key
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                return Err(ValidationError::IdempotencyKey);
            }
        }

        let fingerprint = self.fingerprint(&destination);
        Ok(TaskSpec {
            destination,
            method: self.method,
            headers: self.headers.into_iter().collect(),
            body: self.body,
            run_at_ms,
            max_attempts,
            idempotency_key: self.idempotency_key,
            fingerprint,
        })
    }

    /// Uses the normalized URL and lowercased header names so cosmetic differences replay,
    /// and the *submitted* `run_at_ms` so "now" resolving differently on a retry still matches.
    fn fingerprint(&self, destination: &Destination) -> String {
        let headers: BTreeMap<_, _> = self
            .headers
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect();
        let canonical = serde_json::to_vec(&(
            "schedule_http/v1",
            destination.as_str(),
            self.method,
            headers,
            &self.body,
            self.run_at_ms,
            self.max_attempts,
        ))
        .expect("plain data always serializes");
        hex::encode(Sha256::digest(canonical))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::limits::DAY_MS;

    const NOW: i64 = 1_767_225_600_000;

    fn req(url: &str) -> ScheduleRequest {
        ScheduleRequest {
            url: url.into(),
            ..Default::default()
        }
    }

    fn ok() -> ScheduleRequest {
        req("https://hooks.example.com/run")
    }

    fn invalid(r: ScheduleRequest) -> ValidationError {
        r.validate(NOW).unwrap_err()
    }

    #[test]
    fn minimal_request_gets_defaults() {
        let spec = ok().validate(NOW).unwrap();
        assert_eq!(spec.method, Method::Post);
        assert_eq!(spec.run_at_ms, NOW);
        assert_eq!(spec.max_attempts, DEFAULT_MAX_ATTEMPTS);
        assert_eq!(spec.destination.as_str(), "https://hooks.example.com/run");
        assert_eq!(spec.fingerprint.len(), 64);
    }

    #[test]
    fn parses_json_and_rejects_unknown_fields() {
        let r: ScheduleRequest = serde_json::from_str(
            r#"{"url":"https://a.example.com/","method":"PUT","headers":{"X-A":"1"},"body":"{}","run_at_ms":5}"#,
        )
        .unwrap();
        assert_eq!(r.method, Method::Put);
        assert!(serde_json::from_str::<ScheduleRequest>(
            r#"{"url":"https://a.example.com/","callback":"x"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<ScheduleRequest>(
            r#"{"url":"https://a.example.com/","method":"TRACE"}"#
        )
        .is_err());
    }

    #[test]
    fn rejects_unsafe_destinations() {
        assert_eq!(
            invalid(req("http://example.com/")),
            ValidationError::Destination(DestinationError::NotHttps)
        );
        assert_eq!(invalid(req("https://10.0.0.1/")).field(), "url");
    }

    #[test]
    fn checks_headers() {
        let mut r = ok();
        r.headers.insert("Host".into(), "evil.example.com".into());
        assert!(matches!(invalid(r), ValidationError::Header(_)));

        let mut r = ok();
        r.headers.insert("X-Token".into(), "a".into());
        r.headers.insert("x-token".into(), "b".into());
        assert_eq!(
            invalid(r),
            ValidationError::DuplicateHeader("x-token".into())
        );

        let mut r = ok();
        r.headers = (0..=MAX_HEADERS)
            .map(|i| (format!("X-{i}"), "v".into()))
            .collect();
        assert_eq!(invalid(r), ValidationError::TooManyHeaders);

        let mut r = ok();
        r.headers
            .insert("X-Big".into(), "v".repeat(MAX_HEADER_BYTES));
        assert_eq!(invalid(r), ValidationError::HeadersTooLarge);
    }

    #[test]
    fn checks_body() {
        let mut r = ok();
        r.body = Some("x".repeat(MAX_BODY_BYTES));
        assert!(r.validate(NOW).is_ok());

        let mut r = ok();
        r.body = Some("x".repeat(MAX_BODY_BYTES + 1));
        assert_eq!(invalid(r), ValidationError::BodyTooLarge);

        let mut r = ok();
        r.method = Method::Get;
        r.body = Some(String::new());
        assert_eq!(invalid(r), ValidationError::BodyNotAllowed);
    }

    #[test]
    fn checks_run_at() {
        let at = |t| ScheduleRequest {
            run_at_ms: Some(t),
            ..ok()
        };
        assert_eq!(at(NOW - 1000).validate(NOW).unwrap().run_at_ms, NOW);
        assert_eq!(at(NOW + 5000).validate(NOW).unwrap().run_at_ms, NOW + 5000);
        assert!(at(NOW + 7 * DAY_MS).validate(NOW).is_ok());
        assert_eq!(
            invalid(at(NOW + 7 * DAY_MS + 1)),
            ValidationError::RunAtTooFar
        );
        assert_eq!(invalid(at(-1)), ValidationError::RunAtNegative);
    }

    #[test]
    fn checks_max_attempts_and_idempotency_key() {
        for n in [0, MAX_ATTEMPTS + 1] {
            let r = ScheduleRequest {
                max_attempts: Some(n),
                ..ok()
            };
            assert_eq!(invalid(r), ValidationError::MaxAttempts);
        }
        for key in [
            "",
            "has space",
            "ünicode",
            &"k".repeat(MAX_IDEMPOTENCY_KEY_BYTES + 1),
        ] {
            let r = ScheduleRequest {
                idempotency_key: Some(key.into()),
                ..ok()
            };
            assert_eq!(invalid(r), ValidationError::IdempotencyKey, "{key:?}");
        }
    }

    #[test]
    fn fingerprint_ignores_cosmetics_but_not_content() {
        let fp = |r: ScheduleRequest, now| r.validate(now).unwrap().fingerprint;
        let mut a = req("https://HOOKS.example.com/run");
        a.headers.insert("X-Token".into(), "1".into());
        let mut b = ok();
        b.headers.insert("x-token".into(), "1".into());
        assert_eq!(fp(a.clone(), NOW), fp(b, NOW + 60_000));

        let mut c = a.clone();
        c.body = Some("{}".into());
        assert_ne!(fp(a.clone(), NOW), fp(c, NOW));
        let d = ScheduleRequest {
            method: Method::Put,
            ..a.clone()
        };
        assert_ne!(fp(a, NOW), fp(d, NOW));
    }
}
