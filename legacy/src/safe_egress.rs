//! One bounded transport for alpha delivery and destination ownership checks.
use crate::{
    core::Outcome,
    destinations::{Target, BODY_BYTES, BODY_CHUNKS, HEADER_BYTES, TIMEOUT_MS},
};
use futures_util::{
    future::{select, Either},
    pin_mut, StreamExt,
};
use std::collections::BTreeMap;
use worker::*;

pub(crate) struct BoundedResponse {
    pub status: u16,
    pub body: Vec<u8>,
}
pub(crate) struct Failure {
    #[cfg_attr(feature = "destination-tests", allow(dead_code))]
    pub outcome: Outcome,
    pub category: &'static str,
}
fn rejected(category: &'static str) -> Failure {
    Failure {
        outcome: Outcome::Http(400),
        category,
    }
}
pub(crate) async fn fetch(
    target: Target,
    body: String,
    content_type: &str,
    headers: BTreeMap<String, String>,
) -> std::result::Result<BoundedResponse, Failure> {
    if body.len() > BODY_BYTES {
        return Err(rejected("request_body_too_large"));
    }
    let controller = AbortController::default();
    let signal = controller.signal();
    let action = async {
        let h = Headers::new();
        h.set("Content-Type", content_type)?;
        for (k, v) in &headers {
            h.set(k, v)?;
        }
        let mut init = RequestInit::new();
        init.with_method(Method::Post)
            .with_redirect(RequestRedirect::Manual)
            .with_headers(h)
            .with_body(Some(body.into()));
        let request = Request::new_with_init(target.url(), &init)?;
        let mut r = Fetch::Request(request).send_with_signal(&signal).await?;
        let status = r.status_code();
        if (300..400).contains(&status) {
            return Ok::<_, worker::Error>(Err(rejected("redirect_rejected")));
        }
        let count: usize = r.headers().entries().map(|(k, v)| k.len() + v.len()).sum();
        if count > HEADER_BYTES {
            return Ok(Err(rejected("response_headers_too_large")));
        }
        let mut bytes = Vec::new();
        let mut chunks = 0;
        if let Ok(mut stream) = r.stream() {
            while let Some(part) = stream.next().await {
                let part = part?;
                chunks += 1;
                if bytes.len().saturating_add(part.len()) > BODY_BYTES || chunks > BODY_CHUNKS {
                    return Ok(Err(rejected("response_body_too_large")));
                }
                bytes.extend_from_slice(&part);
            }
        }
        Ok(Ok(BoundedResponse {
            status,
            body: bytes,
        }))
    };
    // Deadline covers headers AND the complete bounded body. Abort on every exit.
    let deadline = Delay::from(std::time::Duration::from_millis(TIMEOUT_MS));
    pin_mut!(action, deadline);
    let result = match select(action, deadline).await {
        Either::Left((Ok(result), _)) => result,
        Either::Left((Err(_), _)) => Err(Failure {
            outcome: Outcome::Timeout,
            category: "network_uncertain",
        }),
        Either::Right(_) => Err(Failure {
            outcome: Outcome::Timeout,
            category: "timeout_uncertain",
        }),
    };
    controller.abort();
    result
}
