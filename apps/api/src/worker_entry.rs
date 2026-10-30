use worker::{event, Context, Env, Request, Response, Result, Router};

#[event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    Router::new()
        .get("/health", |_, _| Response::from_json(&crate::health_body()))
        .run(req, env)
        .await
}
