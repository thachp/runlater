//! One project's task ledger: the authoritative store for its trial, tasks and attempts.
//!
//! Each project lives in its own Durable Object with its own SQLite database, so nothing
//! here filters by project. Every method is synchronous; in a Durable Object a run of
//! storage calls with no `await` between them commits atomically.
//!
//! The task rows double as the outbox: a due task stays eligible for publication to the
//! queue until a consumer claims it, so a lost queue message is simply republished.

use crate::db::{Db, DbError, Param};
use runlater_core::limits::{
    DEFAULT_MAX_ATTEMPTS, MAX_RETAINED_TASKS, RETENTION_MS, TRIAL_ATTEMPTS, TRIAL_DURATION_MS,
};
use runlater_core::{
    Attempt, CancelError, ClaimError, Method, Outcome, RedriveError, ScheduleRequest, Status, Task,
    ValidationError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A published task that has not been claimed after this long is published again.
pub const REPUBLISH_MS: i64 = 60_000;
/// Most tasks published per alarm; the alarm re-arms immediately if more are due.
pub const PUBLISH_BATCH: usize = 100;
pub const DEFAULT_PAGE: usize = 20;
pub const MAX_PAGE: usize = 100;
/// Durable Object SQL bindings pass through JavaScript numbers.
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS project (
        id TEXT PRIMARY KEY,
        created_ms INTEGER NOT NULL,
        expires_ms INTEGER NOT NULL,
        attempt_budget INTEGER NOT NULL,
        attempts_used INTEGER NOT NULL,
        signing_secret TEXT NOT NULL
    )",
    "CREATE TABLE IF NOT EXISTS tasks (
        seq INTEGER PRIMARY KEY,
        id TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL,
        due_ms INTEGER NOT NULL,
        max_attempts INTEGER NOT NULL,
        run_attempts INTEGER NOT NULL,
        total_attempts INTEGER NOT NULL,
        generation INTEGER NOT NULL,
        fence INTEGER NOT NULL,
        lease_until_ms INTEGER,
        cancel_requested INTEGER NOT NULL,
        terminal_ms INTEGER,
        published_ms INTEGER,
        method TEXT NOT NULL,
        url TEXT NOT NULL,
        headers TEXT NOT NULL,
        body TEXT,
        run_at_ms INTEGER NOT NULL,
        idempotency_key TEXT UNIQUE,
        fingerprint TEXT NOT NULL,
        created_ms INTEGER NOT NULL,
        updated_ms INTEGER NOT NULL
    )",
    "CREATE INDEX IF NOT EXISTS tasks_by_status_due ON tasks (status, due_ms)",
    "CREATE TABLE IF NOT EXISTS attempts (
        task_id TEXT NOT NULL,
        number INTEGER NOT NULL,
        started_ms INTEGER NOT NULL,
        finished_ms INTEGER,
        outcome TEXT,
        http_status INTEGER,
        PRIMARY KEY (task_id, number)
    )",
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)",
];

/// Changes to ledgers created by an earlier [`SCHEMA`]. Each entry runs once per ledger, in
/// order; how many have run is kept in `meta`. Append only.
const MIGRATIONS: &[&[&str]] = &[
    // 1: callbacks.
    &[
        "ALTER TABLE tasks ADD COLUMN callback_url TEXT",
        "ALTER TABLE tasks ADD COLUMN callback_task_id TEXT",
        "ALTER TABLE tasks ADD COLUMN callback_for TEXT",
    ],
];

// ---------------------------------------------------------------------------------------
// Errors

#[derive(Debug, PartialEq, Eq)]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
    pub field: Option<&'static str>,
}

impl ApiError {
    fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
            field: None,
        }
    }

    pub fn invalid(e: ValidationError) -> Self {
        Self {
            field: Some(e.field()),
            ..Self::new(400, "invalid_request", e.to_string())
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(400, "invalid_request", message)
    }

    pub fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(404, code, message)
    }

    pub fn body(&self) -> serde_json::Value {
        let mut e = serde_json::json!({ "code": self.code, "message": self.message });
        if let Some(field) = self.field {
            e["field"] = field.into();
        }
        serde_json::json!({ "error": e })
    }
}

impl From<DbError> for ApiError {
    fn from(e: DbError) -> Self {
        Self::new(500, "internal_error", e.to_string())
    }
}

fn no_project() -> ApiError {
    ApiError::not_found("project_not_found", "create the project first")
}

fn no_task() -> ApiError {
    ApiError::not_found("task_not_found", "no such task in this project")
}

// ---------------------------------------------------------------------------------------
// Views returned to callers

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectView {
    pub id: String,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub attempt_budget: i64,
    pub attempts_used: i64,
    pub attempts_remaining: i64,
    /// Receivers verify `RunLater-Signature` with this.
    pub signing_secret: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct AttemptView {
    pub number: i64,
    pub started_ms: i64,
    pub finished_ms: Option<i64>,
    pub outcome: Option<String>,
    pub http_status: Option<i64>,
}

/// Header values and the body are never echoed back: they may hold credentials.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TaskView {
    pub id: String,
    pub status: Status,
    pub method: Method,
    pub url: String,
    pub header_names: Vec<String>,
    pub body_bytes: usize,
    pub run_at_ms: i64,
    /// When the next attempt is due, while the task is waiting.
    pub next_attempt_ms: Option<i64>,
    pub max_attempts: u32,
    pub attempt_count: u32,
    pub idempotency_key: Option<String>,
    /// Where this task's final state is POSTed once it finishes.
    pub callback_url: Option<String>,
    /// The callback task for the most recent time this task finished.
    pub callback_task_id: Option<String>,
    /// Set on a callback task: the task it reports on.
    pub callback_for: Option<String>,
    pub created_ms: i64,
    pub updated_ms: i64,
    pub finished_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempts: Option<Vec<AttemptView>>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct TaskPage {
    pub tasks: Vec<TaskView>,
    pub next_cursor: Option<String>,
}

/// Queue message: which task to try, and for which schedule of it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dispatch {
    pub project_id: String,
    pub task_id: String,
    pub generation: u64,
}

/// Everything the consumer needs to make one attempt.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Delivery {
    pub task_id: String,
    pub attempt: u32,
    pub fence: u64,
    pub method: Method,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<String>,
    pub signing_secret: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Claimed {
    Deliver(Box<Delivery>),
    /// Nothing to do for this message; acknowledge it.
    Skip(&'static str),
}

// ---------------------------------------------------------------------------------------
// Rows

#[derive(Deserialize)]
struct ProjectRow {
    id: String,
    created_ms: i64,
    expires_ms: i64,
    attempt_budget: i64,
    attempts_used: i64,
    signing_secret: String,
}

impl ProjectRow {
    fn view(self) -> ProjectView {
        ProjectView {
            attempts_remaining: (self.attempt_budget - self.attempts_used).max(0),
            id: self.id,
            created_ms: self.created_ms,
            expires_ms: self.expires_ms,
            attempt_budget: self.attempt_budget,
            attempts_used: self.attempts_used,
            signing_secret: self.signing_secret,
        }
    }

    fn can_attempt(&self, now: i64) -> bool {
        now < self.expires_ms && self.attempts_used < self.attempt_budget
    }
}

#[derive(Deserialize)]
struct TaskRow {
    seq: i64,
    id: String,
    status: String,
    due_ms: i64,
    max_attempts: u32,
    run_attempts: u32,
    total_attempts: u32,
    generation: u64,
    fence: u64,
    lease_until_ms: Option<i64>,
    cancel_requested: i64,
    terminal_ms: Option<i64>,
    method: String,
    url: String,
    headers: String,
    body: Option<String>,
    run_at_ms: i64,
    idempotency_key: Option<String>,
    callback_url: Option<String>,
    callback_task_id: Option<String>,
    callback_for: Option<String>,
    created_ms: i64,
    updated_ms: i64,
}

#[derive(Deserialize)]
struct AttemptRow {
    number: i64,
    started_ms: i64,
    finished_ms: Option<i64>,
    outcome: Option<String>,
    http_status: Option<i64>,
}

fn parse<T: serde::de::DeserializeOwned>(s: &str) -> Result<T, DbError> {
    serde_json::from_value(serde_json::Value::String(s.into()))
        .map_err(|_| DbError(format!("unexpected stored value {s:?}")))
}

fn text<T: Serialize>(v: &T) -> String {
    match serde_json::to_value(v) {
        Ok(serde_json::Value::String(s)) => s,
        _ => unreachable!("enums serialize as strings"),
    }
}

impl TaskRow {
    fn task(&self) -> Result<Task, DbError> {
        Ok(Task {
            status: parse(&self.status)?,
            due_ms: self.due_ms,
            max_attempts: self.max_attempts,
            run_attempts: self.run_attempts,
            total_attempts: self.total_attempts,
            generation: self.generation,
            fence: self.fence,
            lease_until_ms: self.lease_until_ms,
            cancel_requested: self.cancel_requested != 0,
            terminal_ms: self.terminal_ms,
        })
    }

    fn headers(&self) -> Result<Vec<(String, String)>, DbError> {
        serde_json::from_str(&self.headers).map_err(|e| DbError(e.to_string()))
    }

    fn view(&self, attempts: Option<Vec<AttemptView>>) -> Result<TaskView, DbError> {
        let task = self.task()?;
        Ok(TaskView {
            id: self.id.clone(),
            status: task.status,
            method: parse(&self.method)?,
            url: self.url.clone(),
            header_names: self.headers()?.into_iter().map(|(k, _)| k).collect(),
            body_bytes: self.body.as_ref().map_or(0, String::len),
            run_at_ms: self.run_at_ms,
            next_attempt_ms: matches!(task.status, Status::Scheduled | Status::Retrying)
                .then_some(task.due_ms),
            max_attempts: task.max_attempts,
            attempt_count: task.total_attempts,
            idempotency_key: self.idempotency_key.clone(),
            callback_url: self.callback_url.clone(),
            callback_task_id: self.callback_task_id.clone(),
            callback_for: self.callback_for.clone(),
            created_ms: self.created_ms,
            updated_ms: self.updated_ms,
            finished_ms: task.terminal_ms,
            attempts,
        })
    }
}

const TASK_COLUMNS: &str = "seq, id, status, due_ms, max_attempts, run_attempts, \
    total_attempts, generation, fence, lease_until_ms, cancel_requested, terminal_ms, \
    method, url, headers, body, run_at_ms, idempotency_key, callback_url, callback_task_id, \
    callback_for, created_ms, updated_ms";

/// A row to insert into `tasks`.
struct NewTask<'s> {
    id: &'s str,
    task: Task,
    method: Method,
    url: &'s str,
    headers: &'s [(String, String)],
    body: Option<String>,
    run_at_ms: i64,
    idempotency_key: Option<String>,
    fingerprint: &'s str,
    callback_url: Option<&'s str>,
    callback_for: Option<&'s str>,
}

/// Callback task ids are derived, so queueing the same callback twice is harmless. A task's
/// generation differs every time it finishes (only a redrive can follow a finish, and it
/// moves the generation on), so each finish gets its own callback.
fn callback_id(task_id: &str, generation: u64) -> String {
    let digest = Sha256::digest(format!("callback/{task_id}/{generation}"));
    format!("task_{}", hex::encode(&digest[..10]))
}

// ---------------------------------------------------------------------------------------

pub struct Ledger<'a, D: Db> {
    db: &'a D,
}

impl<'a, D: Db> Ledger<'a, D> {
    pub fn open(db: &'a D) -> Result<Self, DbError> {
        for statement in SCHEMA {
            db.exec(statement, vec![])?;
        }
        let applied: Vec<MetaRow> =
            db.query("SELECT value FROM meta WHERE key = 'schema'", vec![])?;
        let applied = applied.first().map_or(0, |m| m.value as usize);
        if applied < MIGRATIONS.len() {
            for statement in MIGRATIONS[applied..].iter().copied().flatten() {
                db.exec(statement, vec![])?;
            }
            db.exec(
                "INSERT INTO meta (key, value) VALUES ('schema', ?) \
                 ON CONFLICT (key) DO UPDATE SET value = excluded.value",
                vec![(MIGRATIONS.len() as i64).into()],
            )?;
        }
        Ok(Self { db })
    }

    // -- project -------------------------------------------------------------------------

    fn project_row(&self) -> Result<Option<ProjectRow>, DbError> {
        Ok(self
            .db
            .query(
                "SELECT id, created_ms, expires_ms, attempt_budget, attempts_used, signing_secret \
                 FROM project LIMIT 1",
                vec![],
            )?
            .pop())
    }

    pub fn project(&self) -> Result<ProjectView, ApiError> {
        Ok(self.project_row()?.ok_or_else(no_project)?.view())
    }

    /// Creates the project with a fresh trial, or returns the existing one unchanged.
    /// `signing_secret` is only used on creation.
    pub fn create_project(
        &self,
        project_id: &str,
        signing_secret: &str,
        now: i64,
    ) -> Result<(ProjectView, bool), ApiError> {
        if let Some(existing) = self.project_row()? {
            return Ok((existing.view(), false));
        }
        self.db.exec(
            "INSERT INTO project (id, created_ms, expires_ms, attempt_budget, attempts_used, \
             signing_secret) VALUES (?, ?, ?, ?, 0, ?)",
            vec![
                project_id.into(),
                now.into(),
                (now + TRIAL_DURATION_MS).into(),
                TRIAL_ATTEMPTS.into(),
                signing_secret.into(),
            ],
        )?;
        Ok((self.project()?, true))
    }

    /// Admission for new work: the trial must be live, every waiting task (and the callback
    /// it will send) must still be able to get at least one attempt, and new rows must fit
    /// under the retained-task cap. `rows` and `attempts` are what the new work needs.
    fn admit(
        &self,
        project: &ProjectRow,
        rows: i64,
        attempts: i64,
        now: i64,
    ) -> Result<(), ApiError> {
        if now >= project.expires_ms {
            return Err(ApiError::new(
                403,
                "trial_expired",
                "this project's trial has ended",
            ));
        }
        let counts: Vec<Counts> = self.db.query(
            "SELECT COUNT(*) AS total, \
             COALESCE(SUM(CASE WHEN status IN ('scheduled', 'retrying', 'delivering') \
             THEN 1 + (callback_url IS NOT NULL) ELSE 0 END), 0) AS waiting \
             FROM tasks",
            vec![],
        )?;
        let (total, waiting) = counts.first().map_or((0, 0), |c| (c.total, c.waiting));
        if rows > 0 && total + rows > MAX_RETAINED_TASKS {
            return Err(ApiError::new(
                429,
                "task_limit",
                format!(
                    "this project already holds {MAX_RETAINED_TASKS} tasks; \
                     finished tasks are removed 30 days after they finish"
                ),
            ));
        }
        if waiting + attempts > project.attempt_budget - project.attempts_used {
            return Err(ApiError::new(
                402,
                "budget_exhausted",
                "not enough delivery attempts left in this project's trial",
            ));
        }
        Ok(())
    }

    // -- tasks: commands ------------------------------------------------------------------

    /// Returns the task and whether it was created (false for an idempotent replay).
    pub fn schedule(
        &self,
        request: ScheduleRequest,
        task_id: &str,
        now: i64,
    ) -> Result<(TaskView, bool), ApiError> {
        let project = self.project_row()?.ok_or_else(no_project)?;
        let when_field = if request.delay.is_some() {
            "delay"
        } else {
            "run_at_ms"
        };
        let spec = request.validate(now).map_err(ApiError::invalid)?;

        if let Some(key) = &spec.idempotency_key {
            let existing: Vec<KeyRow> = self.db.query(
                "SELECT id, fingerprint FROM tasks WHERE idempotency_key = ?",
                vec![key.as_str().into()],
            )?;
            if let Some(existing) = existing.first() {
                if existing.fingerprint != spec.fingerprint {
                    return Err(ApiError::new(
                        409,
                        "idempotency_conflict",
                        "idempotency_key was already used for a different request",
                    ));
                }
                return Ok((self.task(&existing.id)?, false));
            }
        }

        let needs = 1 + i64::from(spec.callback.is_some());
        self.admit(&project, needs, needs, now)?;
        if spec.run_at_ms >= project.expires_ms {
            return Err(ApiError {
                field: Some(when_field),
                ..ApiError::bad_request(format!("{when_field} is after this project's trial ends"))
            });
        }

        self.insert(
            NewTask {
                id: task_id,
                task: Task::new(spec.run_at_ms, spec.max_attempts),
                method: spec.method,
                url: spec.destination.as_str(),
                headers: &spec.headers,
                body: spec.body,
                run_at_ms: spec.run_at_ms,
                idempotency_key: spec.idempotency_key,
                fingerprint: &spec.fingerprint,
                callback_url: spec.callback.as_ref().map(|c| c.as_str()),
                callback_for: None,
            },
            now,
        )?;
        Ok((self.task(task_id)?, true))
    }

    pub fn cancel(&self, task_id: &str, now: i64) -> Result<TaskView, ApiError> {
        let row = self.task_row(task_id)?.ok_or_else(no_task)?;
        let mut task = row.task()?;
        match task.cancel(now) {
            Ok(_) => {}
            Err(CancelError::AlreadyFinished(s)) => {
                return Err(ApiError::new(
                    409,
                    "task_finished",
                    format!("task already {}", text(&s)),
                ))
            }
        }
        self.save_row(&row, &task, now)?;
        self.task(task_id)
    }

    /// Gives a failed task a fresh set of attempts, starting now.
    pub fn redrive(&self, task_id: &str, now: i64) -> Result<TaskView, ApiError> {
        let project = self.project_row()?.ok_or_else(no_project)?;
        let row = self.task_row(task_id)?.ok_or_else(no_task)?;
        let mut task = row.task()?;
        if let Err(RedriveError::NotFailed(s)) = task.redrive(now) {
            return Err(ApiError::new(
                409,
                "task_not_failed",
                format!(
                    "only failed tasks can be redriven; this one is {}",
                    text(&s)
                ),
            ));
        }
        let callbacks = i64::from(row.callback_url.is_some());
        self.admit(&project, callbacks, 1 + callbacks, now)?;
        self.save_row(&row, &task, now)?;
        self.task(task_id)
    }

    // -- tasks: queries -------------------------------------------------------------------

    fn task_row(&self, task_id: &str) -> Result<Option<TaskRow>, DbError> {
        Ok(self
            .db
            .query(
                &format!("SELECT {TASK_COLUMNS} FROM tasks WHERE id = ?"),
                vec![task_id.into()],
            )?
            .pop())
    }

    /// One task with its attempt history.
    pub fn task(&self, task_id: &str) -> Result<TaskView, ApiError> {
        let row = self.task_row(task_id)?.ok_or_else(no_task)?;
        Ok(self.full_view(&row)?)
    }

    fn full_view(&self, row: &TaskRow) -> Result<TaskView, DbError> {
        let attempts: Vec<AttemptRow> = self.db.query(
            "SELECT number, started_ms, finished_ms, outcome, http_status FROM attempts \
             WHERE task_id = ? ORDER BY number",
            vec![row.id.as_str().into()],
        )?;
        let attempts = attempts
            .into_iter()
            .map(|a| AttemptView {
                number: a.number,
                started_ms: a.started_ms,
                finished_ms: a.finished_ms,
                outcome: a.outcome,
                http_status: a.http_status,
            })
            .collect();
        row.view(Some(attempts))
    }

    /// Newest first. `cursor` is the `next_cursor` of the previous page.
    pub fn list(
        &self,
        status: Option<Status>,
        cursor: Option<&str>,
        limit: Option<usize>,
    ) -> Result<TaskPage, ApiError> {
        self.project_row()?.ok_or_else(no_project)?;
        let limit = limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
        let before = match cursor {
            None => MAX_SAFE_INTEGER,
            Some(c) => c
                .parse::<i64>()
                .map_err(|_| ApiError::bad_request("cursor is not valid"))?,
        };
        let mut sql = format!("SELECT {TASK_COLUMNS} FROM tasks WHERE seq < ?");
        let mut params: Vec<Param> = vec![before.into()];
        if let Some(status) = status {
            sql.push_str(" AND status = ?");
            params.push(text(&status).into());
        }
        sql.push_str(" ORDER BY seq DESC LIMIT ?");
        params.push((limit as i64 + 1).into());

        let mut rows: Vec<TaskRow> = self.db.query(&sql, params)?;
        let next_cursor = if rows.len() > limit {
            rows.truncate(limit);
            rows.last().map(|r| r.seq.to_string())
        } else {
            None
        };
        let tasks = rows
            .iter()
            .map(|r| r.view(None))
            .collect::<Result<_, _>>()?;
        Ok(TaskPage { tasks, next_cursor })
    }

    // -- delivery -------------------------------------------------------------------------

    /// Due tasks to put on the queue. Marks them published so the next alarm does not
    /// republish them until [`REPUBLISH_MS`] has passed without a claim.
    pub fn publish_due(&self, project_id: &str, now: i64) -> Result<Vec<Dispatch>, DbError> {
        let due: Vec<DueRow> = self.db.query(
            "SELECT id, generation FROM tasks \
             WHERE status IN ('scheduled', 'retrying') AND due_ms <= ? \
             AND (published_ms IS NULL OR published_ms <= ?) \
             ORDER BY due_ms LIMIT ?",
            vec![
                now.into(),
                (now - REPUBLISH_MS).into(),
                (PUBLISH_BATCH as i64).into(),
            ],
        )?;
        for d in &due {
            self.db.exec(
                "UPDATE tasks SET published_ms = ? WHERE id = ?",
                vec![now.into(), d.id.as_str().into()],
            )?;
        }
        Ok(due
            .into_iter()
            .map(|d| Dispatch {
                project_id: project_id.into(),
                task_id: d.id,
                generation: d.generation,
            })
            .collect())
    }

    /// Starts an attempt for a queue message, charging one attempt to the trial.
    pub fn claim(&self, task_id: &str, generation: u64, now: i64) -> Result<Claimed, ApiError> {
        let Some(project) = self.project_row()? else {
            return Ok(Claimed::Skip("project_missing"));
        };
        let Some(row) = self.task_row(task_id)? else {
            return Ok(Claimed::Skip("task_missing"));
        };
        let mut task = row.task()?;

        if !project.can_attempt(now) {
            if task.generation == generation && task.is_due(now) && task.abandon(now) {
                self.save_row(&row, &task, now)?;
                return Ok(Claimed::Skip("budget_exhausted"));
            }
            return Ok(Claimed::Skip("stale"));
        }

        let attempt: Attempt = match task.claim(generation, now) {
            Ok(a) => a,
            Err(ClaimError::Stale) => return Ok(Claimed::Skip("stale")),
            Err(ClaimError::NotDue { .. }) => return Ok(Claimed::Skip("not_due")),
        };
        self.db.exec(
            "UPDATE project SET attempts_used = attempts_used + 1",
            vec![],
        )?;
        self.db.exec(
            "INSERT INTO attempts (task_id, number, started_ms) VALUES (?, ?, ?)",
            vec![task_id.into(), attempt.number.into(), now.into()],
        )?;
        self.save_row(&row, &task, now)?;
        Ok(Claimed::Deliver(Box::new(Delivery {
            task_id: task_id.into(),
            attempt: attempt.number,
            fence: attempt.fence,
            method: parse(&row.method)?,
            url: row.url.clone(),
            headers: row.headers()?,
            body: row.body.clone(),
            signing_secret: project.signing_secret,
        })))
    }

    /// Records an attempt's result. `None` if the attempt no longer holds the task.
    pub fn finish(
        &self,
        task_id: &str,
        fence: u64,
        outcome: Outcome,
        now: i64,
        jitter: f64,
    ) -> Result<Option<Status>, DbError> {
        let Some(row) = self.task_row(task_id)? else {
            return Ok(None);
        };
        let mut task = row.task()?;
        let Ok(status) = task.finish(fence, outcome, now, jitter) else {
            return Ok(None);
        };
        self.record_outcome(task_id, fence, &outcome, now)?;
        self.save_row(&row, &task, now)?;
        Ok(Some(status))
    }

    /// Settles attempts whose consumer vanished. Returns how many were recovered.
    pub fn recover(&self, now: i64, mut jitter: impl FnMut() -> f64) -> Result<usize, DbError> {
        let rows: Vec<TaskRow> = self.db.query(
            &format!(
                "SELECT {TASK_COLUMNS} FROM tasks \
                 WHERE status = 'delivering' AND lease_until_ms <= ?"
            ),
            vec![now.into()],
        )?;
        for row in &rows {
            let mut task = row.task()?;
            let fence = task.fence;
            if task.expire_lease(now, jitter()).is_some() {
                self.record_outcome(&row.id, fence, &Outcome::LeaseExpired, now)?;
                self.save_row(row, &task, now)?;
            }
        }
        Ok(rows.len())
    }

    /// Deletes tasks whose retention period has passed. Returns how many.
    pub fn purge(&self, now: i64) -> Result<usize, DbError> {
        let cutoff = now - RETENTION_MS;
        let expired: Vec<IdRow> = self.db.query(
            "SELECT id FROM tasks WHERE terminal_ms IS NOT NULL AND terminal_ms <= ?",
            vec![cutoff.into()],
        )?;
        for row in &expired {
            self.db.exec(
                "DELETE FROM attempts WHERE task_id = ?",
                vec![row.id.as_str().into()],
            )?;
            self.db.exec(
                "DELETE FROM tasks WHERE id = ?",
                vec![row.id.as_str().into()],
            )?;
        }
        Ok(expired.len())
    }

    /// When the alarm should next run, if there is anything left to do.
    pub fn next_wake(&self) -> Result<Option<i64>, DbError> {
        let rows: Vec<Wake> = self.db.query(
            &format!(
                "SELECT MIN(t) AS t FROM ( \
                 SELECT CASE WHEN published_ms IS NOT NULL AND published_ms + {REPUBLISH_MS} > due_ms \
                        THEN published_ms + {REPUBLISH_MS} ELSE due_ms END AS t \
                   FROM tasks WHERE status IN ('scheduled', 'retrying') \
                 UNION ALL SELECT lease_until_ms FROM tasks WHERE status = 'delivering' \
                 UNION ALL SELECT terminal_ms + {RETENTION_MS} FROM tasks WHERE terminal_ms IS NOT NULL)"
            ),
            vec![],
        )?;
        Ok(rows.first().and_then(|w| w.t))
    }

    // -- helpers --------------------------------------------------------------------------

    fn insert(&self, new: NewTask<'_>, now: i64) -> Result<(), DbError> {
        let NewTask { id, task, .. } = &new;
        let headers = serde_json::to_string(new.headers).map_err(|e| DbError(e.to_string()))?;
        // OR IGNORE only matters for derived callback ids; scheduled ids are fresh.
        self.db.exec(
            "INSERT OR IGNORE INTO tasks (id, status, due_ms, max_attempts, run_attempts, \
             total_attempts, generation, fence, lease_until_ms, cancel_requested, terminal_ms, \
             published_ms, method, url, headers, body, run_at_ms, idempotency_key, fingerprint, \
             callback_url, callback_for, created_ms, updated_ms) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            vec![
                (*id).into(),
                text(&task.status).into(),
                task.due_ms.into(),
                task.max_attempts.into(),
                task.run_attempts.into(),
                task.total_attempts.into(),
                task.generation.into(),
                task.fence.into(),
                task.lease_until_ms.into(),
                task.cancel_requested.into(),
                task.terminal_ms.into(),
                new.method.as_str().into(),
                new.url.into(),
                headers.into(),
                new.body.into(),
                new.run_at_ms.into(),
                new.idempotency_key.into(),
                new.fingerprint.into(),
                new.callback_url.into(),
                new.callback_for.into(),
                now.into(),
                now.into(),
            ],
        )
    }

    /// Saves a change to a task loaded as `row`; if the change finished the task, queues
    /// its callback in the same transaction.
    fn save_row(&self, row: &TaskRow, task: &Task, now: i64) -> Result<(), DbError> {
        self.save(&row.id, task, now)?;
        let was_finished = parse::<Status>(&row.status)?.is_terminal();
        match &row.callback_url {
            Some(url) if task.status.is_terminal() && !was_finished => {
                self.queue_callback(&row.id, url, task.generation, now)
            }
            _ => Ok(()),
        }
    }

    /// A callback is an ordinary task: signed, retried and visible through get_task. It is
    /// sent even if it outlives the trial's budget reservation, which admission made for it.
    fn queue_callback(
        &self,
        task_id: &str,
        url: &str,
        generation: u64,
        now: i64,
    ) -> Result<(), DbError> {
        let id = callback_id(task_id, generation);
        self.db.exec(
            "UPDATE tasks SET callback_task_id = ? WHERE id = ?",
            vec![id.as_str().into(), task_id.into()],
        )?;
        let row = self
            .task_row(task_id)?
            .ok_or_else(|| DbError(format!("task {task_id} vanished")))?;
        let report = serde_json::json!({ "event": "task.finished", "task": self.full_view(&row)? });
        self.insert(
            NewTask {
                id: &id,
                task: Task::new(now, DEFAULT_MAX_ATTEMPTS),
                method: Method::Post,
                url,
                headers: &[("Content-Type".into(), "application/json".into())],
                body: Some(report.to_string()),
                run_at_ms: now,
                idempotency_key: None,
                fingerprint: "callback",
                callback_url: None,
                callback_for: Some(task_id),
            },
            now,
        )
    }

    fn save(&self, task_id: &str, task: &Task, now: i64) -> Result<(), DbError> {
        // A new generation is a new schedule: it must be published again. Succeeded and
        // canceled tasks can never be sent again, so their body is dropped; failed tasks
        // keep it for redrive.
        self.db.exec(
            "UPDATE tasks SET status = ?, due_ms = ?, max_attempts = ?, run_attempts = ?, \
             total_attempts = ?, lease_until_ms = ?, cancel_requested = ?, terminal_ms = ?, \
             body = CASE WHEN ? IN ('succeeded', 'canceled') THEN NULL ELSE body END, \
             published_ms = CASE WHEN generation = ? THEN published_ms ELSE NULL END, \
             generation = ?, fence = ?, updated_ms = ? WHERE id = ?",
            vec![
                text(&task.status).into(),
                task.due_ms.into(),
                task.max_attempts.into(),
                task.run_attempts.into(),
                task.total_attempts.into(),
                task.lease_until_ms.into(),
                task.cancel_requested.into(),
                task.terminal_ms.into(),
                text(&task.status).into(),
                task.generation.into(),
                task.generation.into(),
                task.fence.into(),
                now.into(),
                task_id.into(),
            ],
        )
    }

    /// Attempt numbers and fences advance together, so the fence names the attempt row.
    fn record_outcome(
        &self,
        task_id: &str,
        fence: u64,
        outcome: &Outcome,
        now: i64,
    ) -> Result<(), DbError> {
        let http_status = match outcome {
            Outcome::Http { status, .. } => Some(i64::from(*status)),
            _ => None,
        };
        self.db.exec(
            "UPDATE attempts SET finished_ms = ?, outcome = ?, http_status = ? \
             WHERE task_id = ? AND number = ?",
            vec![
                now.into(),
                outcome.label().into(),
                http_status.into(),
                task_id.into(),
                fence.into(),
            ],
        )
    }
}

#[derive(Deserialize)]
struct MetaRow {
    value: i64,
}

#[derive(Deserialize)]
struct Counts {
    total: i64,
    waiting: i64,
}

#[derive(Deserialize)]
struct KeyRow {
    id: String,
    fingerprint: String,
}

#[derive(Deserialize)]
struct DueRow {
    id: String,
    generation: u64,
}

#[derive(Deserialize)]
struct IdRow {
    id: String,
}

#[derive(Deserialize)]
struct Wake {
    t: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::sqlite::Memory;
    use runlater_core::limits::LEASE_MS;

    const T0: i64 = 1_767_225_600_000;
    const P: &str = "proj_1";

    fn http(status: u16) -> Outcome {
        Outcome::Http {
            status,
            retry_after_ms: None,
        }
    }

    fn req(url: &str) -> ScheduleRequest {
        ScheduleRequest {
            url: url.into(),
            ..Default::default()
        }
    }

    fn setup(db: &Memory) -> Ledger<'_, Memory> {
        let l = Ledger::open(db).unwrap();
        l.create_project(P, "secret", T0).unwrap();
        l
    }

    fn deliver(l: &Ledger<'_, Memory>, d: &Dispatch, now: i64) -> Delivery {
        match l.claim(&d.task_id, d.generation, now).unwrap() {
            Claimed::Deliver(d) => *d,
            other => panic!("expected delivery, got {other:?}"),
        }
    }

    #[test]
    fn opening_twice_is_harmless() {
        let db = Memory::new();
        setup(&db);
        assert!(Ledger::open(&db).is_ok());
    }

    #[test]
    fn creates_a_project_once() {
        let db = Memory::new();
        let l = Ledger::open(&db).unwrap();
        assert_eq!(l.project().unwrap_err().code, "project_not_found");

        let (p, created) = l.create_project(P, "s1", T0).unwrap();
        assert!(created);
        assert_eq!(p.attempts_remaining, i64::from(TRIAL_ATTEMPTS));
        assert_eq!(p.expires_ms, T0 + TRIAL_DURATION_MS);

        let (again, created) = l.create_project(P, "s2", T0 + 5).unwrap();
        assert!(!created);
        assert_eq!(
            again, p,
            "a second create must not refill or rekey the trial"
        );
    }

    #[test]
    fn task_routes_need_a_project() {
        let db = Memory::new();
        let l = Ledger::open(&db).unwrap();
        let err = l
            .schedule(req("https://a.example.com/"), "t1", T0)
            .unwrap_err();
        assert_eq!(err.code, "project_not_found");
        assert_eq!(l.list(None, None, None).unwrap_err().status, 404);
    }

    #[test]
    fn schedules_and_reads_back_without_secrets() {
        let db = Memory::new();
        let l = setup(&db);
        let mut r = req("https://hooks.example.com/x");
        r.headers
            .insert("Authorization".into(), "Bearer s3cret".into());
        r.body = Some("{\"a\":1}".into());
        let (t, created) = l.schedule(r, "t1", T0).unwrap();
        assert!(created);
        assert_eq!(t.status, Status::Scheduled);
        assert_eq!(t.next_attempt_ms, Some(T0));
        assert_eq!(t.header_names, ["Authorization"]);
        assert_eq!(t.body_bytes, 7);
        assert_eq!(t.attempts, Some(vec![]));
        let json = serde_json::to_string(&t).unwrap();
        assert!(!json.contains("s3cret") && !json.contains("\"a\""));
    }

    #[test]
    fn reports_validation_errors_with_the_field() {
        let db = Memory::new();
        let l = setup(&db);
        let err = l
            .schedule(req("http://a.example.com/"), "t1", T0)
            .unwrap_err();
        assert_eq!(
            (err.status, err.code, err.field),
            (400, "invalid_request", Some("url"))
        );
        assert_eq!(err.body()["error"]["field"], "url");
    }

    #[test]
    fn idempotency_replays_and_conflicts() {
        let db = Memory::new();
        let l = setup(&db);
        let mut r = req("https://a.example.com/");
        r.idempotency_key = Some("k1".into());
        let (first, created) = l.schedule(r.clone(), "t1", T0).unwrap();
        assert!(created);
        let (again, created) = l.schedule(r.clone(), "t2", T0 + 1000).unwrap();
        assert!(!created);
        assert_eq!(again.id, first.id);

        r.body = Some("different".into());
        assert_eq!(
            l.schedule(r, "t3", T0).unwrap_err().code,
            "idempotency_conflict"
        );
    }

    #[test]
    fn refuses_work_beyond_the_budget_or_trial() {
        let db = Memory::new();
        let l = setup(&db);
        db.0.execute("UPDATE project SET attempt_budget = 2", [])
            .unwrap();
        l.schedule(req("https://a.example.com/"), "t1", T0).unwrap();
        l.schedule(req("https://a.example.com/"), "t2", T0).unwrap();
        let err = l
            .schedule(req("https://a.example.com/"), "t3", T0)
            .unwrap_err();
        assert_eq!((err.status, err.code), (402, "budget_exhausted"));

        let late = T0 + TRIAL_DURATION_MS;
        assert_eq!(
            l.schedule(req("https://a.example.com/"), "t4", late)
                .unwrap_err()
                .code,
            "trial_expired"
        );

        let mut r = req("https://a.example.com/");
        r.run_at_ms = Some(T0 + TRIAL_DURATION_MS);
        db.0.execute("UPDATE project SET attempt_budget = 100", [])
            .unwrap();
        assert_eq!(
            l.schedule(r, "t5", T0).unwrap_err().field,
            Some("run_at_ms")
        );
    }

    #[test]
    fn caps_retained_tasks_even_when_canceled() {
        let db = Memory::new();
        let l = setup(&db);
        let mut r = req("https://a.example.com/");
        r.run_at_ms = Some(T0 + 60_000);
        r.body = Some("x".repeat(1024));
        for i in 0..MAX_RETAINED_TASKS {
            let id = format!("t{i}");
            l.schedule(r.clone(), &id, T0).unwrap();
            l.cancel(&id, T0).unwrap();
        }
        let err = l.schedule(r, "one_more", T0).unwrap_err();
        assert_eq!((err.status, err.code), (429, "task_limit"));

        // Purge frees the space once finished tasks age out.
        l.purge(T0 + RETENTION_MS).unwrap();
        let total: i64 =
            db.0.query_row("SELECT COUNT(*) FROM tasks", [], |r| r.get(0))
                .unwrap();
        assert_eq!(total, 0);
    }

    #[test]
    fn drops_the_body_once_a_task_cannot_be_sent_again() {
        let db = Memory::new();
        let l = setup(&db);
        let body = |id: &str| -> Option<String> {
            db.0.query_row("SELECT body FROM tasks WHERE id = ?", [id], |r| r.get(0))
                .unwrap()
        };
        let mut r = req("https://a.example.com/");
        r.body = Some("payload".into());
        r.max_attempts = Some(1);

        let mut later = r.clone();
        later.run_at_ms = Some(T0 + 60_000);
        l.schedule(later, "canceled", T0).unwrap();
        l.cancel("canceled", T0).unwrap();
        assert_eq!(body("canceled"), None);

        l.schedule(r.clone(), "ok", T0).unwrap();
        l.schedule(r, "bad", T0).unwrap();
        for d in l.publish_due(P, T0).unwrap() {
            let status = if d.task_id == "ok" { 200 } else { 500 };
            let attempt = deliver(&l, &d, T0);
            l.finish(&d.task_id, attempt.fence, http(status), T0, 0.0)
                .unwrap();
        }
        assert_eq!(body("ok"), None);
        assert_eq!(body("bad").as_deref(), Some("payload"), "kept for redrive");
        l.redrive("bad", T0 + 1).unwrap();
        let d = &l.publish_due(P, T0 + 1).unwrap()[0];
        assert_eq!(deliver(&l, d, T0 + 1).body.as_deref(), Some("payload"));
    }

    #[test]
    fn full_delivery_cycle_succeeds() {
        let db = Memory::new();
        let l = setup(&db);
        l.schedule(req("https://a.example.com/"), "t1", T0).unwrap();

        let due = l.publish_due(P, T0).unwrap();
        assert_eq!(
            due,
            [Dispatch {
                project_id: P.into(),
                task_id: "t1".into(),
                generation: 1
            }]
        );
        assert!(
            l.publish_due(P, T0 + 1).unwrap().is_empty(),
            "not republished right away"
        );

        let d = deliver(&l, &due[0], T0 + 10);
        assert_eq!(
            (d.attempt, d.fence, d.signing_secret.as_str()),
            (1, 1, "secret")
        );
        assert_eq!(l.task("t1").unwrap().status, Status::Delivering);
        assert_eq!(l.project().unwrap().attempts_used, 1);

        assert_eq!(
            l.finish("t1", 1, http(200), T0 + 20, 0.0).unwrap(),
            Some(Status::Succeeded)
        );
        let t = l.task("t1").unwrap();
        assert_eq!(t.status, Status::Succeeded);
        assert_eq!(t.finished_ms, Some(T0 + 20));
        assert_eq!(
            t.attempts.unwrap(),
            [AttemptView {
                number: 1,
                started_ms: T0 + 10,
                finished_ms: Some(T0 + 20),
                outcome: Some("http_200".into()),
                http_status: Some(200),
            }]
        );
    }

    #[test]
    fn retries_get_republished_with_a_new_generation() {
        let db = Memory::new();
        let l = setup(&db);
        l.schedule(req("https://a.example.com/"), "t1", T0).unwrap();
        let due = l.publish_due(P, T0).unwrap();
        deliver(&l, &due[0], T0);
        assert_eq!(
            l.finish("t1", 1, http(503), T0, 0.0).unwrap(),
            Some(Status::Retrying)
        );

        let t = l.task("t1").unwrap();
        let next = t.next_attempt_ms.unwrap();
        assert_eq!(next, T0 + 5_000);
        assert_eq!(l.next_wake().unwrap(), Some(next));
        assert!(l.publish_due(P, next - 1).unwrap().is_empty());

        let again = l.publish_due(P, next).unwrap();
        assert_eq!(again[0].generation, 2);
        assert_eq!(
            l.claim("t1", 1, next).unwrap(),
            Claimed::Skip("stale"),
            "old message ignored"
        );
        let d = deliver(&l, &again[0], next);
        assert_eq!(d.attempt, 2);
    }

    #[test]
    fn republishes_unclaimed_messages() {
        let db = Memory::new();
        let l = setup(&db);
        l.schedule(req("https://a.example.com/"), "t1", T0).unwrap();
        assert_eq!(l.publish_due(P, T0).unwrap().len(), 1);
        assert_eq!(l.next_wake().unwrap(), Some(T0 + REPUBLISH_MS));
        assert_eq!(l.publish_due(P, T0 + REPUBLISH_MS).unwrap().len(), 1);
    }

    #[test]
    fn ignores_duplicate_and_stale_messages() {
        let db = Memory::new();
        let l = setup(&db);
        l.schedule(req("https://a.example.com/"), "t1", T0).unwrap();
        let due = l.publish_due(P, T0).unwrap();
        deliver(&l, &due[0], T0);
        assert_eq!(l.claim("t1", 1, T0).unwrap(), Claimed::Skip("stale"));
        assert_eq!(
            l.claim("nope", 1, T0).unwrap(),
            Claimed::Skip("task_missing")
        );
        assert_eq!(l.finish("t1", 99, http(200), T0, 0.0).unwrap(), None);
        assert_eq!(
            l.project().unwrap().attempts_used,
            1,
            "duplicates are not charged"
        );
    }

    #[test]
    fn recovers_lost_attempts() {
        let db = Memory::new();
        let l = setup(&db);
        l.schedule(req("https://a.example.com/"), "t1", T0).unwrap();
        let due = l.publish_due(P, T0).unwrap();
        deliver(&l, &due[0], T0);
        assert_eq!(l.next_wake().unwrap(), Some(T0 + LEASE_MS));

        assert_eq!(l.recover(T0 + LEASE_MS - 1, || 0.0).unwrap(), 0);
        assert_eq!(l.recover(T0 + LEASE_MS, || 0.0).unwrap(), 1);
        let t = l.task("t1").unwrap();
        assert_eq!(t.status, Status::Retrying);
        assert_eq!(
            t.attempts.unwrap()[0].outcome.as_deref(),
            Some("lease_expired")
        );
        assert_eq!(
            l.finish("t1", 1, http(200), T0 + LEASE_MS + 1, 0.0)
                .unwrap(),
            None
        );
    }

    #[test]
    fn fails_waiting_tasks_when_the_budget_runs_out() {
        let db = Memory::new();
        let l = setup(&db);
        l.schedule(req("https://a.example.com/"), "t1", T0).unwrap();
        db.0.execute("UPDATE project SET attempts_used = attempt_budget", [])
            .unwrap();
        let due = l.publish_due(P, T0).unwrap();
        assert_eq!(
            l.claim("t1", 1, T0).unwrap(),
            Claimed::Skip("budget_exhausted")
        );
        let t = l.task("t1").unwrap();
        assert_eq!((t.status, t.attempt_count), (Status::Failed, 0));
        assert_eq!(
            l.claim("t1", due[0].generation, T0).unwrap(),
            Claimed::Skip("stale")
        );
    }

    #[test]
    fn cancel_and_redrive() {
        let db = Memory::new();
        let l = setup(&db);
        l.schedule(req("https://a.example.com/"), "t1", T0 + 60_000)
            .unwrap();
        assert_eq!(l.cancel("t1", T0).unwrap().status, Status::Canceled);
        assert_eq!(l.redrive("t1", T0).unwrap_err().code, "task_not_failed");
        assert_eq!(l.cancel("nope", T0).unwrap_err().code, "task_not_found");

        let mut r = req("https://a.example.com/");
        r.max_attempts = Some(1);
        l.schedule(r, "t2", T0).unwrap();
        let due = l.publish_due(P, T0).unwrap();
        deliver(&l, &due[0], T0);
        l.finish("t2", 1, http(500), T0, 0.0).unwrap();
        assert_eq!(l.cancel("t2", T0).unwrap_err().code, "task_finished");

        let t = l.redrive("t2", T0 + 1).unwrap();
        assert_eq!(t.status, Status::Scheduled);
        let due = l.publish_due(P, T0 + 1).unwrap();
        assert_eq!(due[0].generation, 2);
        assert_eq!(deliver(&l, &due[0], T0 + 1).attempt, 2);
    }

    #[test]
    fn lists_newest_first_with_cursor_and_filter() {
        let db = Memory::new();
        let l = setup(&db);
        for i in 0..5 {
            l.schedule(req("https://a.example.com/"), &format!("t{i}"), T0 + 60_000)
                .unwrap();
        }
        l.cancel("t3", T0).unwrap();

        let page = l.list(None, None, Some(2)).unwrap();
        let ids: Vec<_> = page.tasks.iter().map(|t| t.id.as_str()).collect();
        assert_eq!(ids, ["t4", "t3"]);
        assert!(page.tasks[0].attempts.is_none());
        let page2 = l.list(None, page.next_cursor.as_deref(), Some(2)).unwrap();
        assert_eq!(page2.tasks[0].id, "t2");
        let last = l.list(None, page2.next_cursor.as_deref(), Some(2)).unwrap();
        assert_eq!((last.tasks.len(), last.next_cursor), (1, None));

        let canceled = l.list(Some(Status::Canceled), None, None).unwrap();
        assert_eq!(canceled.tasks.len(), 1);
        assert_eq!(l.list(None, Some("x"), None).unwrap_err().status, 400);
    }

    #[test]
    fn purges_after_retention() {
        let db = Memory::new();
        let l = setup(&db);
        l.schedule(req("https://a.example.com/"), "t1", T0).unwrap();
        let due = l.publish_due(P, T0).unwrap();
        deliver(&l, &due[0], T0);
        l.finish("t1", 1, http(200), T0, 0.0).unwrap();
        assert_eq!(l.next_wake().unwrap(), Some(T0 + RETENTION_MS));

        assert_eq!(l.purge(T0 + RETENTION_MS - 1).unwrap(), 0);
        assert_eq!(l.purge(T0 + RETENTION_MS).unwrap(), 1);
        assert_eq!(l.task("t1").unwrap_err().code, "task_not_found");
        assert_eq!(l.next_wake().unwrap(), None);
    }

    fn with_callback(url: &str) -> ScheduleRequest {
        ScheduleRequest {
            callback_url: Some("https://cb.example.com/done".into()),
            ..req(url)
        }
    }

    #[test]
    fn migrates_a_v1_ledger_in_place() {
        let db = Memory::new();
        for statement in &SCHEMA[..SCHEMA.len() - 1] {
            db.0.execute(statement, []).unwrap();
        }
        db.0.execute(
            "INSERT INTO tasks (id, status, due_ms, max_attempts, run_attempts, total_attempts, \
             generation, fence, cancel_requested, method, url, headers, run_at_ms, fingerprint, \
             created_ms, updated_ms) VALUES ('old', 'scheduled', 1, 5, 0, 0, 1, 0, 0, 'POST', \
             'https://a.example.com/', '[]', 1, 'f', 1, 1)",
            [],
        )
        .unwrap();
        let l = Ledger::open(&db).unwrap();
        let t = l.task("old").unwrap();
        assert_eq!((t.callback_url, t.callback_task_id), (None, None));
        Ledger::open(&db).expect("migrations run once");
        let version: i64 =
            db.0.query_row("SELECT value FROM meta WHERE key = 'schema'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(version, MIGRATIONS.len() as i64);
    }

    #[test]
    fn delay_errors_name_the_delay_field() {
        let db = Memory::new();
        let l = setup(&db);
        let mut r = req("https://a.example.com/");
        r.delay = Some("soon".into());
        assert_eq!(l.schedule(r, "t1", T0).unwrap_err().field, Some("delay"));

        // Past the trial end: blame the field the caller used.
        db.0.execute("UPDATE project SET expires_ms = ?", [T0 + 3_600_000])
            .unwrap();
        let mut r = req("https://a.example.com/");
        r.delay = Some("2h".into());
        assert_eq!(l.schedule(r, "t2", T0).unwrap_err().field, Some("delay"));
        let mut r = req("https://a.example.com/");
        r.delay = Some("30m".into());
        let (t, _) = l.schedule(r, "t3", T0).unwrap();
        assert_eq!(t.run_at_ms, T0 + 1_800_000);
    }

    #[test]
    fn a_finished_task_posts_its_result_to_the_callback() {
        let db = Memory::new();
        let l = setup(&db);
        let (t, _) = l
            .schedule(with_callback("https://a.example.com/"), "t1", T0)
            .unwrap();
        assert_eq!(
            t.callback_url.as_deref(),
            Some("https://cb.example.com/done")
        );
        assert_eq!(t.callback_task_id, None);

        let d = &l.publish_due(P, T0).unwrap()[0];
        let a = deliver(&l, d, T0);
        l.finish("t1", a.fence, http(204), T0 + 5, 0.0).unwrap();

        let t = l.task("t1").unwrap();
        let cb_id = t.callback_task_id.clone().expect("callback queued");
        assert!(cb_id.starts_with("task_") && cb_id.len() == 25, "{cb_id}");
        let cb = l.task(&cb_id).unwrap();
        assert_eq!(cb.callback_for.as_deref(), Some("t1"));
        assert_eq!((cb.status, cb.method), (Status::Scheduled, Method::Post));
        assert_eq!(cb.url, "https://cb.example.com/done");
        assert_eq!(cb.callback_url, None, "callbacks do not call back");

        let d = &l.publish_due(P, T0 + 5).unwrap()[0];
        assert_eq!(d.task_id, cb_id);
        let delivery = deliver(&l, d, T0 + 5);
        assert_eq!(
            delivery.headers,
            [("Content-Type".to_string(), "application/json".to_string())]
        );
        let report: serde_json::Value =
            serde_json::from_str(delivery.body.as_deref().unwrap()).unwrap();
        assert_eq!(report["event"], "task.finished");
        assert_eq!(report["task"]["id"], "t1");
        assert_eq!(report["task"]["status"], "succeeded");
        assert_eq!(report["task"]["callback_task_id"], cb_id.as_str());
        assert_eq!(report["task"]["attempts"][0]["http_status"], 204);

        l.finish(&cb_id, delivery.fence, http(200), T0 + 6, 0.0)
            .unwrap();
        assert_eq!(l.task(&cb_id).unwrap().status, Status::Succeeded);
        assert_eq!(l.next_wake().unwrap(), Some(T0 + 5 + RETENTION_MS));
        assert_eq!(l.project().unwrap().attempts_used, 2);
    }

    #[test]
    fn every_way_of_finishing_calls_back_once() {
        let db = Memory::new();
        let l = setup(&db);
        let callbacks = |id: &str| -> i64 {
            db.0.query_row(
                "SELECT COUNT(*) FROM tasks WHERE callback_for = ?",
                [id],
                |r| r.get(0),
            )
            .unwrap()
        };
        let mut later = with_callback("https://a.example.com/");
        later.run_at_ms = Some(T0 + 60_000);

        // Canceled while waiting; canceling again does not call back twice.
        l.schedule(later.clone(), "c", T0).unwrap();
        l.cancel("c", T0).unwrap();
        l.cancel("c", T0 + 1).unwrap();
        assert_eq!(callbacks("c"), 1);

        // Failed, redriven and failed again: one callback per finish.
        let mut once = with_callback("https://a.example.com/");
        once.max_attempts = Some(1);
        l.schedule(once, "f", T0).unwrap();
        for now in [T0, T0 + 10] {
            let d = l
                .publish_due(P, now)
                .unwrap()
                .into_iter()
                .find(|d| d.task_id == "f")
                .unwrap();
            let a = deliver(&l, &d, now);
            l.finish("f", a.fence, http(500), now, 0.0).unwrap();
            if now == T0 {
                assert_eq!(callbacks("f"), 1);
                l.redrive("f", T0 + 10).unwrap();
            }
        }
        assert_eq!(callbacks("f"), 2);

        // Lost attempt that exhausts the task's attempts.
        let mut lost = with_callback("https://a.example.com/");
        lost.max_attempts = Some(1);
        l.schedule(lost, "l", T0).unwrap();
        let d = l
            .publish_due(P, T0 + 20)
            .unwrap()
            .into_iter()
            .find(|d| d.task_id == "l")
            .unwrap();
        deliver(&l, &d, T0 + 20);
        l.recover(T0 + 20 + LEASE_MS, || 0.0).unwrap();
        assert_eq!(l.task("l").unwrap().status, Status::Failed);
        assert_eq!(callbacks("l"), 1);
    }

    #[test]
    fn admission_reserves_an_attempt_and_a_row_for_the_callback() {
        let db = Memory::new();
        let l = setup(&db);
        db.0.execute("UPDATE project SET attempt_budget = 3", [])
            .unwrap();
        l.schedule(with_callback("https://a.example.com/"), "t1", T0)
            .unwrap();
        let err = l
            .schedule(with_callback("https://a.example.com/"), "t2", T0)
            .unwrap_err();
        assert_eq!(err.code, "budget_exhausted");
        l.schedule(req("https://a.example.com/"), "t3", T0).unwrap();

        // Abandoned for lack of budget still reports, and that callback is abandoned too.
        db.0.execute("UPDATE project SET attempts_used = 3", [])
            .unwrap();
        let d = l
            .publish_due(P, T0)
            .unwrap()
            .into_iter()
            .find(|d| d.task_id == "t1")
            .unwrap();
        assert_eq!(
            l.claim(&d.task_id, d.generation, T0).unwrap(),
            Claimed::Skip("budget_exhausted")
        );
        let cb_id = l.task("t1").unwrap().callback_task_id.unwrap();
        let d = l
            .publish_due(P, T0 + REPUBLISH_MS)
            .unwrap()
            .into_iter()
            .find(|d| d.task_id == cb_id)
            .unwrap();
        assert_eq!(
            l.claim(&d.task_id, d.generation, T0 + REPUBLISH_MS)
                .unwrap(),
            Claimed::Skip("budget_exhausted")
        );
        assert_eq!(l.task(&cb_id).unwrap().status, Status::Failed);
        assert_eq!(l.task(&cb_id).unwrap().callback_task_id, None);

        // Near the retained-task cap a callback needs a second row.
        db.0.execute(
            "UPDATE project SET attempt_budget = 100, attempts_used = 0",
            [],
        )
        .unwrap();
        let mut later = req("https://a.example.com/");
        later.run_at_ms = Some(T0 + 60_000);
        let held: i64 =
            db.0.query_row("SELECT COUNT(*) FROM tasks", [], |r| r.get(0))
                .unwrap();
        for i in held..MAX_RETAINED_TASKS - 1 {
            let id = format!("x{i}");
            l.schedule(later.clone(), &id, T0).unwrap();
            l.cancel(&id, T0).unwrap();
        }
        let err = l
            .schedule(with_callback("https://a.example.com/"), "big", T0)
            .unwrap_err();
        assert_eq!(err.code, "task_limit");
        l.schedule(later, "small", T0).unwrap();
    }

    #[test]
    fn callback_ids_are_stable_and_distinct() {
        assert_eq!(callback_id("t1", 1), callback_id("t1", 1));
        assert_ne!(callback_id("t1", 1), callback_id("t1", 2));
        assert_ne!(callback_id("t1", 1), callback_id("t2", 1));
    }
}
