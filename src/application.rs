//! CQRS application boundary: separate command/query DTOs and handlers over the same authoritative store.
use crate::core::{Create, Fault, Ledger};
use serde_json::{json, Value};
pub enum Command {
    ConfigureQueue { limits: crate::limits::QueueLimits },
    Enqueue { key: String, input: Create },
    Cancel { id: String },
    Redrive { id: String, key: String },
}
pub enum Query {
    QueueConfig,
    Task { id: String },
    Attempts { id: String },
    List { after: String },
}
pub struct CommandResult {
    pub status: u16,
    pub body: Value,
}
pub fn command(ledger: &mut Ledger, c: Command, now: i64) -> Result<CommandResult, Fault> {
    if let Command::ConfigureQueue { limits } = c {
        ledger.configure(limits, now)?;
        return Ok(CommandResult {
            status: 200,
            body: serde_json::to_value(&ledger.limits).map_err(|_| Fault::Invalid)?,
        });
    }
    let (task, created) = match c {
        Command::ConfigureQueue { .. } => unreachable!("handled above"),
        Command::Enqueue { key, input } => ledger.create(&key, input, now)?,
        Command::Cancel { id } => (ledger.cancel(&id, now)?, false),
        Command::Redrive { id, key } => ledger.redrive(&id, &key, now)?,
    };
    Ok(CommandResult {
        status: if created { 201 } else { 200 },
        body: serde_json::to_value(task).map_err(|_| Fault::Invalid)?,
    })
}
pub fn query(ledger: &Ledger, q: Query) -> Result<Value, Fault> {
    match q {
        Query::QueueConfig => serde_json::to_value(&ledger.limits).map_err(|_| Fault::Invalid),
        Query::Task { id } => serde_json::to_value(ledger.get(&id)?).map_err(|_| Fault::Invalid),
        Query::Attempts { id } => {
            serde_json::to_value(ledger.get(&id)?.attempts).map_err(|_| Fault::Invalid)
        }
        Query::List { after } => {
            let tasks: Vec<_> = ledger
                .tasks
                .values()
                .filter(|t| t.id > after)
                .take(51)
                .cloned()
                .collect();
            let more = tasks.len() > 50;
            let items: Vec<_> = tasks.into_iter().take(50).collect();
            let next = if more {
                items.last().map(|t| t.id.clone())
            } else {
                None
            };
            Ok(json!({"tasks":items,"next_after":next}))
        }
    }
}
