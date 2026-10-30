//! CQRS application boundary: separate command/query DTOs and handlers over the same authoritative store.
use crate::core::{Create, Fault, Ledger};
use serde_json::{json, Value};
pub enum Command {
    ReportTransport {
        reference: crate::transport::Reference,
    },
    ReconcileTransport {
        id: String,
    },
    MaintainRetention,
    ConfigureQueue {
        limits: crate::limits::QueueLimits,
    },
    Enqueue {
        key: String,
        input: Create,
    },
    Cancel {
        id: String,
    },
    Redrive {
        id: String,
        key: String,
    },
}
pub enum Query {
    TransportList { after: String, sampled_at_ms: i64 },
    TransportRecord { id: String, sampled_at_ms: i64 },
    Metrics { sampled_at_ms: i64 },
    Health { sampled_at_ms: i64 },
    Audit,
    Inspection { id: String },
    QueueConfig,
    Task { id: String },
    Attempts { id: String },
    List { after: String },
}
pub struct CommandResult {
    pub status: u16,
    pub body: Value,
}
impl CommandResult {
    /// Mutation permissions do not grant access to persisted payloads or attempt history.
    /// Legacy full-scope fixtures retain their original response contract.
    pub fn scoped_body(&self, can_read: bool) -> Value {
        if !can_read && self.body.get("dead_letter").is_some() {
            return json!({"dead_letter":{"record_id":self.body["dead_letter"]["record_id"]},"replayed":self.body["replayed"]});
        }
        if can_read || self.body.get("id").is_none() {
            return self.body.clone();
        }
        let mut receipt = serde_json::Map::new();
        for field in ["id", "status", "generation", "cancel_requested", "parent"] {
            if let Some(value) = self.body.get(field) {
                receipt.insert(field.into(), value.clone());
            }
        }
        Value::Object(receipt)
    }
}
pub fn command(ledger: &mut Ledger, c: Command, now: i64) -> Result<CommandResult, Fault> {
    if let Command::MaintainRetention = c {
        return Ok(CommandResult {
            status: 200,
            body: serde_json::to_value(ledger.purge(now)).map_err(|_| Fault::Invalid)?,
        });
    }
    if let Command::ConfigureQueue { limits } = c {
        ledger.configure(limits, now)?;
        return Ok(CommandResult {
            status: 200,
            body: serde_json::to_value(&ledger.limits).map_err(|_| Fault::Invalid)?,
        });
    }
    let (task, created) = match c {
        Command::ReportTransport { .. } | Command::ReconcileTransport { .. } => {
            return Err(Fault::Forbidden)
        }
        Command::MaintainRetention | Command::ConfigureQueue { .. } => {
            unreachable!("handled above")
        }
        Command::Enqueue { key, input } => ledger.create(&key, input, now)?,
        Command::Cancel { id } => (ledger.cancel(&id, now)?, false),
        Command::Redrive { id, key } => ledger.redrive(&id, &key, now)?,
    };
    Ok(CommandResult {
        status: if created { 201 } else { 200 },
        body: serde_json::to_value(task).map_err(|_| Fault::Invalid)?,
    })
}
pub fn command_in_tenant(
    ledger: &mut Ledger,
    c: Command,
    now: i64,
    tenant: &str,
    actor: &str,
) -> Result<CommandResult, Fault> {
    match c {
        Command::ReportTransport { reference } => {
            let (record, created, replayed) = ledger.report_transport(tenant, reference, now)?;
            Ok(CommandResult {
                status: if created { 201 } else { 200 },
                body: json!({"dead_letter":record,"replayed":replayed}),
            })
        }
        Command::ReconcileTransport { id } => {
            let (record, replayed) = ledger.reconcile_transport(tenant, &id, actor, now)?;
            Ok(CommandResult {
                status: 200,
                body: json!({"dead_letter":record,"replayed":replayed}),
            })
        }
        other => command(ledger, other, now),
    }
}
pub fn query(ledger: &Ledger, q: Query) -> Result<Value, Fault> {
    match q {
        Query::TransportList {
            after,
            sampled_at_ms,
        } => ledger.transport_records(&after, sampled_at_ms),
        Query::TransportRecord { id, sampled_at_ms } => ledger.transport_record(&id, sampled_at_ms),
        Query::Metrics { sampled_at_ms } => Ok(ledger.metrics.view(sampled_at_ms)),
        Query::Health { sampled_at_ms } => Ok(crate::operations::health(ledger, sampled_at_ms)),
        Query::Audit => Ok(
            json!({"events":ledger.audit,"capacity":crate::operations::AUDIT_CAP,"last_sequence":ledger.audit_sequence}),
        ),
        Query::Inspection { id } => Ok(crate::operations::inspection(&ledger.get(&id)?)),
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
