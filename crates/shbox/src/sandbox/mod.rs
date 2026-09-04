//! Sandbox lifecycle domain: validated ids, durable metadata, safe storage,
//! and the `SandboxManager`.

/// The id grammar is kept independent of storage and SSH transport concerns;
/// SandboxManager and the SSH handlers consume this validated type.
#[allow(dead_code)]
pub mod id;

#[allow(dead_code)]
pub(crate) mod manager;
#[allow(dead_code)]
pub(crate) mod metadata;
#[allow(dead_code)]
pub(crate) mod storage;
/// Subordinate-ID leases for isolated Linux sandboxes. Linux-only in use,
/// but platform-neutral in schema so the ledger can be inspected and
/// reconciled anywhere shbox runs.
#[allow(dead_code)]
pub(crate) mod subid;

// Re-export the domain types used by the manager and SSH layers.
#[allow(unused_imports)]
pub use id::{InvalidSandboxId, SandboxId};
pub(crate) use manager::SandboxManager;
