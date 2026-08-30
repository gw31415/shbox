//! Sandbox lifecycle domain: validated ids, metadata, storage, and the
//! `SandboxManager`. Milestone 1 introduces only the id grammar.

/// The id grammar is kept independent of storage and SSH transport concerns;
/// SandboxManager and the SSH handlers consume this validated type.
#[allow(dead_code)]
pub mod id;

// Re-export the domain type for the manager and SSH layers.
#[allow(unused_imports)]
pub use id::{InvalidSandboxId, SandboxId};
