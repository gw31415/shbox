//! Sandbox lifecycle domain: validated ids, metadata, storage, and the
//! `SandboxManager`. Milestone 1 introduces only the id grammar.

/// Milestone 1 introduces the id grammar; the SandboxManager (Milestone 3)
/// and the SSH handlers (Milestone 2) consume the validated type.
#[allow(dead_code)]
pub mod id;

// Re-exports land with their first consumer in Milestone 2/3.
#[allow(unused_imports)]
pub use id::{InvalidSandboxId, SandboxId};
