---
name: maintain-agents
description: Create, review, or update AGENTS.md as concise durable repository guidance. Use when the user explicitly wants persistent project or directory instructions, recurring corrections, canonical build and test commands, review expectations, safety boundaries, or routing guidance recorded for future Codex sessions. Do not use for temporary task instructions, design details, progress logs, or one-off implementation notes.
---

# Maintain AGENTS.md

Keep durable guidance close to the files it governs and small enough to load on every relevant task.

## Workflow

1. Resolve the repository root and target path. Read every applicable `AGENTS.md` from root to that path before editing.
2. Confirm the requested content should persist across tasks. Repeated mistakes, stable commands, conventions, review gates, directory routing, and safety constraints belong here. Current design, implementation status, historical rationale, and task checklists do not.
3. Verify commands and paths from repository files or actual output. Never encode a guessed command as canonical.
4. Update the closest applicable `AGENTS.md`. Use a nested file for subtree-only rules; keep shared rules at root.
5. Prefer direct imperatives and compact sections. Remove duplication and resolve conflicts with broader guidance explicitly.
6. Read the full effective guidance chain after editing. Check that a future agent can identify scope, commands, required verification, and prohibited actions without task history.
7. Do not stage or commit unless explicitly requested.

## Recommended content

- Scope and repository orientation only when non-obvious.
- Exact install, format, lint, typecheck, test, build, and focused-test commands.
- Rules for generated files, migrations, dependencies, and directory ownership.
- Review expectations and completion gates.
- Safety constraints and operations that require user confirmation.
- A short pointer to `DESIGN.md` for architecture and `PLANS.md` for current work.

## Exclude

- Conversation context, personal preferences unrelated to the repository, and completed work.
- Detailed architecture or data-model prose owned by `DESIGN.md`.
- Milestones, acceptance checklists, transcripts, and progress owned by `PLANS.md` or Git history.
- Rules that should instead be mechanically enforced by formatters, linters, tests, or hooks. Mention the enforcement command, not a duplicate specification.

## Quality bar

Every instruction must be durable, scoped, actionable, non-secret, and supported by the repository. If removing a line would not change future behavior, remove it.
