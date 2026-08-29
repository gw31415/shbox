---
name: maintain-design
description: Create, review, or update DESIGN.md as the current architecture and design source of truth. Use when a durable product goal, system boundary, interface, data model, invariant, security constraint, tradeoff, or architecture decision changes. Do not use for transient implementation progress, completed-work history, routine renames, raw research notes, or task checklists.
---

# Maintain DESIGN.md

Describe the system that should exist now and why its durable constraints matter. Keep historical change narration in Git and active work in `PLANS.md`.

## Workflow

1. Read applicable `AGENTS.md`, the entire current `DESIGN.md`, relevant code, tests, public docs, schemas, and active plan before changing the design.
2. Separate durable design from implementation tactics. Record goals, non-goals, boundaries, dependencies, data flow, interfaces, invariants, failure behavior, security, and material tradeoffs.
3. Confirm each claim against current code or mark it clearly as proposed. Never rewrite a proposal as implemented design before code and tests establish it.
4. Update existing sections in place. Remove obsolete statements when the design changes; do not append a chronological changelog.
5. Record material decisions with rationale and consequences. Keep discarded alternatives only when forgetting them would likely reopen a costly decision.
6. Update `PLANS.md` separately when the design change creates unfinished implementation work. Update `AGENTS.md` only when it changes durable working rules.
7. Check links, paths, terminology, interfaces, and invariants for consistency. Do not stage or commit unless explicitly requested.

## Minimum useful structure

- Purpose, goals, and non-goals.
- Current system overview and component boundaries.
- Interfaces and data flow.
- Invariants, failure behavior, and security constraints.
- Current decisions and tradeoffs.
- Known risks and unresolved design questions.
- Validation or evidence that demonstrates the architecture.

Omit sections that add no information. Prefer diagrams only when relationships are materially clearer than prose.

## Ownership boundary

- `DESIGN.md` says what the current design is and why.
- Code, tests, schemas, and user docs remain authoritative for executable behavior and public contracts.
- `AGENTS.md` says how contributors and agents must work.
- `PLANS.md` says what remains to be done.
- Commit messages preserve past context, deviations, and verification evidence.

When code and `DESIGN.md` disagree, state the discrepancy before choosing whether the document or implementation must change.
