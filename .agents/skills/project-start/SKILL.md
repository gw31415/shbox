---
name: project-start
description: Bootstrap a new or newly formalized repository with focused AGENTS.md, DESIGN.md, and PLANS.md documents. Use only when the user asks to initialize project guidance, architecture documentation, and an executable work plan together, or wants a new project to adopt the Project Continuity workflow. Do not use for summaries, README-only edits, isolated small fixes, or routine updates to just one existing document.
---

# Start a Project Continuity Workflow

Create the smallest useful project context that lets a new contributor understand the rules, current design, and next verifiable milestone without reading a history dump.

## Document ownership

- `AGENTS.md` owns durable repository instructions: commands, conventions, boundaries, and quality gates.
- `DESIGN.md` owns the current design: goals, architecture, interfaces, invariants, decisions, and open design questions.
- `PLANS.md` owns only active execution state: current context, unfinished milestones, acceptance, validation, and recovery.
- Code, tests, and user documentation own current behavior. Git commit bodies own completed-plan history and past rationale.

Do not duplicate the same material across documents. Link to the owning document when another document needs the context.

## Workflow

1. Resolve the repository root and read existing `AGENTS.md` files from root to the working directory. Inspect `README`, manifests, source layout, test configuration, and Git status when available.
2. Check for existing `AGENTS.md`, `DESIGN.md`, `PLANS.md`, architecture records, or planning policies. Never overwrite an existing file. Add only explicitly requested missing structure.
3. Infer commands and repository facts from files and actual command output. Label uncertain assumptions and avoid inventing tools, paths, test results, or architecture.
4. Read the templates under `../../assets/templates/`. Adapt them to this repository, remove irrelevant sections, and resolve every `{{...}}` marker before writing.
5. Keep `AGENTS.md` short. Put design detail in `DESIGN.md` and only unfinished, independently verifiable milestones plus their required current context in `PLANS.md`.
6. Phrase acceptance as observable behavior. Include exact working directories, commands, expected outcomes, safe retry, and rollback guidance.
7. Read all generated files back and check for contradictions, unresolved markers, secrets, and duplicated ownership. Run `python3 <plugin-root>/scripts/validate_repository.py --project-root <repo-root>` when the plugin root is available.
8. Do not stage or commit unless the user explicitly requests it.

## Existing-file behavior

- If all three files exist, report gaps and propose focused edits instead of reinitializing them.
- If only one or two are missing, create only the missing documents.
- If a nested `AGENTS.md` should own directory-specific rules, update the closest applicable file instead of bloating the root.
- If `.agent/PLANS.md` or another file defines planning policy, preserve it as `plan_rules_path` and create or locate a separate active `exec_plan_path`.

## Completion check

- Every generated fact has repository evidence or is labeled as an assumption.
- Existing files and unrelated changes are preserved.
- The three documents have distinct ownership and no conflicting commands or invariants.
- A first-time contributor can identify what to run, what to change next, and how to prove success.
