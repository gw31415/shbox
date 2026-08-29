---
name: rolling-plan
description: Create, execute, resume, or compact a self-contained rolling PLANS.md for complex features, significant refactors, migrations, or multi-session work. Use when the user asks for an ExecPlan, a resumable implementation plan, milestone progress updates, or a plan containing only unfinished work. Preserve planning-policy files and keep verified completed history for archive-commit rather than accumulating it in the active plan.
---

# Operate a Rolling Execution Plan

Maintain an executable specification for what remains, not a diary of what already happened. A new contributor must be able to resume from the current working tree and active plan alone.

## Identify the active plan

Read repository guidance and distinguish:

- `plan_rules_path`: a durable policy or template such as `.agent/PLANS.md`. Never prune it.
- `exec_plan_path`: the task-specific active plan. Only this file follows the rolling lifecycle.

If no convention exists, use `PLANS.md` and adapt `../../assets/templates/PLANS.md`. Never overwrite an existing plan without reading it completely.

## Required properties

- Explain user value and how to observe it.
- Orient a novice with exact repository-relative paths, modules, terms, and current assumptions.
- Keep unchecked and in-flight progress only. Split partial work into completed and remaining portions before archival.
- Describe remaining milestones as goal, edits, result, and proof. Each milestone must be independently verifiable.
- Give exact commands, working directories, expected outcomes, and actual results only after execution.
- Capture uncommitted discoveries and decisions plus facts that still constrain remaining work.
- Include idempotence, retry, rollback, and cleanup for risky work.
- Resolve ambiguity in the plan when safe. Ask only when a missing choice would materially change scope or outcome.

## Execution loop

1. Read the entire plan and relevant source before editing.
2. Select the next coherent, independently verifiable slice.
3. Keep the plan current at every stopping point. Record discoveries and decisions as they occur.
4. Implement through observable behavior, not compilation alone. Run canonical checks and slice acceptance after the final edit.
5. Classify plan items as `implemented`, `deviated`, `discovered`, `deferred`, or `missing`. A `missing` acceptance condition blocks archival.
6. If the user requested a commit, hand verified completed material to `$archive-commit`. Otherwise retain it in the in-flight section and do not prune yet.
7. After successful archival, remove completed progress, acceptance, transcripts, and past-only rationale. Retain current-state summaries and constraints required for unfinished work.

## Compaction boundary

Never delete completed context before an archival payload and recovery snapshot exist. A tracked plan is pruned in the same commit as the implementation. An untracked task-local plan may be removed only after commit success and message readback, and only when deletion is within the user's intent.

The remaining plan may mention implemented code in `Current State` when unfinished work depends on it. State it as current fact; do not retain completed milestone narratives or old verification transcripts.

## Completion check

The plan is self-contained, honest about uncertainty, free of secrets, and contains only active context plus the minimum current-state facts needed to resume.
