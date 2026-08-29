---
name: archive-commit
description: Draft or create a detailed, self-contained Conventional Commit that archives verified implementation context, decisions, deviations, and exact test evidence. Use when the user asks for a long-form commit message, explicitly asks to commit a verified slice, or wants completed active-plan content preserved in Git before PLANS.md is compacted. Draft-only requests never stage, prune, or commit. Actual Git mutations require explicit commit intent.
---

# Archive Verified Work in Git

Use Git history as the immutable record of completed work while keeping the active plan focused on what remains.

## Fix intent and scope

Classify the request as `draft-only`, `commit`, or `commit-with-plan-pruning`. If commit intent is not explicit, return message text only and do not stage, create transport files, or edit the plan.

For a commit, inspect:

```bash
git status --short --branch
git diff --cached --name-status
git diff --cached --stat
git diff --cached --numstat
git diff --cached --check
```

Before mutation, write an exact `owned_path_allowlist` containing every path authorized for this commit. Compare `git diff --cached --name-only` with it. Any staged path outside the allowlist is a hard stop: do not unstage it, prune the plan, or commit. If the active-plan path already has a staged change, also stop before mutation; preserving a worktree/index split cannot be made transactional by restaging the file.

If the staged diff is empty, inspect unstaged changes but do not stage them automatically. Explain only the intended commit scope. Include renames, deletions, binary files, submodules, and generated files in the audit. Never use `git add .` or another broad staging command.

## Evidence gate

Read the staged diff, active plan when present, relevant design and tests, and final post-edit command output. Classify work as `implemented`, `deviated`, `discovered`, `deferred`, or `missing`. Any `missing` item blocks commit and pruning.

Never claim an unexecuted test, hide warnings, or archive secrets, tokens, personal information, huge logs, or fabricated issue references.

## Write the message

Use `../../assets/templates/commit-message.txt` and keep only informative sections. The subject must follow:

```text
<type>[optional scope][optional !]: <imperative description>
```

Use standard lowercase types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, or `revert`. A breaking change requires both `!` and a final `BREAKING CHANGE:` footer.

Preserve context a future reader cannot recover from the diff alone: problem, decision, archived plan slice, semantic implementation, observable behavior, deviations and discoveries, exact final verification, outcome, remaining work, migration, risks, and real references. Avoid raw diff narration and repeated generalities.

## Prune transactionally

For a tracked active plan:

1. Confirm the exact owned-path allowlist, reject any unrelated staged path, and reject a pre-staged active plan.
2. Create a repository-external plan snapshot and message transport with `mktemp`; do not use fixed paths or expand untrusted plan or diff text through a shell heredoc.
3. Read both files back before pruning.
4. Remove only material archived by this commit. Retain unfinished work, current-state facts it needs, constraints, risks, unexecuted validation, and recovery.
5. Stage only explicitly owned implementation paths and the plan edit or deletion. Re-run `git diff --cached --check`, then require every staged path to be in the allowlist and every intended path to be present.
6. Commit with `git commit -F <message-file>`.
7. On failure, restore the plan worktree byte-for-byte from the snapshot and restore only that path's index entry to its pre-transaction clean state. Preserve implementation staging and every unrelated worktree/index change, clean temporary files, and report failure. The pre-staged-plan guard is what makes this exact recovery possible.
8. On success, read back `git show -s --format=%B HEAD`, `git show --stat --oneline HEAD`, and status. Confirm message, diff, pruning, and remaining context agree before deleting temporary files.

An untracked task-local plan cannot record its deletion in the commit. Keep it through commit and message readback; remove it afterward only when deletion is explicitly within the user's intent. Never delete a shared queue, planning policy, or template.

## Boundaries

- With no active plan, use the same long-form quality without creating or pruning `PLANS.md`.
- Do not amend pushed commits, force-push, push, close issues, or add trailers without explicit authority.
- Preserve unrelated changes. Do not use destructive reset, clean, checkout, or broad restore commands.
- A commit is complete only after Git object readback matches the generated message and intended paths.
