# Repository Conventions

- Commit frequently at meaningful checkpoints, especially before large rewrites, after passing verification, and before switching implementation direction.
- Keep commits focused enough that a failing or unwanted change can be understood and reverted without losing unrelated progress.
- Run the relevant tests or build checks before checkpoint commits when practical, and mention any skipped verification in the commit context.
- Do not create files or directories outside the repository root (`./`), including temporary files, logs, evidence, or Git worktrees.

## Project Planning

- GitHub [milestones](https://github.com/minsago-elite/decomp_thing/milestones) and [issues](https://github.com/minsago-elite/decomp_thing/issues) are the source of truth for planned work and progress.
- Use milestones for project phases or outcomes. Use focused issues with explicit acceptance criteria for actionable work.
- Before starting planned work, check the relevant milestone and issue for current scope, dependencies, and status.
- Keep issue status and acceptance criteria current as work lands. Reference issues in commits; include an issue reference in a PR title or description only when that PR is intended to close the issue.
- Create or update a GitHub issue when new roadmap work is discovered. Do not add planning checklists to `ROADMAP.md`; it is retained only as a deprecated migration pointer.
- Files under `roadmap/` are historical design and benchmark context, not live project status, unless an active issue explicitly references them.

## CI and Pull Requests

- Prefer GitHub Actions for primary verification and qualification. Use short local checks for fast feedback when practical.
- Do not poll a CI check that is expected to take longer than three minutes. Continue another useful task and check back later.
- Mark pull requests ready for review instead of leaving them as drafts.
- Do not request review from the Codex code review bot; it is added automatically when a commit is pushed to a ready pull request.
- Do not merge a pull request while required CI checks fail or are pending, or until all Codex code review bot reviews are resolved.
- For privileged commands on local hosts, use `doas` instead of `sudo`.

## Repository Sanity Checks

- Before continuing A-series work, verify the relevant milestone and issue status, dependencies, acceptance criteria, and current evidence.
- Check that closed issues have evidence matching their full acceptance criteria and intended scope; reopen or correct closure metadata when they were closed improperly.
