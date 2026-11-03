# Repository Conventions

- Commit and push frequently at meaningful checkpoints, especially before large rewrites, after passing verification, and before switching implementation direction.
- Keep commits focused enough that a failing or unwanted change can be understood and reverted without losing unrelated progress.
- Run the relevant tests or build checks before checkpoint commits when practical, and mention any skipped verification in the commit context.
- Do not create files or directories outside the repository root (`./`), including temporary files, logs, evidence, or Git worktrees.

## Project Planning

- Ghidra is a bundled application dependency linked through its Java APIs, not a separately installed prerequisite. Production analysis must not require `GHIDRA_HOME` or delegate to an external `analyzeHeadless` installation. Preserve isolated worker execution and authenticated oracle boundaries when migrating existing adapters.
- GitHub [milestones](https://github.com/minsago-elite/decomp_thing/milestones) and [issues](https://github.com/minsago-elite/decomp_thing/issues) are the source of truth for planned work and progress.
- Use milestones for project phases or outcomes. Use focused issues with explicit acceptance criteria for actionable work.
- Before starting planned work, check the relevant milestone and issue for current scope, dependencies, and status.
- Keep issue status and acceptance criteria current as work lands. Reference issues in commits; include an issue reference in a PR title or description only when that PR is intended to close the issue.
- Create or update a GitHub issue when new roadmap work is discovered. Do not add planning checklists to `ROADMAP.md`; it is retained only as a deprecated migration pointer.
- Files under `roadmap/` are historical design and benchmark context, not live project status, unless an active issue explicitly references them.

## Agent Orchestration and Model Routing

- Fetch and integrate the latest upstream state before implementation so branches do not drift unnecessarily. Keep pull requests ready for review when their implementation is ready.
- Use the orchestration tools for provider- or model-specific work. Do not silently substitute a different provider or model when the requested one is unavailable; report the limitation and continue only with independent work.
- For backend work, use Opus 5.5 for substantial planning, Luna for implementation, and Sol 6.1 as the technical middle layer for design decisions, integration, and review. Prefer Sol 6.1 through the orchestration tools rather than implementing backend changes directly with Codex.
- Delegate hard backend tasks with detailed implementation decisions to Fable or Astra when those agents are available. Keep the work focused on a concrete acceptance boundary and retain exact-source test and review evidence.
- For frontend work, use Opus 5.5 through Claude Code at low reasoning. Use Sonnet 5.5 only when a second frontend implementation or review pass is useful.
- Fan out independent work when requested or when it shortens the critical path. Give every agent explicit file or module ownership, tell agents they share the repository, and require them to accommodate others' changes without reverting them.
- Commit focused checkpoints frequently and push them to the intended pull request. Do not merge while required checks are failing or pending or while Codex review threads remain unresolved.

## CI and Pull Requests

- Prefer GitHub Actions for primary verification and qualification. Use short local checks for fast feedback when practical.
- Do not poll a CI check that is expected to take longer than three minutes. Continue another useful task and check back later.
- Mark pull requests ready for review instead of leaving them as drafts.
- Do not request review from the Codex code review bot; it is added automatically when a commit is pushed to a ready pull request.
- Do not merge a pull request while required CI checks fail or are pending, or until all Codex code review bot reviews are resolved.
- For privileged commands on local hosts, use `doas` instead of `sudo`.

## Agent Orchestration

- Use the orchestration tools for delegated model work. Do not silently substitute a different provider or model when the requested one is unavailable; report the limitation and keep work on tasks that do not depend on it.
- For backend work, use Opus 5.5 for planning and architecture, Sol 6.1 as the integration and review layer between planning and implementation, and Luna for implementation. Prefer Sol 6.1 through orchestration tools over Codex for backend analysis and decisions.
- For frontend work, use Opus 5.5 through Claude Code at low reasoning as the lead for planning and implementation direction. Route to Sonnet 5.5 only when a second implementation pass or review is useful. Luna may implement a bounded frontend task when the Opus-led direction is clear.
- Give each delegated implementation a concrete scope, acceptance criteria, and file ownership. Tell workers that other changes may be in progress; they must preserve and accommodate those changes rather than reverting them.
- Delegate high-detail or high-impact work to the requested planning/review models before implementation. Keep implementation ownership explicit, verify the resulting artifact, and commit at meaningful checkpoints.
- Do not delegate external messages, merges, publication, or other irreversible actions unless the user has authorized that action.
- Any of this may be waived or overridden by an explicit user request.

## Repository Sanity Checks

- Milestone sanity checks cover every repository milestone.
- Before continuing planned work, verify the relevant milestone and issue status, dependencies, acceptance criteria, and current evidence.
- Check that closed issues have evidence matching their full acceptance criteria and intended scope; reopen or correct closure metadata when they were closed improperly.

## Milestone Completion Orchestration

- The active project goal is to finish every open milestone, prioritizing remaining UI milestone work and backend completion. Before implementation, audit all milestones and issues against the repository sanity checks above; work from GitHub's current scope and acceptance criteria, not assumptions.
- Use the T3 orchestration tools for delegated work when available. Check `orchestrator_capabilities` before the first delegation and use only listed provider/model identifiers and supported options. If a requested model/provider is unavailable, report that and do not silently substitute.
- Backend: use Codex `gpt-6.1-sol` as the technical middle layer/reviewer, Claude Opus 5.5 for planning where useful, and Codex `gpt-6-luna` for implementation tasks. Keep Ghidra bundled through Java APIs, isolated worker execution, and authenticated oracle boundaries.
- Frontend/UI: use Claude Opus 5.5 with low effort for planning and implementation direction; use Claude Sonnet 5.5 only where useful and available. Do not substitute backend model routing for UI work.
- Keep delegated tasks scoped to explicit milestone/issue acceptance criteria. Review delegated changes and evidence before landing them. Commit frequently at meaningful checkpoints, referencing the relevant issue, and push when practical.
- Preserve the repository rule against creating files or directories outside its root; do not create worktrees unless that rule is explicitly overridden.
- `CLAUDE.md` must remain a symlink to `AGENTS.md` so Claude Code follows the same repository instructions.
