# Repository Conventions

- Commit frequently at meaningful checkpoints, especially before large rewrites, after passing verification, and before switching implementation direction.
- Keep commits focused enough that a failing or unwanted change can be understood and reverted without losing unrelated progress.
- Run the relevant tests or build checks before checkpoint commits when practical, and mention any skipped verification in the commit context.

## Project Planning

- Current user priority is A-series milestones only. Defer new B-, C-, and D-series work unless the user explicitly expands the scope; retain existing work in those series.
- GitHub [milestones](https://github.com/minsago-elite/decomp_thing/milestones) and [issues](https://github.com/minsago-elite/decomp_thing/issues) are the source of truth for planned work and progress.
- Use milestones for project phases or outcomes. Use focused issues with explicit acceptance criteria for actionable work.
- Before starting planned work, check the relevant milestone and issue for current scope, dependencies, and status.
- Keep issue status and acceptance criteria current as work lands, and reference the issue in commits or pull requests when practical.
- Create or update a GitHub issue when new roadmap work is discovered. Do not add planning checklists to `ROADMAP.md`; it is retained only as a deprecated migration pointer.
- Files under `roadmap/` are historical design and benchmark context, not live project status, unless an active issue explicitly references them.
