# L3: Trace-Guided Repair

Goal: use runtime diffs to improve generated source.

Required gates:

- Failed validation cases produce structured diffs.
- OpenRouter repair loop can patch compile errors.
- OpenRouter repair loop can patch behavior mismatches.
- Regression tests are retained.
- iteration history is visible in UI.

Acceptance evidence should include before/after repair attempts, structured diffs, and regression cases retained after fixes.
