# L0: Skeleton

Goal: the project can accept a binary and create a visible analysis job.

Required gates:

- Web UI uploads ELF.
- Backend stores job.
- Basic metadata extraction works.
- Job state is visible.

Acceptance evidence should come from integration tests that upload a fixture ELF, verify persistence, verify extracted metadata, and verify the UI/API exposes the job state.
