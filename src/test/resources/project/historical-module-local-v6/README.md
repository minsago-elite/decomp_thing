# Historical local module compilation fixtures

These two small projects preserve schema-6 acceptance under the historical `generated-c-module-validation-v2` host compiler. They are fixtures for archive parsing, tamper rejection, and restoration of previously accepted bytes. They do not authorize schema-7 acceptance, contained compiler execution, whole-program equivalence, or independent-agent qualification.

Each project has one `parse_input` implementation, an authored ACP receipt from the existing archive-test harness, and a real successful local module compile and project build. The ACP receipt is authored test evidence; no external agent executed it. Make and Ninja are retained separately because the profile is part of the recorded identity.

`provenance.json` pins the archive bytes, source, checkpoint, receipt, selected profile, six-field compiler record, and relevant producer source files. The acceptance-path base revision is `920f4e316ddadbe0996aa4e46c7796427c01542f`. Those 11 producer files matched that commit during capture. Concurrent unselected contained-runtime work was present in the shared worktree, so this is not a claim that the complete build was from a clean checkout or was hermetic.

Capture ran the temporary `HistoricalCompilationFixtureCaptureTest` through an isolated Gradle test task with the old default compiler still selected. The test required schema 6, the exact six historical compiler fields, local policy v2, accepted source, and a passing project build before packaging. It refused existing fixture paths and capped each archive at 256 KiB. The executable capture test was removed afterward; its source hash is retained in the provenance.

Preserve these bytes when testing the historical contract. New successful acceptance tests must use the actual contained runtime and obtain a live compiler permit from real execution.
