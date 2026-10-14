# Callable evaluator v2 reviewed source archive

This is a byte-identical, non-live archive of the public portion of preparation 002. It does not relocate or qualify a runtime. The checkpoint JSON maps every archived file to its original and sealed source path and SHA256. Restore reviewed source into a new isolated scratch namespace before any later use; private inputs and pinned tools are separate local dependencies.

Twenty focused tests and all 30 preflight controls pass. Five compatible controls each match all 24 scenarios; behavior and bounded failure controls remain separate. Refused interfaces and private-include attempts never load or call the candidate. Constructor failure controls deliberately execute constructors and retain load failure, with zero API calls.

Preparation 002 is prepared-no-model-call, with distinct source/preflight acceptance and post-create integrity reviews. Preparation 001 is preserved but superseded and unusable after the host-probe exposure was found. Candidate helper probes are now isolated; actual retained synthetic sentinel denials include macro-emitted include directives and the compile-failed/probe-attempted path.

Full private fixtures, expected declarations, generated controls, observations, raw reviews and binaries are excluded. The two generic Python tests have documented local private-input/tool prerequisites; this archive is not a portable public qualification suite. No historical candidate execution, new model/authentication call, behavior accuracy claim, structural score or production authority is included. Referenced-byte evidence is not bound for a new trial.

The source archive preserves the sealed `bounded_runtime.py` trailing blank line. The exact-byte hash check takes precedence over normalizing that historical EOF; whitespace verification disables only blank-at-EOF reporting, without changing repository policy.
