# Archival reconstruction corpus

These repository-authored synthetic programs exercise small and larger source-tree reconstruction without importing third-party code. `manifest.json` records provenance, redistribution terms, build variants, input surfaces, expected scale, and source hashes.

`binaries/linux-x86_64/` contains the versioned symbol-bearing and stripped ELF fixtures used as stable archival inputs. Their hashes and compiler characteristics are recorded in the manifest; CI also recompiles the sources to exercise the current toolchain.

The large fixture deliberately exposes several named subsystems and shared state. CI also expands the same pattern to more than 100 recovered functions to test bounded module partitioning, clean archival rebuilds, and behavior comparison at project scale.
