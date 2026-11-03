# Archival reconstruction corpus

These repository-authored synthetic programs exercise small and larger source-tree reconstruction without importing third-party code. `manifest.json` records provenance, redistribution terms, build variants, input surfaces, expected scale, and source hashes.

`binaries/linux-x86_64/` contains the versioned symbol-bearing and stripped ELF fixtures used as stable archival inputs. Their hashes and compiler characteristics are recorded in the manifest; CI also recompiles the sources to exercise the current toolchain.

The large fixture deliberately exposes several named subsystems and shared state. CI also expands the same pattern to more than 100 recovered functions to test bounded module partitioning, clean archival rebuilds, and behavior comparison at project scale.

`large_project_mtu/` is the profiling-scale variant: six separately compiled translation units share `shared.h`, and the manifest pins their link order (`main.c`, `state.c`, `parser.c`, `renderer.c`, `store.c`, `util.c`). Its symbol-bearing and stripped PIE inputs are intended for resumed-analysis timing and per-module invalidation experiments. Rebuild with `gcc -Wall -Wextra -std=c11 -O2 -fPIE -pie -Wl,--build-id=none` followed by those source paths in the pinned order.
