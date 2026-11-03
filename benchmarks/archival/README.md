# Archival reconstruction corpus

These repository-authored synthetic programs exercise small and larger source-tree reconstruction without importing third-party code. `manifest.json` records provenance, redistribution terms, build variants, input surfaces, expected scale, and source hashes.

`binaries/linux-x86_64/` contains the versioned symbol-bearing and stripped ELF fixtures used as stable archival inputs. Their hashes and compiler characteristics are recorded in the manifest; CI also recompiles the sources to exercise the current toolchain.

The large fixture deliberately exposes several named subsystems and shared state. CI also expands the same pattern to more than 100 recovered functions to test bounded module partitioning, clean archival rebuilds, and behavior comparison at project scale.

`large_project_mtu/` is the deterministic multi-translation-unit profiling fixture. It has
seven ordered C translation units and one shared header; the pinned binaries and each source
hash are recorded in `manifest.json`. Rebuild the symbol-bearing binary from the repository
root with the manifest's link order:

```sh
gcc -std=c11 -O2 -fPIE -pie -Wl,--build-id=none -Ibenchmarks/archival/large_project_mtu \
  benchmarks/archival/large_project_mtu/main.c \
  benchmarks/archival/large_project_mtu/parse.c \
  benchmarks/archival/large_project_mtu/render.c \
  benchmarks/archival/large_project_mtu/state.c \
  benchmarks/archival/large_project_mtu/io.c \
  benchmarks/archival/large_project_mtu/measure.c \
  benchmarks/archival/large_project_mtu/report.c \
  -o benchmarks/archival/binaries/linux-x86_64/large_project_mtu-symbols
cp benchmarks/archival/binaries/linux-x86_64/large_project_mtu-symbols \
  benchmarks/archival/binaries/linux-x86_64/large_project_mtu-stripped
strip --strip-all benchmarks/archival/binaries/linux-x86_64/large_project_mtu-stripped
```
