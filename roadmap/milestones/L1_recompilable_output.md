# L1: Reconstruct

Goal: compile `c-vul/src/01_out_of_bounds_write.c` and reconstruct its ELF into meaningful editable C.

Done when:

- the generated C represents the fixture's required behavior instead of returning a placeholder value.
- the generated project compiles into an executable.
- the reconstructed executable prints `[03] Alexandria Stone` and exits successfully.
