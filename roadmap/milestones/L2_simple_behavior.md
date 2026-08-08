# L2: Patch

Goal: apply one reviewable source patch for the CWE-787 out-of-bounds write in `01_out_of_bounds_write.c`.

Done when:

- AddressSanitizer reproduces the original stack buffer overflow and the finding maps to reconstructed source.
- a human-approved minimal patch is recorded as a source diff.
- the patched source recompiles with the MVP hardening flags.
