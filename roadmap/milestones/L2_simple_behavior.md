# L2: Simple Behavioral Match

Goal: match original process behavior for simple programs.

Required gates:

- Hello-world binary passes.
- argv-processing binary passes.
- stdin-processing binary passes.
- exit code/stdout/stderr are compared byte-for-byte.
- sandboxed execution is mandatory.

Acceptance evidence should include sandboxed original-vs-rebuilt runs and byte-for-byte process I/O comparison reports.
