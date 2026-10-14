# Referenced data byte evidence

Program-model schema 3 and exporter 12 preserve raw referenced input windows separately from listing initializer display text. These windows carry no object extent, C type, initializer, oracle, ABI, scoring or release authority.

Each global has required version-1 `byteEvidence` with nonempty `windows` and `omissionReason`. A window identifies the actual reference target address and instruction/reference/operand origin. A positive `requestedLength` comes only from one unambiguous statically associated access in an instruction's raw p-code. The finite supported policy is:

- LOAD output or STORE value size, when the constant pointer and address-space ID exactly match the reference target.
- COPY direct RAM input or output size, when its single input and output sizes agree and the memory address and space exactly match the target.
- FLOAT_ADD or FLOAT_MULT direct RAM value-input size, for a two-input operation with a nonnull output and equal input/output sizes. Either value input can match the exact target address and space; an output aliasing that target is rejected.

Direct reads use the existing `pcode_direct_read` basis and COPY writes use `pcode_direct_write`. More than one matching association, inconsistent sizes, dynamic pointers, or target memory operands in unreviewed opcodes remain unknown. Control-flow destinations do not establish data-read widths. This policy does not infer an object extent, a C type or a full initializer from the access size. An unknown association has null length, `unknown` availability, no segments and `unknown_width` basis. `omissionReason` is `unknown_access_width` exactly when any window has unknown width, otherwise null.

Known windows contain contiguous offset/length segments covering the complete requested span. Available segments carry lowercase address-order hex; unavailable segments carry null hex and an explicit `unmapped`, `unreadable`, `uninitialized` or `read_failed` reason. Available zero bytes remain data. Missing bytes are never filled or silently truncated. Window availability summarizes complete, partial or absent coverage.

The exporter gathers references before publishing first-owner global records. Windows sort by target and origin and exact duplicates collapse, while duplicate inspection work remains charged. Planning and full exports share rendering. Exact global records enter semantic and capture commitments, so local record edits cannot retain an earlier authenticated state.

Limits are 256 requested bytes/window, 32 inspected windows/global, 65,536 requested bytes/model, 4,096 inspected windows/model and 65,536 inspected data reference candidates/model. Requested bytes include missing spans and duplicate occurrence work. Exceeding a bound fails export before completion. Module prompts allow 65,536 decoded available bytes and 524,288 rendered evidence bytes and fail before agent invocation if exceeded. Existing artifact, token, depth, cancellation and execution limits also apply.

Schemas 1 and 2 retain their historical canonical representation and lack byte evidence. A historical global cannot carry `byteEvidence`; schema 3 cannot omit it. Prompts mark historical windows unavailable. Production capture/resume requires schema 3 with exporter 12 and matching staged exporter digest; historical checkpoints require fresh export and are not rewritten.

Active GCC controls are `oracle/gcc/16.2.0/compiler-engines-exporter12.json` and `structural-full-export-profile-exporter12.json`. Their exporter SHA is bound to the staged Java source. The earlier unsuffixed exporter-11 profiles remain historical evidence; loading them as current production controls fails the implementation identity check.

The authored bundled ProgramDB control disassembles MOVSD, ADDSD and MULSD to actual COPY, FLOAT_ADD and FLOAT_MULT p-code. It deliberately defines a one-byte `00h` listing at each referenced constant and checks that export preserves that initializer while retaining all eight leading-zero memory bytes. This controlled listing setup does not establish how an unmodified input is naturally analyzed; natural listing observations and corrected input qualification require separate evidence.

Qualification also includes the bundled public Java API memory probe and an opt-in stripped ELF fixture containing explicit eight-byte loads of raw binary64 0.5, 0.25 and 8.0. The fixture independently checks ELF symbol addresses and PT_LOAD file bytes, then verifies the recovered bytes after stripping. The `bundled-ghidra` Actions job enables the real fixture. Exported bytes establish input availability only; a separate newly frozen experiment is required for any later ACP measurement.
