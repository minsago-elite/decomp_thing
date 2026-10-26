# Issue 1506 corrected real window validation (Sol)

The corrected frozen exporter passes the same stripped ELF fixture that failed the prior reproduction. Exactly three reference windows now have the original exact addresses, requestedLength 8, availability `available`, the complete independently inspected bytes including leading zeros, and omissionReason `null`. Their width origin is truthfully `pcode_direct_read`, matching actual bundled-Ghidra direct-memory COPY operations.

| Object | Window/reference address | Origin instruction | Length | Exact available segment hex |
| --- | --- | --- | --- | --- |
| half_value | `0x402000` | `0x401000` | 8 | `000000000000e03f` |
| quarter_value | `0x402008` | `0x401008` | 8 | `000000000000d03f` |
| eight_value | `0x402010` | `0x401010` | 8 | `0000000000002040` |

Every window has operandIndex 1 and a single offset-0, length-8 available segment with reason `null`. The model schema is 3, byte-evidence schema is 1, and model inputSha256 matches the analyzed file. No exact-address, eight-byte length, payload, or leading-zero requirement was relaxed. The first actual exported row is:

```json
{"address":"0x402000","requestedLength":8,"origin":{"instructionAddress":"0x401000","referenceAddress":"0x402000","operandIndex":1,"widthBasis":"pcode_direct_read"},"availability":"available","segments":[{"offset":0,"length":8,"availability":"available","hex":"000000000000e03f","reason":null}]}
```

The stripped binary SHA256 and complete raw instruction/p-code probe SHA256 are identical to the earlier failing reproduction. That run exported null lengths for these same direct-memory accesses; the corrected source now associates their exact RAM input varnodes and sizes. The raw probe again identifies x86:LE:64:default, ram space ID 433, and COPY inputs `(ram, 0x402000, 8)`, `(ram, 0x402008, 8)`, and `(ram, 0x402010, 8)`. This holds the input and observed p-code constant while changing the exporter.

## Freeze and execution

All bounded run receipts, source copies, classes, input, project, export state and runtime state are below `build/issue1506-corrected-real-window-validation/`. This report is the only new file outside that owned run directory. No production/test source, Git state, remote/CI state, auth/model/candidate/original input, or prior evidence artifact was changed.

The source owner stopped at `build/issue1506-corrections/source-freeze-013.json` in `.claude/worktrees/issue-1506-referenced-bytes`. The manifest SHA256 is `a5b5bfd54cc7b4c403899e37b509565a35205c206e343cd150b546d60fef0532`, based on `87050ae41a246547a4364c7971ba9e07de380408`. Every one of its 23 present/deleted path states and file hashes was checked before and after this run. The corrected exporter was copied only after verifying its frozen SHA256; all 23 manifest states remained unchanged.

The fixture assembly comes from the original failing revision's exact test snapshot, retained unchanged from the prior reproduction. Existing gcc compiled it using the same `-nostdlib -no-pie -Wl,-e,probe` recipe. Existing readelf confirmed the size-one symbol declarations and addresses. Independent Python ELF PT_LOAD mapping verified all three complete eight-byte payloads before existing strip removed all symbols. The resulting stripped input is byte-identical to the earlier diagnostic input. The binary was analyzed, never executed.

The corrected actual `ExportProgramModel.java` was compiled with existing javac against the same 153 pinned bundled-Ghidra JARs. The unchanged inert Java driver initializes `GhidraApplicationLayout` and `HeadlessAnalyzer` through Java APIs, runs compiled `ExportProgramModel.class` in full mode, then runs the unchanged bounded raw p-code probe. No external analyzeHeadless, GHIDRA_HOME, Gradle, new package, or production worker class was used. Analysis completed with process exit zero within the unchanged 120-second timeout; javac was bounded to 60 seconds, fixture/tool commands to 30 seconds. `commands.json` retains precise argument arrays and deadlines. `validation-result.json` records the exact address/length/payload assertions, and `analysis.log` records successful import, analysis, export and raw probe execution.

HOME, TMPDIR/TMP/TEMP, XDG config/cache/data/state/runtime, java.io.tmpdir, jna.tmpdir, user.home and both Java preferences roots were explicitly placed below the run directory. Both Java and javac received `-XX:-UsePerfData`; inherited Java option variables and GHIDRA_HOME were removed. Python used `-B`. Ghidra logs confirm contained application logs/preferences/caches/project paths. Source, class, input and tools were hashed before analysis and verified after it.

## Integrity receipts

The existing archive SHA256 `93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54` was independently checked again. All 5,218 extracted release files, including native tools/libraries, were verified by size and SHA256 against their archive members before execution and hash checked after it. The complete release file inventory had no additions. The 153 classpath JARs were separately recorded. All 452 files in the existing JDK tree were hashed before and checked after. Existing java/javac/gcc/strip/readelf executable identities plus gcc-selected cc1, assembler, collect2 and linker executable identities were also recorded before and checked after; these receipts do not claim to freeze every host shared library. The exporter, driver/probe, other diagnostic source copies, compiled classes and exact stripped input were unchanged across execution.

Paths below are relative to the run directory. The equal before/after digests refer to actual hash revalidation, not an assumption of immutability.

| Artifact | SHA256 |
| --- | --- |
| `source-freeze-013.json` | `a5b5bfd54cc7b4c403899e37b509565a35205c206e343cd150b546d60fef0532` |
| `src/ExportProgramModel.java` | `4546507e7d20a6eb1ac766edcfc7d8041b4f2a294e35232902f8bda1e667512b` |
| `classes/ExportProgramModel.class` | `0cb603de055a0c71956d506ebfb1020398f7e7b86e8907b63e56a88699b0e8e3` |
| original `src/ReferencedDataBytesRealGhidraTest.kt` snapshot | `9f61ea2ebc2d3881b1f33d44df311ca9b782dacbc5309cf16784a0e3cbdc50c6` |
| `src/WindowReproDriver.java` | `6366393ae9748be118dcb6184d7e9c87222d376c4585985edcf91662abc33b88` |
| `src/WindowPcodeProbe.java` | `a78e8826e2bfc3efb279591697a309dbeba7760ecca0ad81e07d7d8a03e31e44` |
| `reproduce.py` | `edb5abba1c38bf2957d28a2560d622639dc081e11f3dbc8391c66efcb75b6d17` |
| `release-before.json`, `release-after.json` | `446449fa693332c5db44204e6ae8c89e8722272d72531a1bbc8d78db18aefe8d` |
| `classpath.json` | `9b62b665fa26ee9721d488a2fad35f33764d192bf3a3553a322ea53b888fbc02` |
| `compiled-before.json` | `0ec9b6e02f21cb9582020e642da5f892a1610f8a26f5f0510d36104e0b62c0ec` |
| `tools-before.json` | `a136b503f413914f4f9179dc4df7589c87269b8fc5857a378dfa39051174f16e` |
| `jdk-runtime-before.json`, `jdk-runtime-after.json` | `69e2deca483065e6d170b6499df19d39006de60370a128c0da8bfea162a9e89b` |
| `compiler-native-before.json`, `compiler-native-after.json` | `83025786b0585ed3c0498f49034c10b63a828e6803c67923be1455e41d8e58bc` |
| `source-before.json`, `source-after.json` | `554c344621a2694ce9b328f46a9f98375ef7278586ec9dea8864ed56f0adc047` |
| `frozen-source-before.json`, `frozen-source-after.json` | `e5b97c5f5523444e60359c60f0252e228a1c44a7b97366450e3a87cdd7090d59` |
| `commands.json` | `cd28b613cabdcd5e6c84c7f7519cdef1e8a34cf603c924a7f3dd0489e3509dec` |
| stripped `fixture` | `0ccdde14c026f0543a2521dfb3f8db2526e226a128c7d521cda34096bdb9a09b` |
| `output/program_model.json` | `2be9b71046f394ea1bf3b1b7da23b1ba024713d824e93f9cc2c0e597bd18003a` |
| `output/pcode.txt` | `2cabcd9f549f204b1c8aecd988cb1c5d846fdb299f55c5de53dd238a1a19465a` |
| `observed-windows.json` | `2a9de674d65b356b5a0c0bfde6b1c4394964418bf3ff825fd36247dbb1c6571b` |
| `validation-result.json` | `11d187ae4d54f597c722853db1edb54918a34440fa42809eb7de8fa79f84f437` |
| `integrity-after.json` | `e3f31937bc6282338358c0be598b3dffa56b8888dcd202967ad0fcd9bcd7f34c` |
| `artifact-manifest.json` | `b3fbadb741486ec56310f494e28aecccc089699000c0f6ea4e43ddfa547e9f2b` |

The final artifact manifest hashes 99 retained files totaling 11,949,117 bytes and excludes itself.

## Limits

This qualifies the corrected actual exporter class against the exact public stripped ELF input and actual bundled Ghidra analysis. It does not execute the Kotlin model/parser classes, production wrapper, complete JUnit test, planning mode, prompt, auth/oracle/model/candidate workflow, private original input, or hosted CI. The supplied analysis-tool binding is the verified release inventory digest for this isolated diagnostic. Independent source review and coordinator-owned remaining gates are separate.

The natural stripped analysis produced `undefined8` globals with initializers `3FE0000000000000h`, `3FD0000000000000h`, and `4020000000000000h`. The ELF symbols declared size one before stripping, which does not imply the stripped listing has size one. No authored ProgramDB/listing changes were made or executed here. The separate controlled Undefined1DataType/`00h` fixture must be described as an authored one-byte listing control; this run supplies no claim that unmodified ELF analysis yields that listing.
