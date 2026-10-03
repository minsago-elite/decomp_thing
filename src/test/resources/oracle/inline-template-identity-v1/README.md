# Inline and template identity fixture

`FullTreeSourceEntityIdentityProducerTest` compiles these translation units with GCC and Clang at
`-O0` and `-O2`, records `readelf --debug-dump=info --wide` output, and checks the emitted DIE shape
before interpreting source-identity facts. The test requires GCC and requires Clang in the dedicated
`validate-clang.sh` CI lane.

Compiler output differs. A declaration, template instance, or inline instance is expected only when
that compiler emitted the corresponding DIE. In particular, the declaration of
`declaration_only_inline` and the uninstantiated `pattern_only` template can be absent; the test
rejects a fabricated census row in those cases. GCC emits more template instance forms than Clang
for this fixture. Missing template-pattern references remain unknown, even when the displayed DIE
names look related; the extractor does not infer a relationship from names.

`unique_pattern.cpp` supplies a positive compiler-emitted pattern/instance edge: each compiler's
optimized DWARF contains one `DW_TAG_inlined_subroutine` with a resolved `DW_AT_abstract_origin`
targeting `unique_source_pattern`. The test requires exactly one observable inline fact with no
candidate collision for this relationship. This is fixture evidence only; it does not qualify
production behavior.

`value_template` is marked `noinline` so both non-type actual values remain represented by concrete
template DIEs at `-O2`. The test checks that the values remain distinct and validates unknown,
ambiguous, non-scoreable, and emitted-RVA-linked cases without adding source rows to the RVA
denominator.
