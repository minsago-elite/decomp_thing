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

`unique_pattern.cpp` supplies a positive ordinary inline-origin edge: each compiler's optimized
DWARF contains one `DW_TAG_inlined_subroutine` with a resolved `DW_AT_abstract_origin` targeting
`unique_source_pattern`. This validates the inline reference path only; it is not generic-template
proof. Official DWARF 5 §2.23 describes concrete template instantiations, not a portable generic
template definition. GCC 14.2 and Clang 19.1 emit concrete function-template instances for the
primary-template fixture but no validated DWARF reference from those instances to a generic
function-template pattern. A concrete instance with complete source context, signature, and ordered
typed actuals may still have its own semantic candidate; the absent pattern relation remains null
and explicitly unknown. That candidate does not prove equivalence, authorize deduplication, or
establish generic-pattern identity. Authenticated source/frontend proof is scoped separately in
#1470, and #876 remains open for that requirement. All artifact evidence is fixture-only and does
not qualify production behavior.

`value_template` is marked `noinline` so both non-type actual values remain represented by concrete
template DIEs at `-O2`. The test checks that the values remain distinct and validates unknown,
ambiguous, non-scoreable, and emitted-RVA-linked cases without adding source rows to the RVA
denominator.

The compiler matrix also keeps cross-compiler spelling differences out of template-instance
candidates by hashing validated typed actuals with the base name only when the rendered trailing
template-id is balanced and its top-level argument count matches those typed DIE facts. Malformed,
unbalanced, or mismatched suffixes remain unknown, and the original `DW_AT_name` is retained in the
census. `packed_template` checks that GNU formal-parameter pack
wrappers are flattened to the same ordered signature shape as direct parameters while template
actual pack paths remain evidence. `callback_signature` exercises bounded return/parameter and
variadic descriptions of `DW_TAG_subroutine_type`. Same-line `Payload` types nested in distinct
unions ensure union lexical scopes remain part of typed source descriptors and instance candidates.

`boolean_template` adds a positive `bool` non-type actual control. Both `false` and `true` concrete
instances must retain ordered typed arguments and distinct candidate hashes. This compiler fixture
backs the boolean form decoder; its type/value decoding is still bounded source evidence, not
production qualification. Cross-CU `DW_FORM_ref_addr` acceptance and invalid target-boundary
rejection are also tested with a separate handcrafted two-CU DWARF byte stream. That parser control
is explicitly synthetic and is not described as compiler-emitted cross-CU evidence.
