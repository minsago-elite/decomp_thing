#include "identity_fixture.hpp"

[[maybe_unused]] int (*declaration_only_reference)(int) = &declaration_only_inline;

int caller_one(int value) {
    scope_left::SameLineType left{value};
    scope_right::SameLineType right{value + 1};
    SameUnionLeft::Payload unionLeft{value};
    SameUnionRight::Payload unionRight{value + 1};
    return shared_inline(value) + shared_inline(value + 1) + template_pattern<int>(value) +
        unique_template_pattern<int>(value) + scoped_type_template(left).value + scoped_type_template(right).value +
        union_scoped_template(unionLeft).value + union_scoped_template(unionRight).value +
        callback_signature(callback_target, value) + nested_root(value);
}
