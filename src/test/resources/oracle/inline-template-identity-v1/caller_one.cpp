#include "identity_fixture.hpp"

[[maybe_unused]] int (*declaration_only_reference)(int) = &declaration_only_inline;

int caller_one(int value) {
    scope_left::SameLineType left{value};
    scope_right::SameLineType right{value + 1};
    return shared_inline(value) + shared_inline(value + 1) + template_pattern<int>(value) +
        unique_template_pattern<int>(value) + scoped_type_template(left).value + scoped_type_template(right).value +
        nested_root(value);
}
