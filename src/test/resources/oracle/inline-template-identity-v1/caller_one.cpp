#include "identity_fixture.hpp"

[[maybe_unused]] int (*declaration_only_reference)(int) = &declaration_only_inline;

int caller_one(int value) {
    return shared_inline(value) + shared_inline(value + 1) + template_pattern<int>(value);
}
