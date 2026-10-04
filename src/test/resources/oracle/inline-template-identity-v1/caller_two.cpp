#include "identity_fixture.hpp"

int caller_two(int value) {
    return static_cast<int>(overloaded(static_cast<long>(value))) + overloaded(value) +
        static_cast<int>(template_pattern<long>(static_cast<long>(value + 1))) +
        static_cast<int>(unique_template_pattern<long>(static_cast<long>(value))) +
        value_template<3>(value) + value_template<4>(value + 1) + value_template<-1>(value + 2) +
        boolean_template<true>(value) + boolean_template<false>(value + 1) +
        enum_template<IdentityMode::small>(value) + enum_template<IdentityMode::large>(value + 1) +
        packed_template(value, value + 1) + nested_root(value + 1);
}
