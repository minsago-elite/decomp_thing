#include "identity_fixture.hpp"

int caller_two(int value) {
    return static_cast<int>(overloaded(static_cast<long>(value))) + overloaded(value) +
        static_cast<int>(template_pattern<long>(static_cast<long>(value + 1))) +
        value_template<3>(value) + value_template<4>(value + 1);
}
