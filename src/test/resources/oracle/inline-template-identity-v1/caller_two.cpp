#include "identity_fixture.hpp"

int caller_two(int value) {
    return static_cast<int>(overloaded(static_cast<long>(value))) + overloaded(value) +
        static_cast<int>(template_pattern<long>(static_cast<long>(value + 1))) +
        static_cast<int>(unique_template_pattern<long>(static_cast<long>(value))) +
        value_template<3>(value) + value_template<4>(value + 1) + value_template<-1>(value + 2) +
        packed_template(value, value + 1);
}
