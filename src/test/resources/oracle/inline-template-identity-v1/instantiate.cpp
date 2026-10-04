#include "identity_fixture.hpp"

template int template_pattern<int>(int);
template int unique_template_pattern<int>(int);
template long unique_template_pattern<long>(long);

int caller_one(int value);
int caller_two(int value);

int main() {
    return caller_one(1) + caller_two(2);
}
