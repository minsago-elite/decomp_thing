#pragma once

inline int declaration_only_inline(int value);
template <typename T>
inline T pattern_only(T value);

inline int shared_inline(int value) {
    return value * 3 + 1;
}

inline long overloaded(long value) {
    return value + 3L;
}

inline int overloaded(int value) {
    return value + 4;
}

template <typename T>
inline T template_pattern(T value) {
    return value + static_cast<T>(1);
}

template <int Offset, typename T>
__attribute__((noinline)) inline T value_template(T value) {
    return value + static_cast<T>(Offset);
}

extern template int template_pattern<int>(int);
extern template long template_pattern<long>(long);
extern template int pattern_only<int>(int);
