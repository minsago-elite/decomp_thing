#pragma once

#define DECLARE_SAME_LINE_TYPE(NS) namespace NS { struct SameLineType { int value; }; }
DECLARE_SAME_LINE_TYPE(scope_left) DECLARE_SAME_LINE_TYPE(scope_right)
#undef DECLARE_SAME_LINE_TYPE

#define DECLARE_SAME_LINE_UNION(NAME) union NAME { struct Payload { int value; }; };
DECLARE_SAME_LINE_UNION(SameUnionLeft) DECLARE_SAME_LINE_UNION(SameUnionRight)
#undef DECLARE_SAME_LINE_UNION

inline int declaration_only_inline(int value);
template <typename T>
inline T pattern_only(T value);

inline int shared_inline(int value) {
    return value * 3 + 1;
}

inline int callback_target(int value, ...) {
    return value + 1;
}

template <typename T>
__attribute__((noinline)) inline T callback_signature(int (*callback)(int, ...), T value) {
    return static_cast<T>(callback(static_cast<int>(value), 1));
}

inline int nested_leaf(int value) {
    volatile int adjusted = value + 1;
    return adjusted * 3;
}

inline int nested_middle(int value) {
    return nested_leaf(value) + value * 7;
}

inline int nested_root(int value) {
    return nested_middle(value) ^ (value + 17);
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

template <typename T>
__attribute__((noinline)) inline T unique_template_pattern(T value) {
    return value + static_cast<T>(2);
}

template <int Offset, typename T>
__attribute__((noinline)) inline T value_template(T value) {
    return value + static_cast<T>(Offset);
}

template <bool Enabled, typename T>
__attribute__((noinline)) inline T boolean_template(T value) {
    return Enabled ? value + static_cast<T>(1) : value - static_cast<T>(1);
}

enum class IdentityMode : unsigned char {
    small = 3,
    large = 7,
};

template <IdentityMode Mode>
__attribute__((noinline)) inline int enum_template(int value) {
    return value + static_cast<int>(Mode);
}

template <typename... Values>
__attribute__((noinline)) inline int packed_template(Values... values) {
    return (0 + ... + static_cast<int>(values));
}

template <typename T>
__attribute__((noinline)) inline T scoped_type_template(T value) {
    return value;
}

template <typename T>
__attribute__((noinline)) inline T union_scoped_template(T value) {
    return value;
}

extern template int template_pattern<int>(int);
extern template long template_pattern<long>(long);
extern template int unique_template_pattern<int>(int);
extern template long unique_template_pattern<long>(long);
extern template int pattern_only<int>(int);
extern template SameUnionLeft::Payload union_scoped_template<SameUnionLeft::Payload>(SameUnionLeft::Payload);
extern template SameUnionRight::Payload union_scoped_template<SameUnionRight::Payload>(SameUnionRight::Payload);
