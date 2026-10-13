inline int unique_source_pattern(int value) {
    return value * 7 + 13;
}

int unique_source_caller(int value) {
    return unique_source_pattern(value);
}
