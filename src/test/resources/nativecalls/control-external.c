extern int puts(const char *);
__attribute__((noinline)) int external_call(void) { return puts("native-call-control"); }
int main(void) { return external_call(); }
