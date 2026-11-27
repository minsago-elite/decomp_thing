namespace engine {

int convert(const char* value);

namespace {
int helper() { return 11; }
}

int use_helper() { return helper(); }

} // namespace engine
