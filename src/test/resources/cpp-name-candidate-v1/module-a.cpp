namespace engine {

struct Meter {
    int operator+(const Meter& other) const;
    int operator-(const Meter& other) const;
    operator int() const;
};

int convert(int value);
int convert(double value);

namespace {
int helper() { return 7; }
}

int next_counter() {
    static int state = 0;
    return helper() + ++state;
}

} // namespace engine
