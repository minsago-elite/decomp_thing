template <class T> struct Box {
  T value;
};

template <class T> struct Box<T *> {
  T *value;
};

template <class T> T identity(T value) { return value; }

template <> int identity<int>(int value) { return value + 1; }

int main() {
  Box<int *> pointerBox{nullptr};
  Box<long> valueBox{7};
  return identity(pointerBox.value == nullptr ? static_cast<int>(valueBox.value) : 0);
}
