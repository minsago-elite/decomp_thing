# Clang 18.1.3 parser fixtures

`llvmorg-18.1.3-LangOptions.def` and `llvmorg-18.1.3-LangOptions.h` are the
public GitHub file contents at the LLVM `llvmorg-18.1.3` tag, paths
`clang/include/clang/Basic/LangOptions.def` and
`clang/include/clang/Basic/LangOptions.h` respectively. Their Git blob object
IDs are `4942dcaa086eaca931fc7dfb55e0f85936d1855e` and
`c1cc5548ef10c0fcf1467109e31c916510b52900`.

These checked-in files exercise the parser against the exact public tag text,
including the real `setLangDefaults` default argument. They are regression
fixtures only: fetching public tag content does not authenticate the release
source archive and is not provenance evidence for an accepted toolchain build.
The provisioning contract still requires its separate signed acquisition and
source audit before acceptance.
