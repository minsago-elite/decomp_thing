"""LLVM/Clang adapter for generic function-oracle generation."""

from typing import Any

from oracle.function_recovery_profile_oracle import generate_profile_oracle


def _driver_symbol(name: str) -> bool:
    return name in {"main", "clang_main"} or name.startswith("_ZN5clang6driver")


def _driver_compilation_unit(path: str) -> bool:
    return "/clang/lib/Driver/" in path or path.endswith(
        "/clang/tools/driver/driver.cpp"
    )


def generate_llvm_profile_oracle(**arguments: Any) -> dict[str, Any]:
    """Generate a bounded profile of Clang's driver implementation."""

    return generate_profile_oracle(
        **arguments,
        symbol_name_selector=_driver_symbol,
        compilation_unit_selector=_driver_compilation_unit,
        include_inline_only=False,
    )
