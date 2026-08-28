# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517

ARG DEBIAN_FRONTEND=noninteractive
ARG SOURCE_DATE_EPOCH=1779182222
ARG LLVM_PACKAGE_VERSION=1:22.1.8~++20260714014902+ca7933e47d3a-1~exp1~20260714135019.80

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates cmake curl gnupg ninja-build python3 xz-utils zlib1g-dev \
    && curl --fail --silent --show-error https://apt.llvm.org/llvm-snapshot.gpg.key \
        --output /tmp/llvm-snapshot.gpg.key \
    && echo '8b2a587ffd672c4687e7581dad4b2f6c1bb2ad6b480cd9771ba2ff48e0b8c75d  /tmp/llvm-snapshot.gpg.key' \
        | sha256sum --check --strict \
    && gpg --batch --dearmor --output /usr/share/keyrings/apt.llvm.org.gpg \
        /tmp/llvm-snapshot.gpg.key \
    && echo 'deb [signed-by=/usr/share/keyrings/apt.llvm.org.gpg] https://apt.llvm.org/noble/ llvm-toolchain-noble-22 main' \
        > /etc/apt/sources.list.d/llvm-22.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        "clang-22=${LLVM_PACKAGE_VERSION}" \
        "lld-22=${LLVM_PACKAGE_VERSION}" \
        "llvm-22=${LLVM_PACKAGE_VERSION}" \
    && test "$(clang-22 --version | sed -n '1p')" = 'Debian clang version 22.1.8 (++20260714014902+ca7933e47d3a-1~exp1~20260714135019.80)' \
    && test "$(ld.lld-22 --version)" = 'Debian LLD 22.1.8 (compatible with GNU linkers)' \
    && rm -rf /var/lib/apt/lists/* /tmp/llvm-snapshot.gpg.key \
    && find /usr/share/keyrings/apt.llvm.org.gpg /etc/apt/sources.list.d/llvm-22.list \
        -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +
