# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517 AS bootstrap

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
    && clang-22 --version | sed -n '1p' | grep --fixed-strings '22.1.8' \
    && ld.lld-22 --version | grep --fixed-strings '22.1.8' \
    && rm -rf /var/lib/apt/lists/* /tmp/llvm-snapshot.gpg.key \
    && find /usr/share/keyrings/apt.llvm.org.gpg /etc/apt/sources.list.d/llvm-22.list \
        -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +

# Bootstrap tools remain the reviewed 22.1.8 build tools. The subject and its resource
# headers below are independently locked LLVM 22.1.6 inputs, not the old v1 image.
FROM bootstrap AS resource-builder
WORKDIR /native-build
COPY llvm-project-22.1.6.src.tar.xz /native-build/source.tar.xz
RUN echo '6e0b376a1f6d9873e7dfb09ae6e04b9c7024400f01733fa4c29be69d5c138bc2  /native-build/source.tar.xz' \
        | sha256sum --check --strict \
    && test "$(stat --format='%s' /native-build/source.tar.xz)" = 167043464 \
    && tar --extract --xz --file /native-build/source.tar.xz --directory /native-build \
    && cmake -G Ninja -S /native-build/llvm-project-22.1.6.src/llvm -B /native-build/build \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DLLVM_ENABLE_PROJECTS=clang -DLLVM_TARGETS_TO_BUILD=X86 \
        -DLLVM_INCLUDE_TESTS=OFF -DCLANG_INCLUDE_TESTS=OFF \
        -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_INCLUDE_EXAMPLES=OFF \
        -DLLVM_BUILD_EXAMPLES=OFF -DLLVM_ENABLE_BINDINGS=OFF \
        -DLLVM_ENABLE_TERMINFO=OFF -DLLVM_ENABLE_LIBXML2=OFF \
        -DLLVM_ENABLE_ZSTD=OFF -DLLVM_ENABLE_CURL=OFF \
        -DLLVM_ENABLE_HTTPLIB=OFF -DLLVM_ENABLE_LIBEDIT=OFF \
        -DLLVM_ENABLE_ASSERTIONS=OFF -DLLVM_ENABLE_RTTI=OFF \
        -DCMAKE_C_COMPILER=/usr/lib/llvm-22/bin/clang \
        -DCMAKE_CXX_COMPILER=/usr/lib/llvm-22/bin/clang++ \
        -DCMAKE_AR=/usr/lib/llvm-22/bin/llvm-ar \
        -DCMAKE_RANLIB=/usr/lib/llvm-22/bin/llvm-ranlib \
        '-DCMAKE_EXE_LINKER_FLAGS=-fuse-ld=lld -Wl,--build-id=sha1 -Wl,--compress-debug-sections=zlib' \
        '-DCMAKE_SHARED_LINKER_FLAGS=-fuse-ld=lld -Wl,--build-id=sha1 -Wl,--compress-debug-sections=zlib' \
        '-DCMAKE_C_FLAGS_RELWITHDEBINFO=-Oz -g2 -DNDEBUG -ffile-prefix-map=/native-build=/usr/src/llvm-native-runtime' \
        '-DCMAKE_CXX_FLAGS_RELWITHDEBINFO=-Oz -g2 -DNDEBUG -ffile-prefix-map=/native-build=/usr/src/llvm-native-runtime' \
    && cmake --build /native-build/build --target clang-resource-headers -- -j4 \
    && cmake --install /native-build/build --component clang-resource-headers --prefix /native-build/install \
    && test -s /native-build/install/lib/clang/22/include/stddef.h \
    && test -s /native-build/install/lib/clang/22/include/stdarg.h \
    && test -s /native-build/install/lib/clang/22/include/limits.h \
    && install -D -m 0444 /native-build/llvm-project-22.1.6.src/LICENSE.TXT \
        /native-build/install/licenses/llvm-LICENSE.TXT \
    && install -D -m 0444 /native-build/llvm-project-22.1.6.src/clang/LICENSE.TXT \
        /native-build/install/licenses/clang-LICENSE.TXT \
    && find /native-build/install -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +

FROM bootstrap AS runtime-measurement-candidate
COPY --chmod=0755 clang-driver.stripped /subject/executable
# Fixed v2 argv0 is /subject/executable. Its default ../lib/clang/22 resource
# location resolves through Ubuntu's /lib -> /usr/lib container-root symlink.
# Keep the subject resource directory distinct from any 22.1.8 package link/tree.
RUN test -d /usr/lib/clang && test ! -L /usr/lib/clang \
    && rm -rf -- /usr/lib/clang/22 \
    && install -d -m 0755 /usr/lib/clang/22
COPY --from=resource-builder /native-build/install/lib/clang/22 /usr/lib/clang/22
COPY --from=resource-builder /native-build/install/licenses /decomp-native-build/licenses
COPY native-runtime-measurement-v2.Dockerfile /decomp-native-build/native-runtime-measurement-v2.Dockerfile
RUN echo '65e57857bfaf9f98a552f2fd371938e11175158bc4c11c849bd6ecbfef30c006  /subject/executable' \
        | sha256sum --check --strict \
    && test "$(stat --format='%s' /subject/executable)" = 84561368 \
    && test -x /usr/bin/env \
    && test -x /usr/bin/ld \
    && test -x /usr/lib/llvm-22/bin/lld \
    && test -s /lib/clang/22/include/stddef.h \
    && test -s /lib/clang/22/include/stdarg.h \
    && find /subject /usr/lib/clang/22 /decomp-native-build \
        -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} +
LABEL org.decompengine.native-runtime.role="unapproved-measurement-candidate" \
      org.decompengine.native-runtime.subject-version="22.1.6" \
      org.decompengine.native-runtime.bootstrap-tools-version="22.1.8" \
      org.decompengine.native-runtime.start-authorized="false"
