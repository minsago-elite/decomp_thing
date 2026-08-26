# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

# The official image is itself built from the locked GCC 16.2.0 release. The
# index digest is pinned and every build/run selects linux/amd64 explicitly.
FROM gcc@sha256:2e6f4ae27ab8ad6f9617b46f0468889d368fdd91f2ea29aff98e4d5d1a3637f0 AS dependency-extractor

ARG DEBIAN_FRONTEND=noninteractive

# Fetch the only missing development headers from an immutable Debian
# snapshot, verify the exact package bytes, and extract them without mutating
# package-manager state in the final image. The official base already contains
# the matching runtime libraries and GMP development package.
WORKDIR /tmp/dependencies
RUN sed -i \
        -e 's|http://deb.debian.org/debian-security|https://snapshot.debian.org/archive/debian-security/20260824T000000Z|g' \
        -e 's|http://deb.debian.org/debian|https://snapshot.debian.org/archive/debian/20260824T000000Z|g' \
        /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get download \
        libmpc-dev=1.3.1-1+b3 \
        libmpfr-dev=4.2.2-1 \
    && echo '01927983fa7a448180a0162e73619a1e8ad47839cea2b6dcc31c304b903e7fc0  libmpc-dev_1.3.1-1+b3_amd64.deb' | sha256sum --check --strict \
    && echo '43cbe73a48cce65232ad5d4219a67dfdd0974f45aa88d381ae051d64052b996a  libmpfr-dev_4.2.2-1_amd64.deb' | sha256sum --check --strict \
    && dpkg-deb --extract libmpc-dev_1.3.1-1+b3_amd64.deb /toolchain \
    && dpkg-deb --extract libmpfr-dev_4.2.2-1_amd64.deb /toolchain \
    && cp /usr/lib/x86_64-linux-gnu/libmpc.so.3.3.1 /toolchain/usr/lib/x86_64-linux-gnu/ \
    && cp /usr/lib/x86_64-linux-gnu/libmpfr.so.6.2.2 /toolchain/usr/lib/x86_64-linux-gnu/

FROM gcc@sha256:2e6f4ae27ab8ad6f9617b46f0468889d368fdd91f2ea29aff98e4d5d1a3637f0

ARG SOURCE_DATE_EPOCH=1786060800

# A single final layer copies only the verified headers, linker names, matching
# runtime objects, and notices. Explicit mtimes make the final layer digest
# independent of the package download/extraction clock in the discarded stage.
RUN --mount=from=dependency-extractor,source=/toolchain,target=/toolchain,ro \
    install -m 0644 /toolchain/usr/include/mpc.h /usr/include/mpc.h \
    && install -m 0644 /toolchain/usr/include/mpf2mpfr.h /usr/include/mpf2mpfr.h \
    && install -m 0644 /toolchain/usr/include/mpfr.h /usr/include/mpfr.h \
    && cp -a /toolchain/usr/lib/x86_64-linux-gnu/libmpc.so* /usr/lib/x86_64-linux-gnu/ \
    && cp -a /toolchain/usr/lib/x86_64-linux-gnu/libmpfr.so* /usr/lib/x86_64-linux-gnu/ \
    && cp -a /toolchain/usr/share/doc/libmpc-dev /usr/share/doc/ \
    && cp -a /toolchain/usr/share/doc/libmpfr-dev /usr/share/doc/ \
    && find \
        /usr/include/mpc.h \
        /usr/include/mpf2mpfr.h \
        /usr/include/mpfr.h \
        /usr/lib/x86_64-linux-gnu/libmpc.so \
        /usr/lib/x86_64-linux-gnu/libmpc.so.3.3.1 \
        /usr/lib/x86_64-linux-gnu/libmpfr.so \
        /usr/lib/x86_64-linux-gnu/libmpfr.so.6.2.2 \
        /usr/share/doc/libmpc-dev \
        /usr/share/doc/libmpfr-dev \
        -exec touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" {} + \
    && touch --no-dereference --date="@${SOURCE_DATE_EPOCH}" \
        / /etc /usr /usr/include /usr/lib /usr/lib/x86_64-linux-gnu /usr/share /usr/share/doc
