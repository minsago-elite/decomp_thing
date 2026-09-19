# syntax=docker/dockerfile:1

FROM eclipse-temurin:21-jdk-jammy@sha256:55fb9bf738f9b5d9b4a6c01b39337e3070d3e27370dd3c478fd1d5d3cd2233c6d8 AS toolchain

ARG ANGR_VERSION=9.2.213
ARG BUBBLEWRAP_VERSION=0.11.2
ARG BUBBLEWRAP_SHA256=69abc30005d2186baf7737feacd8da35633b93cf5af38838ecff17c5f8e924f6

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        build-essential \
        ca-certificates \
        clang \
        curl \
        libcap-dev \
        libselinux1-dev \
        libseccomp-dev \
        meson \
        ninja-build \
        python3 \
        python3-pip \
        tar \
        unzip \
        xz-utils \
    && curl --fail --location --silent --show-error --retry 3 \
        --output /tmp/bubblewrap.tar.xz \
        "https://github.com/containers/bubblewrap/releases/download/v${BUBBLEWRAP_VERSION}/bubblewrap-${BUBBLEWRAP_VERSION}.tar.xz" \
    && printf '%s  %s\\n' "${BUBBLEWRAP_SHA256}" /tmp/bubblewrap.tar.xz | sha256sum --check --strict \
    && mkdir -p /tmp/bubblewrap-src \
    && tar -xJf /tmp/bubblewrap.tar.xz --strip-components=1 -C /tmp/bubblewrap-src \
    && meson setup /tmp/bubblewrap-build /tmp/bubblewrap-src --prefix=/usr/local --buildtype=release \
    && meson compile -C /tmp/bubblewrap-build \
    && meson install -C /tmp/bubblewrap-build \
    && /usr/local/bin/bwrap --version \
    && rm -rf /tmp/bubblewrap.tar.xz /tmp/bubblewrap-src /tmp/bubblewrap-build \
    && python3 -m pip install --no-cache-dir "angr==${ANGR_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/local/bin:${PATH}"
RUN test "$(bwrap --version)" = "bubblewrap ${BUBBLEWRAP_VERSION}"

FROM toolchain AS build

WORKDIR /workspace
COPY scripts/install-frontend-node.sh scripts/frontend-node-sha256.txt ./scripts/
COPY .node-version ./
COPY frontend/package.json ./frontend/package.json
RUN bash scripts/install-frontend-node.sh /opt/frontend-node
ENV PATH="/opt/frontend-node/bin:${PATH}"
COPY . .
RUN --mount=type=cache,target=/root/.gradle ./gradlew --no-daemon installDist

FROM toolchain AS runtime

# Node/npm belong only to the build stage, never the application runtime.
RUN ! command -v node && ! command -v npm && test ! -e /opt/frontend-node

ARG APP_UID=1000
ARG APP_GID=1000

ENV PATH="/opt/llm_bin_patch/bin:${PATH}"

RUN groupadd --gid "${APP_GID}" llm-bin-patch \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home --shell /bin/bash llm-bin-patch \
    && mkdir -p /input /output /runner \
    && chown llm-bin-patch:llm-bin-patch /output /runner \
    && chmod 0700 /runner

COPY --from=build /workspace/build/install/llm_bin_patch /opt/llm_bin_patch

RUN test ! -L /opt/llm_bin_patch/libexec/decomp-acp-gate-helper \
    && test "$(stat -c '%a:%u:%g' /opt/llm_bin_patch/libexec/decomp-acp-gate-helper)" = "755:0:0" \
    && cd /opt/llm_bin_patch/libexec \
    && sha256sum --check --strict decomp-acp-gate-helper.sha256

USER llm-bin-patch
WORKDIR /work

RUN llm_bin_patch doctor --tools-only

ENTRYPOINT ["llm_bin_patch"]
CMD ["--help"]
