# syntax=docker/dockerfile:1

FROM eclipse-temurin:21-jdk-jammy@sha256:55fb9bf738f5d9b4a6c01b39337e3070d3e27370dd3c478fd1d5d3cd2233c6d8 AS toolchain

ARG ANGR_VERSION=9.2.213

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        binutils \
        bubblewrap \
        build-essential \
        ca-certificates \
        clang \
        curl \
        python3 \
        python3-pip \
        unzip \
    && python3 -m pip install --no-cache-dir "angr==${ANGR_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

FROM toolchain AS build

WORKDIR /workspace
COPY . .
RUN --mount=type=cache,target=/root/.gradle ./gradlew --no-daemon installDist

FROM toolchain AS runtime

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
