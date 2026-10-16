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
        ninja-build \
        python3 \
        python3-pip \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# pip connection retries do not retry a failed streaming download. Keep completed
# downloads outside the image and bound retries of the complete installation.
COPY requirements/angr-compatibility.txt /workspace/requirements/angr-compatibility.txt
RUN --mount=type=cache,target=/root/.cache/pip \
    timeout --signal=KILL 15m sh -ec ' \
        for attempt in 1 2 3; do \
            if python3 -m pip install --no-input --disable-pip-version-check \
                --timeout 60 --retries 5 --constraint /workspace/requirements/angr-compatibility.txt "$1"; then exit 0; fi; \
            if [ "$attempt" -lt 3 ]; then sleep 5; fi; \
        done; \
        exit 1 \
    ' -- "angr==${ANGR_VERSION}"
RUN python3 -c 'import angr, sys; assert angr.__version__ == sys.argv[1]; print("angr import:", angr.__version__)' "$ANGR_VERSION"

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
