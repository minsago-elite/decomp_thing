ARG TOOLCHAIN_IMAGE
FROM ${TOOLCHAIN_IMAGE}

COPY jdk/ /decomp-jdk/
COPY app/lib/ /decomp-app/lib/
COPY app/worker.args /decomp-app/worker.args

ENTRYPOINT ["/decomp-jdk/bin/java","@/decomp-app/worker.args"]
CMD []
