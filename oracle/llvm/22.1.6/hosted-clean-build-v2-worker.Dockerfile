ARG TOOLCHAIN_IMAGE
FROM ${TOOLCHAIN_IMAGE}

COPY jdk/ /decomp-jdk/
COPY app/lib/ /decomp-app/lib/

ENTRYPOINT ["/decomp-jdk/bin/java","-Djna.nosys=true","-Djna.tmpdir=/decomp-jna","-cp","/decomp-app/lib/*","decompengine.oracle.behavior.LlvmBehaviorHostedCleanBuildV2InnerWorkerMain"]
CMD []
