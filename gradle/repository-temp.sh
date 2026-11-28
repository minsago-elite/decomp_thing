# Sourced by ./gradlew (POSIX sh) after DEFAULT_JVM_OPTS is set; `tasks.wrapper` in
# build.gradle.kts re-adds the sourcing line whenever the wrapper is regenerated (#2008).
#
# Keeps build-tool temporary files under the repository. The client's java.io.tmpdir is
# immutable, so Gradle starts its daemon with the same value, and the daemon passes the
# exported TMPDIR to the tools it runs (cc, npm, python). HotSpot writes
# /tmp/hsperfdata_<user>/<pid> whatever java.io.tmpdir says, hence -XX:-UsePerfData.
# .gradle/ survives `clean`, which would otherwise delete a running daemon's temp directory.
# These options are appended to GRADLE_OPTS, the last options gradlew passes, so a caller's
# own java.io.tmpdir or UsePerfData setting cannot move them out of the repository.

DECOMP_GRADLE_TMPDIR=$APP_HOME/.gradle/tmp
case $DECOMP_GRADLE_TMPDIR in
    *[\"\\]* | *'
'*) die "ERROR: the repository path cannot be passed to java safely: $DECOMP_GRADLE_TMPDIR" ;;
esac
mkdir -p "$DECOMP_GRADLE_TMPDIR" || die "ERROR: cannot create $DECOMP_GRADLE_TMPDIR"
TMPDIR=$DECOMP_GRADLE_TMPDIR
export TMPDIR
GRADLE_OPTS="$GRADLE_OPTS \"-XX:-UsePerfData\" \"-Djava.io.tmpdir=$DECOMP_GRADLE_TMPDIR\""
