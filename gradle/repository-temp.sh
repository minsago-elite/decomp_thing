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

# Every toolchain is Java 21 and auto-detection is off (gradle.properties), so the JVM that runs
# Gradle must be Java 21. Any other JDK Gradle has to resolve as a toolchain is started once to
# read its version, without -XX:-UsePerfData, which writes /tmp/hsperfdata_<user>/<pid>.
decomp_java=$JAVACMD
case $decomp_java in
    */*) ;;
    *) decomp_java=$(command -v "$decomp_java") || die "ERROR: cannot find $JAVACMD" ;;
esac
# /usr/bin/java is often a link into the installation, whose `release` file names its version.
decomp_java=$(readlink -f "$decomp_java" 2>/dev/null) || decomp_java=$JAVACMD
decomp_java_home=$(cd -P "$(dirname "$decomp_java")/.." >/dev/null && pwd) ||
    die "ERROR: cannot resolve the Java installation of $decomp_java"
if [ -f "$decomp_java_home/release" ]; then
    decomp_java_version=$(sed -n 's/^JAVA_VERSION="\([^"]*\)".*/\1/p' "$decomp_java_home/release")
else
    decomp_java_version=$("$JAVACMD" -XX:-UsePerfData -version 2>&1 | sed -n 's/^[^"]* version "\([^"]*\)".*/\1/p')
fi
case $decomp_java_version in
    21 | 21.*) ;;
    *) die "ERROR: this build requires Java 21 to run Gradle, but $decomp_java is Java ${decomp_java_version:-unknown}.
Set JAVA_HOME to a Java 21 installation. Gradle starts any other JDK it resolves as a toolchain
without -XX:-UsePerfData, which writes temporary files outside the repository (#2008)." ;;
esac

DECOMP_GRADLE_TMPDIR=$APP_HOME/.gradle/tmp
case $DECOMP_GRADLE_TMPDIR in
    *[\"\\]* | *'
'*) die "ERROR: the repository path cannot be passed to java safely: $DECOMP_GRADLE_TMPDIR" ;;
esac
mkdir -p "$DECOMP_GRADLE_TMPDIR" || die "ERROR: cannot create $DECOMP_GRADLE_TMPDIR"
TMPDIR=$DECOMP_GRADLE_TMPDIR
export TMPDIR
GRADLE_OPTS="$GRADLE_OPTS \"-XX:-UsePerfData\" \"-Djava.io.tmpdir=$DECOMP_GRADLE_TMPDIR\""
