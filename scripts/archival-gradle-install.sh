#!/bin/sh
# One bounded Gradle installDist invocation for the archival image build (#2013).
# It is the single place that sets the archival resolver retry properties.
#
# Cold retry window: Gradle retries a transient repository failure, including
# HTTP 429, up to MAX_TENTATIVES requests per resource and sleeps the initial
# backoff, then 2x, 4x, ... between them, so the sleeps total
# (2^(MAX_TENTATIVES-1) - 1) x the initial backoff. Each build draws its initial
# backoff uniformly from [BACKOFF_FLOOR_MS, BACKOFF_FLOOR_MS + BACKOFF_JITTER_MS)
# so concurrent CI builds do not retry in lockstep. With 8 tentatives and
# 3000-5000 ms, one throttled resource waits 381-635 s (6.4-10.6 min) before
# Gradle reports the failure. The 45-minute timeout bounds the whole invocation.
set -eu

MAX_TENTATIVES=8
BACKOFF_FLOOR_MS=3000
BACKOFF_JITTER_MS=2000

if [ -n "${ARCHIVAL_GRADLE_INITIAL_BACKOFF_MS:-}" ]; then
  # Loopback resolver controls only; the image build never sets this.
  initial_backoff_ms=$ARCHIVAL_GRADLE_INITIAL_BACKOFF_MS
else
  random=$(od -An -N2 -tu2 /dev/urandom | tr -d ' \n')
  initial_backoff_ms=$((BACKOFF_FLOOR_MS + random % BACKOFF_JITTER_MS))
fi
case $initial_backoff_ms in
  '' | *[!0-9]*) echo "archival Gradle retry: invalid initial backoff" >&2; exit 2 ;;
esac

echo "archival Gradle retry: $MAX_TENTATIVES tentatives, initial backoff $initial_backoff_ms ms," \
  "at most $((initial_backoff_ms * ((1 << (MAX_TENTATIVES - 1)) - 1) / 1000)) s of backoff per resource"

exec timeout --signal=TERM --kill-after=30s 45m \
  "${ARCHIVAL_GRADLEW:-./gradlew}" --no-daemon \
  -Dorg.gradle.internal.repository.max.tentatives="$MAX_TENTATIVES" \
  -Dorg.gradle.internal.repository.initial.backoff="$initial_backoff_ms" \
  -Dorg.gradle.internal.http.connectionTimeout=30000 \
  -Dorg.gradle.internal.http.socketTimeout=60000 \
  installDist
