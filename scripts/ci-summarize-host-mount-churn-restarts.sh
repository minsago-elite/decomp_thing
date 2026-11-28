#!/usr/bin/env bash
# Summarizes one CI run attempt's ACP host mount churn restart reports (#1799). Diagnostic only:
# it never fails the job. Each test JVM writes test-jvm-<pid>.expected when its first ACP test class
# starts and test-jvm-<pid>.json at the end; a missing JSON or an .incomplete marker is incomplete.
# A job that knows how many ACP test JVMs it runs passes that minimum, so a JVM whose .expected
# marker could not be written still makes the summary INCOMPLETE.
set -u
directory="${1:?usage: ci-summarize-host-mount-churn-restarts.sh <report-directory> [minimum-reports]}"
minimum="${2:-0}"
case "$minimum" in ''|*[!0-9]*) minimum=0 ;; esac
expected=0 complete=0 incomplete=0 restarted=0
if [ -d "$directory" ]; then
  for marker in "$directory"/test-jvm-*.expected; do
    [ -e "$marker" ] || continue
    expected=$((expected + 1))
    report="${marker%.expected}.json"
    if [ -f "$report" ] && [ ! -e "${marker%.expected}.incomplete" ]; then
      count=$(grep -o '"restartedRefusals":[0-9]\{1,19\}' "$report" | head -n 1 | cut -d: -f2)
      if [ -n "$count" ]; then
        complete=$((complete + 1))
        restarted=$((restarted + count))
        continue
      fi
    fi
    incomplete=$((incomplete + 1))
  done
fi
if [ "$expected" -lt "$minimum" ] || [ "$incomplete" -gt 0 ]; then status=INCOMPLETE
elif [ "$expected" -eq 0 ]; then status=ABSENT
else status=COMPLETE
fi
line="acp-host-mount-churn-restarts status=$status expectedReports=$expected minimumReports=$minimum"
line="$line completeReports=$complete incompleteReports=$incomplete restartedRefusals=$restarted"
echo "$line"
if [ -d "$directory" ]; then printf '%s\n' "$line" > "$directory/summary.txt" 2>/dev/null || true; fi
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then printf '%s\n' "$line" >> "$GITHUB_STEP_SUMMARY" 2>/dev/null || true; fi
exit 0
