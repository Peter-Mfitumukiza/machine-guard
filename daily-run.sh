#!/usr/bin/env bash
#
# Daily wrapper invoked by launchd.
#
# Reports DELTAS ONLY: on a clean machine it writes a one-line log entry and is
# otherwise completely silent. A daily report that repeats itself gets filtered
# to trash within a fortnight, and then it protects nothing.
#
# On CRITICAL it raises a macOS notification, because a finding nobody sees is
# not a finding. On WARN it stays quiet and lets the log carry it.

set -uo pipefail
MG_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOGDIR="$MG_HOME/var/logs"
mkdir -p "$LOGDIR"
TS="$(date '+%Y%m%d-%H%M%S')"
OUT="$LOGDIR/scan-$TS.log"

"$MG_HOME/machine-guard.sh" scan > "$OUT" 2>&1
RC=$?

SUMMARY="$(tail -3 "$OUT" | grep RESULT || echo ' RESULT: (see log)')"
echo "$(date -u '+%Y-%m-%dT%H:%M:%SZ') rc=$RC $SUMMARY" >> "$LOGDIR/history.log"

case "$RC" in
  2)
    n=$(grep -c '\[CRITICAL\]' "$OUT")
    /usr/bin/osascript -e "display notification \"$n critical finding(s). See $OUT\" with title \"machine-guard: COMPROMISE INDICATORS\" sound name \"Basso\"" 2>/dev/null
    ;;
  1)
    : # warnings stay in the log; not worth interrupting for
    ;;
  0)
    # Clean: keep the summary line in history.log, discard the full log so the
    # directory does not fill with identical clean reports.
    rm -f "$OUT"
    ;;
esac

# Keep 60 days of non-clean logs.
find "$LOGDIR" -name 'scan-*.log' -mtime +60 -delete 2>/dev/null
exit "$RC"
