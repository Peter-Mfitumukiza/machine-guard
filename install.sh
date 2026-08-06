#!/usr/bin/env bash
#
# machine-guard :: install the layered cadence.
#
#   daily   launchd job, full scan once a day, notifies only on CRITICAL
#   hook    git pre-push guard -- refuses to push if the toolchain changed
#   shell   adds a fast `quick` check to ~/.zshrc (milliseconds)
#   all     all three
#   status  show what is installed
#   remove  uninstall everything
#
# Rationale for layering: the npm implant re-stole credentials on EVERY npm
# invocation, so a once-a-day scan can leave ~24h of exfiltration. The cheap
# hash check runs at the two moments that actually matter -- before a push
# carries stolen credentials out, and when you open a shell -- while the
# expensive filesystem sweep stays daily.

set -uo pipefail
MG_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LABEL="com.peter.machine-guard"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
HOUR="${MG_HOUR:-9}"
MIN="${MG_MIN:-30}"

install_daily() {
  mkdir -p "$MG_HOME/var/logs"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$MG_HOME/daily-run.sh</string>
  </array>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>$HOUR</integer>
    <key>Minute</key><integer>$MIN</integer>
  </dict>
  <key>RunAtLoad</key><false/>
  <key>StandardOutPath</key><string>$MG_HOME/var/logs/launchd.out.log</string>
  <key>StandardErrorPath</key><string>$MG_HOME/var/logs/launchd.err.log</string>
</dict>
</plist>
EOF
  launchctl unload "$PLIST" 2>/dev/null
  launchctl load "$PLIST" 2>/dev/null
  echo "  daily scan installed: $LABEL at $(printf '%02d:%02d' "$HOUR" "$MIN")"
  echo "  NOTE: this adds a plist to ~/Library/LaunchAgents, which machine-guard"
  echo "        itself watches. Re-run 'machine-guard.sh baseline' to accept it."
}

install_hook() {
  local hooks="$HOME/.config/git/hooks"
  mkdir -p "$hooks"
  cat > "$hooks/pre-push" <<EOF
#!/bin/sh
# machine-guard: refuse to push if the package manager changed since baseline.
# The 2026-08 worm pushed forged commits to ~56 repos using a token stolen by a
# trojaned npm. This is the last cheap moment to stop that.
"$MG_HOME/machine-guard.sh" quick || {
  echo "pre-push blocked by machine-guard. Investigate before pushing."
  exit 1
}
exit 0
EOF
  chmod +x "$hooks/pre-push"
  git config --global core.hooksPath "$hooks" 2>/dev/null
  echo "  pre-push hook installed: $hooks/pre-push"
  echo "  (git core.hooksPath set globally -- existing per-repo hooks in .husky/"
  echo "   still run if the repo sets its own core.hooksPath)"
}

install_shell() {
  local rc="$HOME/.zshrc" marker="# >>> machine-guard >>>"
  if grep -qF "$marker" "$rc" 2>/dev/null; then
    echo "  shell check already present in $rc"; return 0
  fi
  cat >> "$rc" <<EOF

$marker
[ -x "$MG_HOME/machine-guard.sh" ] && "$MG_HOME/machine-guard.sh" quick
# <<< machine-guard <<<
EOF
  echo "  shell check appended to $rc"
}

cmd_status() {
  echo "machine-guard install status"
  [ -f "$PLIST" ] && echo "  daily : installed ($PLIST)" || echo "  daily : not installed"
  launchctl list 2>/dev/null | grep -q "$LABEL" && echo "          loaded" || echo "          NOT loaded"
  [ -x "$HOME/.config/git/hooks/pre-push" ] && echo "  hook  : installed" || echo "  hook  : not installed"
  grep -qF ">>> machine-guard >>>" "$HOME/.zshrc" 2>/dev/null && echo "  shell : installed" || echo "  shell : not installed"
}

cmd_remove() {
  launchctl unload "$PLIST" 2>/dev/null; rm -f "$PLIST"
  rm -f "$HOME/.config/git/hooks/pre-push"
  if grep -qF ">>> machine-guard >>>" "$HOME/.zshrc" 2>/dev/null; then
    /usr/bin/sed -i '' '/# >>> machine-guard >>>/,/# <<< machine-guard <<</d' "$HOME/.zshrc"
  fi
  echo "  removed (git core.hooksPath left as-is -- unset manually if you want)"
}

case "${1:-status}" in
  daily)  install_daily ;;
  hook)   install_hook ;;
  shell)  install_shell ;;
  all)    install_daily; install_hook; install_shell ;;
  status) cmd_status ;;
  remove) cmd_remove ;;
  *) sed -n '3,18p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
