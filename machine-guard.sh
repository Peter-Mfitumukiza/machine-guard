#!/usr/bin/env bash
#
# machine-guard -- integrity-first compromise detection for a developer machine.
#
#   baseline           capture the known-good hash manifest
#   scan               full scan: integrity + toolchain + runtime + quarantine + techniques + signatures
#   quick              fast toolchain integrity check (shell startup / pre-push hook)
#   harden-quarantine  strip the executable bit from every quarantine root
#   status             manifest age and last scan result
#
# Design notes -- why it is shaped this way:
#
#  * INTEGRITY IS THE CORE, signatures are the garnish. Signature matching only
#    finds the campaign you already know about; this operator rotates campaign
#    IDs per host and rotates C2 through the blockchain. Asking "has something
#    that should never change, changed?" is variant-agnostic, and would have
#    caught the 2026-06-26 compromise on 2026-06-26 (npm/lib/cli.js changed and
#    com.clipboard-bot.plist appeared, two hours apart).
#
#  * DETECT TECHNIQUES, NOT CAMPAIGNS. A >2000-char line in a build config
#    catches the carrier trick whatever the watermark says. A multi-KB argv on
#    node/python catches stage-2 whatever it contains.
#
#  * DELTAS ONLY. If nothing changed, say nothing. A daily report that repeats
#    itself gets filtered to trash, and then it protects nothing.
#
#  * QUARANTINE IS SCANNED, NOT EXEMPTED. Known artifacts are labelled
#    KNOWN-QUARANTINED (informational). An executable bit under a quarantine
#    root is CRITICAL -- that is where an attacker would hide.
#
#  * FINDINGS ARE RECORDED TO A FILE, NOT SHELL VARIABLES. Every check runs
#    inside a pipeline, and bash runs those in subshells, so variable
#    increments are silently discarded. The first version of this script had
#    that bug and printed "RESULT: CLEAN" under a dozen CRITICAL findings.
#
# READ-ONLY (except `harden-quarantine`, which only removes permission bits).
# Installs nothing, builds nothing, executes no scanned code, prints no secrets.
#
# Exit: 0 = clean/no change   1 = warnings   2 = CRITICAL

set -uo pipefail

MG_HOME="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF="$MG_HOME/config"
VAR="$MG_HOME/var"
MANIFEST="$VAR/manifest.tsv"
LASTSCAN="$VAR/last-scan.txt"
mkdir -p "$VAR" 2>/dev/null

FINDINGS="$VAR/.findings.$$"
: > "$FINDINGS"
trap 'rm -f "$FINDINGS" "$FINDINGS.q" 2>/dev/null' EXIT

FULL="${MG_FULL:-0}"
QUIET=0

# ---------------------------------------------------------------------------
# Reporting -- file-backed so it survives pipeline subshells.
# ---------------------------------------------------------------------------
crit() { printf 'CRITICAL\t%s\n' "$*" >> "$FINDINGS"; printf '  [CRITICAL] %s\n' "$*"; }
warn() { printf 'WARN\t%s\n'     "$*" >> "$FINDINGS"; printf '  [WARN]     %s\n' "$*"; }
info() { printf 'INFO\t%s\n'     "$*" >> "$FINDINGS"; [ "$FULL" = 1 ] && printf '  [info]     %s\n' "$*"; return 0; }
note() { [ "$QUIET" = 1 ] || printf '             %s\n' "$*"; }
line() { [ "$QUIET" = 1 ] || printf '  %s\n' "$*"; }
sec()  { [ "$QUIET" = 1 ] || printf '\n== %s\n' "$*"; }

count_of() { grep -c "^$1" "$FINDINGS" 2>/dev/null | tr -d ' '; }

hash_of() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}'; }
mode_of() { stat -f '%Lp' "$1" 2>/dev/null; }
size_of() { stat -f '%z' "$1" 2>/dev/null; }

# ---------------------------------------------------------------------------
# Quarantine roots
# ---------------------------------------------------------------------------
quarantine_roots() {
  { ls -d "$HOME"/quarantine* 2>/dev/null
    ls -d "$HOME"/*quarantine* 2>/dev/null
    [ -f "$CONF/quarantine.list" ] && grep -v '^#' "$CONF/quarantine.list" 2>/dev/null | grep -v '^[[:space:]]*$'
  } | sort -u
}

# Loaded launchd labels, filtered to PERSISTENT ones.
#
# `launchctl list` mixes durable jobs with per-session churn: Spotlight
# mdworkers respawn constantly with fresh UUIDs, and every GUI app launch
# registers an `application.<bundle>.<session-id>` label. Diffing raw output
# yields a fresh batch of "NEW job!" warnings every few minutes, which is
# noise, not signal. We want persistence, so we drop anything carrying a
# session/UUID marker.
# PIDs of this process and every ancestor, so the scan never reports itself.
self_ancestry() {
  local p=$$
  while [ -n "$p" ] && [ "$p" != "0" ] && [ "$p" != "1" ]; do
    printf '%s ' "$p"
    p=$(ps -p "$p" -o ppid= 2>/dev/null | tr -d ' ')
  done
}

current_launchd() {
  launchctl list 2>/dev/null | awk 'NR>1{print $3}' \
    | grep -E '^[a-zA-Z]' \
    | grep -vE '^application\.' \
    | grep -vE '\.mdworker\.' \
    | grep -vE '[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-' \
    | grep -vE '\.[0-9]{6,}' \
    | sort -u
}

is_quarantined() {
  local p="$1" r
  while IFS= read -r r; do
    [ -z "$r" ] && continue
    case "$p" in "$r"/*|"$r") return 0 ;; esac
  done < <(quarantine_roots)
  return 1
}

# ---------------------------------------------------------------------------
# Allow list, compiled once into a single alternation for speed.
# ---------------------------------------------------------------------------
ALLOW_RE=""
build_allow_re() {
  [ -f "$CONF/allow.list" ] || return 0
  ALLOW_RE="$(grep -v '^#' "$CONF/allow.list" 2>/dev/null | grep -v '^[[:space:]]*$' | paste -sd'|' -)"
}
allowed() { [ -n "$ALLOW_RE" ] && printf '%s' "$1" | grep -qE "$ALLOW_RE"; }

# Files git ships as inert templates -- git never executes *.sample. Excluding
# them is not a security hole; including them buries real findings in noise.
INERT_EXEC_RE='\.sample$|/\.git/hooks/[^/]*\.sample$'

# ---------------------------------------------------------------------------
expand_targets() {
  local kind path f
  grep -v '^#' "$CONF/watch.list" 2>/dev/null | grep -v '^[[:space:]]*$' | while read -r kind path; do
    path="${path/#\~/$HOME}"
    case "$kind" in
      FILE) [ -f "$path" ] && echo "$path" ;;
      GLOB) for f in $path; do [ -f "$f" ] && echo "$f"; done ;;
      DIR)  [ -d "$path" ] && find "$path" -maxdepth 1 -type f 2>/dev/null ;;
      TREE) [ -d "$path" ] && find "$path" -type f 2>/dev/null ;;
    esac
  done | sort -u
}

# ===========================================================================
cmd_baseline() {
  echo "machine-guard :: capturing integrity baseline"
  echo
  if [ "${MG_FORCE:-0}" != "1" ] && [ -f "$MANIFEST" ]; then
    QUIET=1; check_integrity >/dev/null 2>&1; QUIET=0
    if [ "$(count_of CRITICAL)" != "0" ]; then
      echo "  REFUSING: integrity CRITICAL findings are present."
      echo "  Baselining now would freeze a possible compromise in as 'known good'."
      echo "  Resolve them, or re-run with MG_FORCE=1 if you are certain."
      return 2
    fi
    : > "$FINDINGS"
  fi

  expand_targets | while IFS= read -r f; do
    printf '%s\t%s\t%s\t%s\n' "$(hash_of "$f")" "$(size_of "$f")" "$(mode_of "$f")" "$f"
  done | sort -t"$(printf '\t')" -k4 > "$MANIFEST"

  current_launchd > "$VAR/launchd.list"

  local n l; n=$(wc -l < "$MANIFEST" | tr -d ' '); l=$(wc -l < "$VAR/launchd.list" | tr -d ' ')
  { echo "captured: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "host: $(hostname)"
    echo "entries: $n"
    echo "launchd labels: $l"; } > "$VAR/manifest.meta"
  echo "  baselined $n file(s) -> $MANIFEST"
  echo "  baselined $l loaded launchd label(s)"
  echo
  echo "  Review it once by hand: everything listed is something you assert"
  echo "  should never change silently."
  return 0
}

# ===========================================================================
check_integrity() {
  sec "1. Integrity  (has anything that should never change, changed?)"
  if [ ! -f "$MANIFEST" ]; then
    warn "no baseline yet -- run: machine-guard.sh baseline"
    return
  fi

  while IFS=$'\t' read -r ohash osize omode f; do
    [ -z "${f:-}" ] && continue
    if [ ! -f "$f" ]; then warn "REMOVED  $f"; continue; fi
    local nhash nmode
    nhash="$(hash_of "$f")"; nmode="$(mode_of "$f")"
    if [ "$nhash" != "$ohash" ]; then
      crit "CHANGED  $f"
      note "was ${osize}B, now $(size_of "$f")B   sha256 ${ohash:0:16}… -> ${nhash:0:16}…"
    elif [ "$nmode" != "$omode" ]; then
      warn "MODE     $f  ($omode -> $nmode)"
    fi
  done < "$MANIFEST"

  expand_targets | while IFS= read -r f; do
    cut -f4 "$MANIFEST" | grep -qxF "$f" || echo "$f"
  done | while IFS= read -r f; do
    crit "NEW      $f"
    note "appeared since baseline (a new LaunchAgent or SSH key is exactly how"
    note "both 2026-06-26 payloads announced themselves)"
  done

  [ "$(count_of CRITICAL)" = "0" ] && [ "$(count_of WARN)" = "0" ] && line "no changes against baseline"
  return 0
}

# ===========================================================================
check_toolchain() {
  sec "2. Package-manager entry points  (structural, baseline-independent)"
  local found=0 p maxlen lines sz tc_before
  tc_before="$(count_of CRITICAL)"
  for p in "$HOME"/.nvm/versions/node/*/lib/node_modules/npm/lib/cli.js \
           "$HOME"/.local/share/mise/installs/node/*/lib/node_modules/npm/lib/cli.js \
           "$HOME"/.asdf/installs/nodejs/*/lib/node_modules/npm/lib/cli.js \
           "$HOME"/.volta/tools/image/node/*/lib/node_modules/npm/lib/cli.js \
           /usr/local/lib/node_modules/npm/lib/cli.js \
           /opt/homebrew/lib/node_modules/npm/lib/cli.js; do
    [ -f "$p" ] || continue
    found=1
    maxlen=$(awk '{if(length>m)m=length}END{print m+0}' "$p")
    lines=$(wc -l < "$p" | tr -d ' '); sz=$(size_of "$p")
    if [ "${maxlen:-0}" -gt 500 ] || [ "${sz:-0}" -gt 4000 ]; then
      crit "TROJANED npm entry point: $p"
      note "${sz}B, ${lines} lines, longest line ${maxlen}  (genuine ~407B / 12 / 79)"
      note "-> reinstall Node; do NOT merely truncate the payload line"
    else
      info "ok: $p (${sz}B, longest ${maxlen})"
    fi
  done
  if [ "$found" = 0 ]; then
    line "no npm installation found"
  else
    [ "$(count_of CRITICAL)" = "$tc_before" ] && line "npm entry points structurally sound"
  fi
  return 0
}

# ===========================================================================
check_runtime() {
  sec "3. Runtime  (a live process is an active compromise, not a risk)"
  local ps_out; ps_out="$(ps -Ao pid,ppid,command 2>/dev/null)"
  local before before_w; before="$(count_of CRITICAL)"; before_w="$(count_of WARN)"

  # 3a/3b. Inline-eval processes: payload markers, oversized argv, or spawned
  # by a package manager (the npm-implant relationship).
  #
  # Match on the process's ACTUAL EXECUTABLE (comm), never on a substring of
  # the command line. A shell that merely *mentions* `node -e ...` in its argv
  # -- including the very shell running this scan -- is not an inline-eval
  # process, and substring matching makes the scanner flag itself on every run.
  #
  # Our own ancestry is skipped for the same reason.
  local selfline; selfline="$(self_ancestry)"

  # Shell BLOCKLIST, not an interpreter allowlist.
  #
  # Allowlisting interpreter names ("is comm == node?") is trivially defeated:
  # `cp $(which node) /tmp/systemd-helper` and the check goes blind. Measured
  # -- that evasion beat the previous version of this function. Blocking shells
  # instead keeps out the one real false positive (a shell whose argv merely
  # *contains* a node command, including the shell running this scan) while
  # still seeing a renamed interpreter.
  printf '%s\n' "$ps_out" | awk 'NR>1{print $1}' | while IFS= read -r pid; do
    case " $selfline " in *" $pid "*) continue ;; esac

    local commfull commbase args len ppid pcmd
    commfull=$(ps -p "$pid" -o comm= 2>/dev/null)
    [ -z "$commfull" ] && continue
    commbase="${commfull##*/}"
    case "$commbase" in
      sh|bash|zsh|dash|ksh|fish|tcsh|csh|login|ps|grep|awk|sed) continue ;;
    esac

    args=$(ps -p "$pid" -o command= 2>/dev/null)
    [ -z "$args" ] && continue
    len=${#args}
    ppid=$(ps -p "$pid" -o ppid= 2>/dev/null | tr -d ' ')
    pcmd=$(ps -p "$ppid" -o command= 2>/dev/null | cut -c1-70)

    # (a) Inline evaluation: -e / --eval / -c
    if printf '%s' "$args" | grep -qE ' -e |--eval|[[:space:]]-c '; then
      if printf '%s' "$args" | grep -qE "global\[|atob\(|_\\\$_|child_process|createRequire|eval\("; then
        crit "inline-eval process carrying payload markers (pid $pid, $commbase)"
        note "$(printf '%s' "$args" | cut -c1-130)"
      elif [ "$len" -gt 2000 ]; then
        crit "inline-eval process with ${len}-char argv (pid $pid, $commbase) -- stage-2 shape"
        note "$(printf '%s' "$args" | cut -c1-130)"
      fi
      case "$pcmd" in
        *"npm exec"*|*"npm ls"*|*npx*|*pnpm*|*yarn*)
          crit "inline-eval spawned by a package manager (pid $pid, parent $ppid)"
          note "parent: $pcmd"
          note "this is the npm-implant parent/child relationship exactly" ;;
      esac
    fi

    # (b) Preload injection: -r / --require / --import pointing somewhere odd.
    #     Legitimate preloads (ts-node/register, tsx, dotenv) live in node_modules.
    if printf '%s' "$args" | grep -qE '(^| )(-r|--require|--import)[= ]'; then
      local pre
      pre=$(printf '%s' "$args" | grep -oE '(-r|--require|--import)[= ][^ ]+' | head -1 | sed -E 's/^(-r|--require|--import)[= ]//')
      case "$pre" in
        */node_modules/*|"") ;;
        /tmp/*|/var/tmp/*|*/.*/*|*quarantine*)
          crit "preload injection into $commbase (pid $pid): $pre" ;;
      esac
    fi

    # (c) Executable running from a location code should not live in.
    case "$commfull" in
      /tmp/*|/var/tmp/*|*/quarantine*|*/.cache/*|*/.local/tmp/*)
        warn "process running from an unusual location (pid $pid): $commfull" ;;
    esac

    # (e) Script argument that no longer exists on disk.
    #     Classic drop-execute-unlink. lsof shows nothing useful (node reads the
    #     file at startup and closes the fd), but argv is fixed at exec time, so
    #     the path is still visible long after the file is gone.
    case "$commbase" in
      node|nodejs|deno|bun|python|python2|python3|python3.*|ruby|perl)
        local sarg
        sarg=$(printf '%s' "$args" | awk '{for(i=2;i<=NF;i++){if($i ~ /^-/) continue; print $i; exit}}')
        if [ -n "$sarg" ]; then
          case "$sarg" in
            /*|./*|../*)
              if [ ! -e "$sarg" ]; then
                crit "process running a script that no longer exists on disk (pid $pid)"
                note "$commbase $sarg  -- drop-execute-unlink pattern"
              fi ;;
          esac
        else
          # No script argument and no eval flag => reading code from stdin,
          # or an interactive REPL. Unusual for a long-lived background process.
          printf '%s' "$args" | grep -qE ' -e |--eval|[[:space:]]-c |-i|--interactive' || \
            warn "interpreter running with no script argument (pid $pid, $commbase) -- stdin/REPL"
        fi ;;
    esac

    # (d) NODE_OPTIONS injection -- a quiet way to preload code into every
    #     node process without touching any command line.
    local envs
    envs=$(ps -E -p "$pid" -o command= 2>/dev/null | tr ' ' '\n' | grep -E '^NODE_OPTIONS=' | head -1)
    if [ -n "$envs" ]; then
      case "$envs" in
        *--require*|*--import*|*-r\ *)
          crit "NODE_OPTIONS preload injection (pid $pid): $envs" ;;
      esac
    fi
  done

  # 3c. Clipboard / seed-phrase stealer family.
  printf '%s\n' "$ps_out" | grep -iE 'clipboard[-_]?bot|run_bot\.py|clipboard_watch|clipboard_monitor' | grep -v grep | \
  while IFS= read -r l; do
    crit "clipboard/seed-stealer process running"
    note "$(printf '%s' "$l" | cut -c1-130)"
  done

  # 3d. Live connections to known C2.
  local conns
  conns="$(lsof -nP -iTCP -sTCP:ESTABLISHED 2>/dev/null | grep -E '166\.88\.8\.133')"
  if [ -n "$conns" ]; then
    crit "ESTABLISHED connection to known C2 infrastructure"
    printf '%s\n' "$conns" | head -5 | while IFS= read -r c; do note "$c"; done
  fi

  # 3e. Loaded launchd jobs -- DELTA against baseline, not "is there a plist".
  #
  # The obvious check ("loaded but no plist in the standard directories") is
  # useless in practice: ssh-agent, Slack, Spotify, Postman and every Squirrel
  # /ShipIt updater are legitimately registered from inside app bundles. It
  # produced six false positives on a clean machine, which is precisely the
  # noise that trains you to ignore the report. What actually matters is a
  # label that was not loaded yesterday.
  if [ -f "$VAR/launchd.list" ]; then
    current_launchd | while IFS= read -r label; do
      grep -qxF "$label" "$VAR/launchd.list" || {
        warn "NEW launchd job loaded since baseline: $label"
        note "if you did not install this, inspect: launchctl print gui/\$UID/$label"
      }
    done
  else
    info "no launchd baseline yet (captured on next 'baseline' run)"
  fi

  [ "$(count_of CRITICAL)" = "$before" ] && [ "$(count_of WARN)" = "$before_w" ] && line "no suspicious processes or connections"
  return 0
}

# ===========================================================================
check_quarantine() {
  sec "4. Quarantine hygiene  (scanned, never exempted)"
  local roots; roots="$(quarantine_roots)"
  if [ -z "$roots" ]; then line "no quarantine roots found"; return 0; fi

  printf '%s\n' "$roots" | while IFS= read -r r; do
    [ -d "$r" ] || continue
    local n x
    n=$(find "$r" -type f 2>/dev/null | wc -l | tr -d ' ')
    # THE control: nothing under quarantine may be runnable.
    find "$r" -type f -perm -u+x 2>/dev/null | grep -vE "$INERT_EXEC_RE" > "$FINDINGS.q" || true
    x=$(wc -l < "$FINDINGS.q" | tr -d ' ')
    if [ "${x:-0}" -gt 0 ]; then
      crit "QUARANTINE-BREACH: $x executable file(s) under $r"
      head -5 "$FINDINGS.q" | while IFS= read -r f; do note "$f  (mode $(mode_of "$f"))"; done
      [ "$x" -gt 5 ] && note "... and $((x-5)) more"
      note "-> machine-guard.sh harden-quarantine   (quarantine must be inert by construction)"
    fi
    info "KNOWN-QUARANTINED: $n file(s) under $r"
    line "root: $r  ($n files, $x executable)"
  done
  return 0
}

# ===========================================================================
check_techniques() {
  sec "5. Carrier technique  (structural -- survives a rebrand)"
  local scan_roots="" d
  for d in "$HOME/Documents" "$HOME/Desktop" "$HOME/Projects" "$HOME/dev" "$HOME/code" "$HOME/work"; do
    [ -d "$d" ] && scan_roots="$scan_roots $d"
  done
  [ -z "$scan_roots" ] && { line "no project directories"; return 0; }
  local before; before="$(count_of CRITICAL)"

  find $scan_roots \
    \( -name node_modules -o -name .git -o -name .next -o -name dist -o -name build \
       -o -name coverage -o -name .venv -o -name venv \) -prune -o \
    -type f \( -name '*.config.js' -o -name '*.config.mjs' -o -name '*.config.cjs' \
       -o -name '*.config.ts' -o -name '.eslintrc.js' -o -name '.eslintrc.cjs' \
       -o -name 'eslint.config.*' -o -name '.prettierrc.js' -o -name 'babel.config.*' \) -print 2>/dev/null | \
  while IFS= read -r f; do
    local maxlen; maxlen=$(awk '{if(length>m)m=length}END{print m+0}' "$f" 2>/dev/null)
    [ "${maxlen:-0}" -le 2000 ] && continue
    allowed "$f" && continue
    if is_quarantined "$f"; then
      info "KNOWN-QUARANTINED carrier: $f (${maxlen}-char line)"
    else
      crit "build-config with a ${maxlen}-char line -- carrier shape: $f"
      note "review with: git diff -w -- '$f'   (whitespace padding hides it)"
    fi
  done
  [ "$(count_of CRITICAL)" = "$before" ] && line "no carrier-shaped build configs"
  return 0
}

# ===========================================================================
check_signatures() {
  sec "6. Known signatures  (scoped -- last, and least trusted)"
  local roots="" d
  for d in "$HOME/Documents" "$HOME/Desktop" "$HOME/Downloads"; do [ -d "$d" ] && roots="$roots $d"; done
  [ -z "$roots" ] && return 0
  local before; before="$(count_of CRITICAL)"

  local pat="global\['e'\]='NPM'|global\.i=['\"]A8-|global\[.!.\]='9-|_\\\$_1e42|_\\\$af163278|_\\\$_ccfc|0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a|TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|166\.88\.8\.133|PAYLOAD_TYPE *= *\"A8\""

  grep -rIlE "$pat" $roots \
      --include='*.js' --include='*.mjs' --include='*.cjs' \
      --include='*.ts' --include='*.tsx' --include='*.jsx' --include='*.py' \
      --exclude-dir=node_modules --exclude-dir=.git --exclude-dir=.next \
      --exclude-dir=dist --exclude-dir=build --exclude-dir=coverage 2>/dev/null | \
  while IFS= read -r f; do
    allowed "$f" && continue
    if is_quarantined "$f"; then
      info "KNOWN-QUARANTINED artifact: $f"
    else
      crit "payload signature in active source: $f"
    fi
  done
  [ "$(count_of CRITICAL)" = "$before" ] && line "no signatures outside quarantine"
  return 0
}

# ===========================================================================
cmd_harden_quarantine() {
  echo "machine-guard :: making quarantine roots inert"
  local roots; roots="$(quarantine_roots)"
  [ -z "$roots" ] && { echo "  no quarantine roots"; return 0; }
  printf '%s\n' "$roots" | while IFS= read -r r; do
    [ -d "$r" ] || continue
    local n; n=$(find "$r" -type f -perm -u+x 2>/dev/null | wc -l | tr -d ' ')
    # FILES ONLY. `chmod -R a-x` also strips the traverse bit from directories,
    # which makes the quarantine unreadable -- find cannot descend, and even rm
    # fails. Directories must keep +x; only files need to lose it.
    find "$r" -type f -perm -u+x -exec chmod a-x {} + 2>/dev/null
    echo "  $r: cleared exec bit on $n file(s) (directories left traversable)"
  done
  echo
  echo "  Quarantine is now inert by construction rather than by daily inspection."
  return 0
}

cmd_quick() {
  [ -f "$MANIFEST" ] || return 0
  local rc=0 out
  out="$(grep -E 'npm/lib/cli\.js|npm/bin/np|corepack|/bin/(npm|npx)$' "$MANIFEST" 2>/dev/null | \
    while IFS=$'\t' read -r ohash osize omode f; do
      [ -f "$f" ] || continue
      [ "$(hash_of "$f")" != "$ohash" ] && echo "$f"
    done)"
  if [ -n "$out" ]; then
    echo "machine-guard: !! PACKAGE MANAGER MODIFIED SINCE BASELINE:"
    printf '%s\n' "$out" | sed 's/^/machine-guard: !!   /'
    echo "machine-guard: !! Do not run npm/npx/pnpm or push until this is explained."
    rc=2
  fi
  return $rc
}

cmd_status() {
  [ -f "$VAR/manifest.meta" ] && cat "$VAR/manifest.meta" || echo "no baseline"
  echo
  [ -f "$LASTSCAN" ] && { echo "last scan:"; cat "$LASTSCAN"; }
}

cmd_scan() {
  local started; started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  echo "machine-guard :: scan  $started  host $(hostname)"
  build_allow_re

  check_integrity
  check_toolchain
  check_runtime
  check_quarantine
  check_techniques
  check_signatures

  local c w i; c=$(count_of CRITICAL); w=$(count_of WARN); i=$(count_of INFO)
  echo
  echo "=============================================================="
  if [ "$c" -gt 0 ]; then
    echo " RESULT: CRITICAL -- $c critical, $w warning(s), $i informational"
    echo "=============================================================="
    echo
    echo " Stop using npm/npx/pnpm/yarn. Rotate credentials from a clean device."
    echo " Reinstall Node rather than patching. Do not push until resolved, or"
    echo " you will re-poison remotes under your own account."
  elif [ "$w" -gt 0 ]; then
    echo " RESULT: WARNINGS -- $w warning(s), $i informational"
    echo "=============================================================="
  else
    echo " RESULT: CLEAN -- no change against baseline ($i informational)"
    echo "=============================================================="
  fi
  echo "$started  crit=$c warn=$w info=$i" > "$LASTSCAN"
  [ "$c" -gt 0 ] && return 2
  [ "$w" -gt 0 ] && return 1
  return 0
}

usage() { sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'; }

MAIN="${1:-scan}"; shift 2>/dev/null || true
for a in "$@"; do
  case "$a" in --full) FULL=1 ;; --quiet) QUIET=1 ;; esac
done

case "$MAIN" in
  baseline)          cmd_baseline ;;
  scan)              cmd_scan ;;
  quick)             cmd_quick ;;
  harden-quarantine) cmd_harden_quarantine ;;
  status)            cmd_status ;;
  *) usage; exit 64 ;;
esac
