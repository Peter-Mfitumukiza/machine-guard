#!/usr/bin/env bash
#
# machine-guard -- integrity-first compromise detection for a developer machine.
#
#   baseline           capture the known-good hash manifest
#   scan               full scan: integrity + toolchain + runtime + quarantine + techniques + autorun + signatures
#   accept PATH...     accept ONE reviewed change into the baseline (-m, -y, --all, --force)
#   quick              fast toolchain integrity check (shell startup / pre-push hook)
#   harden-quarantine  strip the executable bit from every quarantine root
#   status             manifest age, last scan result, recent accepts
#   selftest           prove the structural checks fire on a synthetic fixture
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
#  * OPENING A FOLDER IS AN EXECUTION SURFACE. The 2026-10 wave (PR #37 on
#    jdufitum/user-vendor-microservice) carried no build-config tail and no
#    known string at all: a hidden `runOn: folderOpen` task in .vscode/tasks.json
#    ran `node` on a "font" that was really 14 KB of padded, obfuscated JS, and
#    .vscode/settings.json pre-approved automatic tasks so VS Code never asked.
#    Every check we had passed it. So: flag auto-run tasks, flag interpreters
#    pointed at non-script files, and flag the whitespace padding itself, in
#    files of ANY extension -- the padding is the one trick every wave reuses.
#
#  * DELTAS ONLY. If nothing changed, say nothing. A daily report that repeats
#    itself gets filtered to trash, and then it protects nothing.
#
#  * QUARANTINE IS SCANNED, NOT EXEMPTED. Known artifacts are labelled
#    KNOWN-QUARANTINED (informational). An executable bit under a quarantine
#    root is CRITICAL -- that is where an attacker would hide.
#
#  * ACCEPTANCE IS PER-FINDING, NOT ALL-OR-NOTHING. Most CRITICALs on a real
#    machine are you editing your own dotfiles. If the only way to clear one
#    were "re-baseline everything", then every benign edit would also bless
#    whatever else happened to be outstanding in the same scan -- and the
#    operator would learn to reflex-force. `accept PATH` re-hashes exactly the
#    paths you name, leaves every other finding standing, and writes an audit
#    line so the decision is reviewable later.
#
#  * ACCEPT ONLY WHAT WAS REVIEWED. Because `accept` re-hashes live, a file
#    edited between the scan you read and the accept you typed would be blessed
#    sight unseen -- the exact outcome this command exists to prevent. `scan`
#    records what it observed to var/.observed.tsv; `accept` refuses a path
#    whose hash has moved on since, and says so, rather than quietly widening
#    what you agreed to. This is not hypothetical: it happened on 2026-08-12,
#    when a .zshrc edit landed one minute after the scan read the file.
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
ACCEPTLOG="$VAR/accepted.log"
# What the last scan actually observed on disk, so `accept` can bless only the
# state the operator was shown. Outlives the scan process by design -- `accept`
# runs later, from a different PID -- so it is NOT in the cleanup trap.
OBSERVED="$VAR/.observed.tsv"
mkdir -p "$VAR" 2>/dev/null

# Scratch paths are declared at script scope, not inside the function that uses
# them. A `local` variable is out of scope by the time an EXIT trap fires, and
# under `set -u` the trap then dies on an unbound variable and cleans up
# nothing -- which is how .targets/.findings files came to litter var/.
FINDINGS="$VAR/.findings.$$"
TARGETS="$VAR/.targets.$$"
: > "$FINDINGS"

# Set only by `selftest`, to point the project checks at a throwaway fixture.
# Assigned here rather than read from the environment, so nothing outside this
# script -- a poisoned shell rc, a LaunchAgent -- can steer a scan away from
# your real projects.
ROOTS_OVERRIDE=""
SELFTEST_DIR=""
# macOS TMPDIR ends in "/"; strip it so the cleanup pattern matches one exact form.
SELFTEST_TMP="${TMPDIR:-/tmp}"; SELFTEST_TMP="${SELFTEST_TMP%/}"
cleanup() {
  rm -f "$FINDINGS" "$FINDINGS.q" "$TARGETS" 2>/dev/null
  # Only ever a directory selftest created itself.
  case "$SELFTEST_DIR" in
    "$SELFTEST_TMP"/mg-selftest.??????) rm -rf "$SELFTEST_DIR" ;;
  esac
}
trap cleanup EXIT

FULL="${MG_FULL:-0}"
QUIET=0
# Set only by `scan`, so that the integrity passes run by `baseline` and
# `accept --all` do not overwrite the record `accept` validates against.
RECORD_OBSERVED=0
ACCEPT_FORCE=0

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

# Record what a scan saw for a reported path: path \t hash \t mode, with "-"
# for a file that is gone. File-backed for the same reason findings are -- the
# NEW-file check runs inside a pipeline, so a shell variable would be discarded.
observe() {
  [ "$RECORD_OBSERVED" = 1 ] || return 0
  printf '%s\t%s\t%s\n' "$1" "${2:--}" "${3:--}" >> "$OBSERVED"
  return 0
}

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

# Where project checkouts live. Shared by the technique and autorun checks so
# they can never disagree about what "your projects" means.
project_roots() {
  local d
  [ -n "$ROOTS_OVERRIDE" ] && { printf '%s\n' "$ROOTS_OVERRIDE"; return 0; }
  for d in "$HOME/Documents" "$HOME/Desktop" "$HOME/Projects" "$HOME/dev" "$HOME/code" "$HOME/work"; do
    [ -d "$d" ] && printf '%s\n' "$d"
  done
}

# Directories that hold generated or third-party code, never your own source.
# Package caches (.pnpm-store, .yarn, .npm) store README tables and source maps
# under extensionless content hashes; they are node_modules by another name.
PRUNE_DIRS=(node_modules .pnpm-store .yarn .npm .cache .git .next .nuxt .svelte-kit .turbo dist build coverage .venv venv vendor Pods .dart_tool .gradle)

# Extensions an interpreter may legitimately be handed. Anything else after
# `node` -- a .woff2, a .llf, a .png -- is a payload wearing a costume.
SCRIPT_EXT_RE='\.(js|mjs|cjs|ts|mts|cts|jsx|tsx|py|rb|pl|sh)$'

# Asset types that are binary by format. A text body in one of these is code.
ASSET_EXT_RE='\.(woff2?|ttf|otf|eot|llf|png|jpe?g|gif|ico|webp|bmp|mp3|mp4|wav)$'

# A run of 200+ blanks followed by more content on the same line: the trick
# every wave of this family has used to push code past the edge of the editor
# and out of a diff view. Measured: zero legitimate source hits on this machine.
PAD_RE='[[:blank:]]{200,}[^[:blank:]]'

# ===========================================================================
cmd_baseline() {
  echo "machine-guard :: capturing integrity baseline"
  echo
  if [ "${MG_FORCE:-0}" != "1" ] && [ -f "$MANIFEST" ]; then
    QUIET=1; check_integrity >/dev/null 2>&1; QUIET=0
    if [ "$(count_of CRITICAL)" != "0" ]; then
      echo "  REFUSING: integrity CRITICAL findings are present."
      echo "  Baselining now would freeze a possible compromise in as 'known good'."
      echo
      echo "  Review them with 'machine-guard.sh scan', then accept each one you"
      echo "  recognise INDIVIDUALLY -- that clears it without blessing the rest:"
      echo
      echo "      machine-guard.sh accept /path/to/file -m \"why this changed\""
      echo
      echo "  MG_FORCE=1 still works, but it accepts every outstanding finding at"
      echo "  once and records no reason. Prefer 'accept'."
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
# accept -- clear a reviewed finding without re-baselining the whole machine.
#
# Manifest lines are  hash \t size \t mode \t path  sorted on path. Rewriting a
# single entry is an awk delete + append + sort; awk compares $4 as an exact
# string, so paths containing regex metacharacters are handled correctly (grep
# -F would still match a substring, and `sed` would need escaping).
# ===========================================================================

# Normalise a user-supplied path to the absolute form stored in the manifest,
# without requiring the file to exist (REMOVED findings must be acceptable too).
resolve_path() {
  local p="${1/#\~/$HOME}" d b
  case "$p" in /*) ;; *) p="$PWD/$p" ;; esac
  d="$(dirname "$p")"; b="$(basename "$p")"
  if [ -d "$d" ]; then d="$(cd "$d" 2>/dev/null && pwd)"; fi
  printf '%s' "${d%/}/$b"
}

accept_log() {
  [ -f "$ACCEPTLOG" ] || printf '# when\taction\tpath\told-hash\tnew-hash\treason\n' > "$ACCEPTLOG"
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$1" "$2" "${3:--}" "${4:--}" "${5:--}" >> "$ACCEPTLOG"
}

# Does the file still look the way the last scan reported it?
#
# Returns 0 to proceed, 1 to refuse. A path the last scan never reported is
# allowed through with a note rather than blocked: `accept` is also how you
# clear a finding you reasoned about by other means, and hard-failing there
# would push operators straight to --force, which is worse than a note.
accept_matches_scan() {
  local f="$1" obs seen_hash seen_mode cur
  [ "$ACCEPT_FORCE" = 1 ] && return 0

  obs="$(awk -F'\t' -v p="$f" '$1==p{l=$0} END{if(l!="")print l}' "$OBSERVED" 2>/dev/null)"
  if [ -z "$obs" ]; then
    printf '  NOTE      %s\n' "$f"
    printf '            not reported by the last scan -- accepting on your judgement,\n'
    printf '            not on something machine-guard showed you.\n'
    return 0
  fi

  seen_hash=""; seen_mode=""
  IFS=$'\t' read -r _ seen_hash seen_mode <<<"$obs"

  if [ "$seen_hash" = "-" ]; then
    [ ! -f "$f" ] && return 0
    printf '  STALE     %s\n' "$f"
    printf '            the scan reported this file as REMOVED, but it exists again now.\n'
    printf '            Re-scan and review what came back before accepting.\n'
    return 1
  fi

  cur="$(hash_of "$f")"
  if [ "$cur" != "$seen_hash" ]; then
    printf '  STALE     %s\n' "$f"
    printf '            changed AGAIN since the scan you are accepting from:\n'
    printf '            scan saw sha256 %s…, on disk now %s…\n' "${seen_hash:0:16}" "${cur:0:16}"
    printf '            Accepting would bless content you have not reviewed.\n'
    printf '            Re-scan, review the new state, then accept (or --force).\n'
    return 1
  fi
  return 0
}

# Rewrite (or remove) exactly one manifest entry. Returns 0 if it changed.
manifest_set() {
  local f="$1" newline="${2:-}" tmp="$MANIFEST.tmp.$$"
  awk -F'\t' -v p="$f" '$4 != p' "$MANIFEST" > "$tmp" || return 1
  [ -n "$newline" ] && printf '%s\n' "$newline" >> "$tmp"
  LC_ALL=C sort -t"$(printf '\t')" -k4 "$tmp" -o "$tmp" && mv "$tmp" "$MANIFEST"
}

accept_one() {
  local f="$1" reason="$2" targets="$3"
  local oldline ohash osize omode nhash nsize nmode

  # TOCTOU guard. `accept` re-hashes live, so anything that lands between the
  # scan the operator read and the accept they typed would be blessed sight
  # unseen -- the one failure this command exists to prevent. Compare against
  # what the last scan actually observed and refuse if the file has moved on.
  if ! accept_matches_scan "$f"; then return 1; fi

  oldline="$(awk -F'\t' -v p="$f" '$4==p{print; exit}' "$MANIFEST")"
  IFS=$'\t' read -r ohash osize omode _ <<<"${oldline:-}"

  if [ -z "$oldline" ] && ! grep -qxF "$f" "$targets"; then
    printf '  SKIP      %s\n' "$f"
    printf '            not a watched path -- nothing to accept. Watched paths come\n'
    printf '            from config/watch.list; a finding elsewhere is not an\n'
    printf '            integrity finding and accept cannot silence it.\n'
    return 1
  fi

  # REMOVED: entry exists, file is gone.
  if [ -n "$oldline" ] && [ ! -f "$f" ]; then
    manifest_set "$f" ""
    accept_log REMOVED "$f" "$ohash" "-" "$reason"
    printf '  REMOVED   %s\n            dropped from baseline\n' "$f"
    return 0
  fi

  nhash="$(hash_of "$f")"; nsize="$(size_of "$f")"; nmode="$(mode_of "$f")"

  # NEW: file is watched but absent from the manifest.
  if [ -z "$oldline" ]; then
    manifest_set "$f" "$(printf '%s\t%s\t%s\t%s' "$nhash" "$nsize" "$nmode" "$f")"
    accept_log NEW "$f" "-" "$nhash" "$reason"
    printf '  NEW       %s\n            added to baseline  sha256 %s…  mode %s\n' \
      "$f" "${nhash:0:16}" "$nmode"
    return 0
  fi

  if [ "$nhash" = "$ohash" ] && [ "$nmode" = "$omode" ]; then
    printf '  UNCHANGED %s\n            already matches the baseline; nothing to accept\n' "$f"
    return 1
  fi

  manifest_set "$f" "$(printf '%s\t%s\t%s\t%s' "$nhash" "$nsize" "$nmode" "$f")"
  if [ "$nhash" != "$ohash" ]; then
    accept_log CHANGED "$f" "$ohash" "$nhash" "$reason"
    printf '  ACCEPTED  %s\n            %sB -> %sB   sha256 %s… -> %s…\n' \
      "$f" "$osize" "$nsize" "${ohash:0:16}" "${nhash:0:16}"
  else
    accept_log MODE "$f" "$omode" "$nmode" "$reason"
    printf '  ACCEPTED  %s\n            mode %s -> %s\n' "$f" "$omode" "$nmode"
  fi
  return 0
}

cmd_accept() {
  local reason="" assume_yes=0 all=0 args=() a
  while [ $# -gt 0 ]; do
    a="$1"
    case "$a" in
      -m|--message) reason="${2:-}"; shift 2 ;;
      -y|--yes)     assume_yes=1; shift ;;
      --all)        all=1; shift ;;
      --force)      ACCEPT_FORCE=1; shift ;;
      --full|--quiet) shift ;;
      -*)           echo "  unknown option: $a"; return 64 ;;
      *)            args+=("$a"); shift ;;
    esac
  done

  if [ ! -f "$MANIFEST" ]; then
    echo "  no baseline yet -- run: machine-guard.sh baseline"; return 2
  fi

  expand_targets > "$TARGETS"

  # --all: derive the path list from a real integrity pass, so it accepts what
  # is genuinely outstanding rather than re-hashing every watched file.
  if [ "$all" = 1 ]; then
    QUIET=1; check_integrity >/dev/null 2>&1; QUIET=0
    while IFS=$'\t' read -r _ msg; do
      case "$msg" in
        CHANGED*|NEW*|REMOVED*|MODE*) args+=("$(printf '%s' "${msg#* }" | sed 's/^ *//')") ;;
      esac
    done < <(grep -E '^(CRITICAL|WARN)' "$FINDINGS" 2>/dev/null)
    : > "$FINDINGS"
  fi

  if [ ${#args[@]} -eq 0 ]; then
    echo "  usage: machine-guard.sh accept <path>... [-m \"reason\"] [-y]"
    echo "         machine-guard.sh accept --all   [-m \"reason\"] [-y]"
    echo
    echo "  Accepts ONLY the paths you name. Every other finding stays outstanding."
    return 64
  fi

  echo "machine-guard :: accept  $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  echo
  echo "  You are asserting these changes are yours and were reviewed."
  echo "  A wrong accept is how a compromise becomes 'known good' permanently."
  echo
  local f; for f in "${args[@]}"; do echo "    $(resolve_path "$f")"; done
  echo
  [ -n "$reason" ] && echo "  reason: $reason" || \
    echo "  reason: (none given -- prefer -m \"why\", the audit log is the point)"
  echo

  if [ "$assume_yes" != 1 ] && [ -t 0 ]; then
    printf '  Proceed? [y/N] '; local ans; read -r ans
    case "$ans" in y|Y|yes|YES) ;; *) echo "  aborted."; return 1 ;; esac
    echo
  fi

  local changed=0
  for f in "${args[@]}"; do
    accept_one "$(resolve_path "$f")" "$reason" "$TARGETS" && changed=$((changed + 1))
  done

  if [ "$changed" -gt 0 ]; then
    # Read every value BEFORE the redirect opens. `> file` truncates at the
    # moment the block starts, so a $(grep ... file) inside it reads the file
    # it is already clobbering -- which silently blanked `captured:`, losing
    # the baseline date on the first accept. Build elsewhere, then move.
    local cap ents labs meta_tmp
    cap="$(grep '^captured:' "$VAR/manifest.meta" 2>/dev/null | cut -d' ' -f2-)"
    ents="$(wc -l < "$MANIFEST" | tr -d ' ')"
    labs="$(wc -l < "$VAR/launchd.list" 2>/dev/null | tr -d ' ')"
    meta_tmp="$VAR/manifest.meta.tmp.$$"
    { echo "captured: $cap"
      echo "host: $(hostname)"
      echo "entries: $ents"
      echo "launchd labels: $labs"
      echo "last accept: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"; } > "$meta_tmp" \
      && mv "$meta_tmp" "$VAR/manifest.meta"
  fi

  echo
  echo "  $changed entr(y|ies) accepted -> $MANIFEST"
  echo "  audit trail: $ACCEPTLOG"
  echo "  Re-run 'machine-guard.sh scan' to confirm what is still outstanding."
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
    if [ ! -f "$f" ]; then warn "REMOVED  $f"; observe "$f" "-" "-"; continue; fi
    local nhash nmode
    nhash="$(hash_of "$f")"; nmode="$(mode_of "$f")"
    if [ "$nhash" != "$ohash" ]; then
      crit "CHANGED  $f"
      note "was ${osize}B, now $(size_of "$f")B   sha256 ${ohash:0:16}… -> ${nhash:0:16}…"
      observe "$f" "$nhash" "$nmode"
    elif [ "$nmode" != "$omode" ]; then
      warn "MODE     $f  ($omode -> $nmode)"
      observe "$f" "$nhash" "$nmode"
    fi
  done < "$MANIFEST"

  expand_targets | while IFS= read -r f; do
    cut -f4 "$MANIFEST" | grep -qxF "$f" || echo "$f"
  done | while IFS= read -r f; do
    crit "NEW      $f"
    note "appeared since baseline (a new LaunchAgent or SSH key is exactly how"
    note "both 2026-06-26 payloads announced themselves)"
    observe "$f" "$(hash_of "$f")" "$(mode_of "$f")"
  done

  [ "$(count_of CRITICAL)" = "0" ] && [ "$(count_of WARN)" = "0" ] && line "no changes against baseline"
  return 0
}

# Follow a symlink chain to the real file (macOS readlink has no -f before 12.3).
real_path() {
  local p="$1" l
  while [ -L "$p" ]; do
    l="$(readlink "$p")"
    case "$l" in /*) p="$l" ;; *) p="$(dirname "$p")/$l" ;; esac
  done
  printf '%s/%s' "$(cd "$(dirname "$p")" 2>/dev/null && pwd)" "$(basename "$p")"
}

npm_entry_points() {
  local p r
  { for p in "$HOME"/.nvm/versions/node/*/lib/node_modules/npm/lib/cli.js \
             "$HOME"/.local/share/mise/installs/node/*/lib/node_modules/npm/lib/cli.js \
             "$HOME"/.local/share/fnm/node-versions/*/installation/lib/node_modules/npm/lib/cli.js \
             "$HOME"/.asdf/installs/nodejs/*/lib/node_modules/npm/lib/cli.js \
             "$HOME"/.volta/tools/image/node/*/lib/node_modules/npm/lib/cli.js \
             "$HOME"/.hermes/node/lib/node_modules/npm/lib/cli.js \
             /usr/local/lib/node_modules/npm/lib/cli.js \
             /opt/homebrew/lib/node_modules/npm/lib/cli.js; do
      [ -f "$p" ] && printf '%s\n' "$p"
    done
    # Interactive-shell PATH is not launchd's PATH, so also try the usual
    # user bin dirs explicitly; a shim there is exactly what we are hunting.
    for p in "$(command -v npm 2>/dev/null)" "$HOME/.local/bin/npm" /usr/local/bin/npm /opt/homebrew/bin/npm; do
      [ -n "$p" ] && [ -e "$p" ] || continue
      r="$(real_path "$p")"                       # .../npm/bin/npm-cli.js
      r="$(dirname "$(dirname "$r")")/lib/cli.js" # .../npm/lib/cli.js
      [ -f "$r" ] && printf '%s\n' "$r"
    done
  } | sort -u
}

# ===========================================================================
check_toolchain() {
  sec "2. Package-manager entry points  (structural, baseline-independent)"
  local found=0 p maxlen lines sz tc_before
  tc_before="$(count_of CRITICAL)"
  # Fixed locations, PLUS whatever `npm` actually resolves to. Tools ship their
  # own Node and put it first on PATH -- Hermes Agent did, via ~/.local/bin --
  # and a list of version-manager paths is blind to that npm, which is the one
  # that runs when you type `npm`.
  while IFS= read -r p; do
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
  done < <(npm_entry_points)
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
          # An interpreter handed a font or image is running a disguised
          # payload -- `node ./public/fonts/fa-solid-300.llf` in the 2026-10 wave.
          if printf '%s' "$sarg" | grep -qiE "$ASSET_EXT_RE"; then
            crit "interpreter running a file disguised as an asset (pid $pid)"
            note "$commbase $sarg"
            note "parent: $pcmd"
          fi
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
  local scan_roots
  scan_roots="$(project_roots | tr '\n' ' ')"
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
# Report one autorun finding, honouring the allow list and quarantine. Takes
# the severity so a caller can downgrade without duplicating the plumbing.
autorun_hit() {
  local sev="$1" f="$2"; shift 2
  allowed "$f" && return 0
  if is_quarantined "$f"; then info "KNOWN-QUARANTINED: $* ($f)"; return 0; fi
  "$sev" "$*: $f"
}

# `node X` targets inside a tasks.json command or a package.json script.
# Prints one target per line, options skipped.
node_targets() {
  grep -oE '(^|[^[:alnum:]_./-])node[[:space:]]+[^[:space:]"&|;)<>]+' "$1" 2>/dev/null \
    | sed -E 's/^.*node[[:space:]]+//' | grep -v '^-'
}

check_autorun() {
  sec "6. Editor auto-run & disguised payloads  (opening a folder must not run code)"
  local roots; roots="$(project_roots | tr '\n' ' ')"
  [ -z "$roots" ] && { line "no project directories"; return 0; }
  local before before_w; before="$(count_of CRITICAL)"; before_w="$(count_of WARN)"
  local prune=() d
  for d in "${PRUNE_DIRS[@]}"; do prune+=(-name "$d" -o); done
  unset 'prune[${#prune[@]}-1]'

  # 6a. Workspace config that runs, or pre-approves running, code on open.
  #     tasks.json may legitimately auto-run (rare); hiding it, pointing an
  #     interpreter at something, or approving it on the user's behalf is not.
  # shellcheck disable=SC2086
  find $roots \( "${prune[@]}" \) -prune -o -type f \
       \( -path '*/.vscode/tasks.json' -o -path '*/.vscode/settings.json' -o -name '*.code-workspace' \) \
       -print 2>/dev/null | \
  while IFS= read -r f; do
    if grep -qE '"task\.allowAutomaticTasks"[[:space:]]*:[[:space:]]*(true|"on")' "$f"; then
      autorun_hit crit "$f" "workspace pre-approves automatic tasks (disables VS Code's consent prompt)"
    fi
    grep -qE '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f" || continue
    local cmd; cmd="$(grep -oE '"command"[[:space:]]*:[[:space:]]*"[^"]*"' "$f" | head -3 | cut -c1-150)"
    if grep -qE '"(reveal)"[[:space:]]*:[[:space:]]*"never"|"(hide)"[[:space:]]*:[[:space:]]*true|"(echo)"[[:space:]]*:[[:space:]]*false' "$f"; then
      autorun_hit crit "$f" "HIDDEN task that runs on folder open"
    elif [ "${f##*/}" = "settings.json" ]; then
      autorun_hit crit "$f" "folder-open task smuggled into settings.json"
    elif printf '%s' "$cmd" | grep -qE '(^|[^[:alnum:]])(node|deno|bun|python[0-9.]*|bash|sh|zsh|curl|wget|powershell|pwsh|cmd)([^[:alnum:]]|$)'; then
      autorun_hit crit "$f" "folder-open task launches an interpreter"
    else
      autorun_hit warn "$f" "task runs automatically on folder open"
    fi
    [ -n "$cmd" ] && printf '%s\n' "$cmd" | while IFS= read -r c; do note "$c"; done
  done

  # 6b. Interpreters pointed at files that are not scripts, and runners that
  #     a build/start script executes before the real command.
  # shellcheck disable=SC2086
  find $roots \( "${prune[@]}" \) -prune -o -type f \
       \( -path '*/.vscode/tasks.json' -o -name 'package.json' \) -print 2>/dev/null | \
  while IFS= read -r f; do
    local base t tp
    base="$(dirname "$f")"; [ "${base##*/}" = ".vscode" ] && base="$(dirname "$base")"
    node_targets "$f" | sort -u | while IFS= read -r t; do
      tp="$base/${t#./}"
      if printf '%s' "$t" | grep -qiE "$ASSET_EXT_RE"; then
        autorun_hit crit "$f" "runs 'node $t' -- a payload disguised as an asset"
      elif [ -f "$tp" ] && grep -qE "$PAD_RE" "$tp" 2>/dev/null; then
        autorun_hit crit "$f" "runs 'node $t', which hides code behind whitespace padding"
      elif [ -f "$tp" ] && ! printf '%s' "$t" | grep -qE "$SCRIPT_EXT_RE"; then
        autorun_hit warn "$f" "runs 'node $t' -- not a script extension"
      fi
    done
  done

  # 6c. Whitespace padding in ANY text file, whatever its extension. grep -I
  #     skips real binaries, so a genuine font never matches; a "font" that
  #     is text with code shoved 400 tabs to the right does.
  local exdirs=()
  for d in "${PRUNE_DIRS[@]}"; do exdirs+=(--exclude-dir="$d"); done
  # shellcheck disable=SC2086
  grep -rIlE "$PAD_RE" $roots "${exdirs[@]}" \
       --exclude='*.md' --exclude='*.txt' --exclude='*.rst' --exclude='*.csv' \
       --exclude='*.tsv' --exclude='*.log' --exclude='*.map' 2>/dev/null | \
  while IFS= read -r f; do
    if printf '%s' "$f" | grep -qiE "$ASSET_EXT_RE"; then
      autorun_hit crit "$f" "text payload disguised as an asset, hidden behind whitespace padding"
    else
      autorun_hit crit "$f" "code hidden behind a 200+ blank run on one line"
    fi
    note "inspect without running: awk '{print length}' '$f' ; sed -E 's/^[[:blank:]]+//' '$f' | head -c 300"
  done

  # 6d. Asset files with a text body. Real fonts and images are binary.
  # shellcheck disable=SC2086
  find $roots \( "${prune[@]}" \) -prune -o -type f -size +0 \
       \( -iname '*.woff' -o -iname '*.woff2' -o -iname '*.ttf' -o -iname '*.otf' \
          -o -iname '*.eot' -o -iname '*.llf' \) -print 2>/dev/null | \
  while IFS= read -r f; do
    grep -qIE "$PAD_RE" "$f" 2>/dev/null && continue   # already reported by 6c
    grep -qI '[^[:space:]]' "$f" 2>/dev/null || continue
    autorun_hit crit "$f" "font file is plain text -- likely a disguised script"
  done

  [ "$(count_of CRITICAL)" = "$before" ] && [ "$(count_of WARN)" = "$before_w" ] \
    && line "no auto-run tasks, disguised payloads, or padded code"
  return 0
}

# ===========================================================================
check_signatures() {
  sec "7. Known signatures  (scoped -- last, and least trusted)"
  local roots="" d
  for d in "$HOME/Documents" "$HOME/Desktop" "$HOME/Downloads"; do [ -d "$d" ] && roots="$roots $d"; done
  [ -n "$ROOTS_OVERRIDE" ] && roots="$ROOTS_OVERRIDE"
  [ -z "$roots" ] && return 0
  local before; before="$(count_of CRITICAL)"

  # The watermark is matched loosely: the 2026-10 wave wrote
  # `global['!'] = '8-J'` -- spaced, and a different prefix -- and the old
  # literal `='9-` missed it. `v8('',x8)(` is the closing call both of that
  # wave's payloads shared.
  local pat="global\['e'\]='NPM'|global\.i *= *['\"]A8-|global\[.!.\] *= *['\"][0-9A-Za-z]+-|v8\('',x8\)\(|_\\\$_1e42|_\\\$af163278|_\\\$_ccfc|0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a|TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP|166\.88\.8\.133|PAYLOAD_TYPE *= *\"A8\""

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
  if [ -s "$ACCEPTLOG" ]; then
    echo
    echo "recent accepts (baseline entries you asserted were yours):"
    grep -v '^#' "$ACCEPTLOG" | tail -5 | while IFS=$'\t' read -r w act p _ _ r; do
      printf '  %s  %-8s %s\n' "$w" "$act" "$p"
      [ "$r" != "-" ] && [ -n "$r" ] && printf '  %s   reason: %s\n' "$(printf '%20s' '')" "$r"
    done
  fi
}

# ===========================================================================
# selftest -- prove the structural checks still fire, without real malware.
#
# Builds a replica of the PR #37 attack SHAPE (jdufitum/user-vendor-microservice,
# 2026-10) from synthetic, inert content: every "payload" is a comment, so even
# opening the fixture in VS Code runs nothing. A clean control project sits next
# to it and must produce zero findings. Everything lives in a mktemp directory
# that the EXIT trap removes; nothing is written to your project folders.
#
# Indicator strings are assembled at runtime so this file never contains them
# verbatim and cannot trip a scanner -- including this one -- on its own source.
# ===========================================================================
selftest_fixture() {
  local bad="$1" clean="$2" pad wm tail
  pad="$(printf '%424s' '' | tr ' ' '\t')"
  wm="global["; wm="$wm'!'] = '8-J'"
  tail="v8(''"; tail="$tail,x8)("

  mkdir -p "$bad/.vscode" "$bad/public/fonts"
  printf '%s/* %s; MG-SELFTEST inert placeholder */\n' "$pad" "$wm" > "$bad/public/fonts/fa-solid-300.llf"
  printf '%s/* MG-SELFTEST inert placeholder %s0) */\n' "$pad" "$tail" > "$bad/api.js"
  printf 'module.exports = 0; // MG-SELFTEST: a "font" with a text body\n' > "$bad/public/fonts/fa-solid-400.woff2"
  { printf 'export default { plugins: {} };'
    printf '%s/* MG-SELFTEST inert carrier tail %s */\n' "$pad" "$(printf '%2100s' '' | tr ' ' 'x')"
  } > "$bad/postcss.config.mjs"
  cat > "$bad/package.json" <<'J'
{
  "name": "mg-selftest-bad",
  "private": true,
  "scripts": {
    "build": "node api.js && nest build",
    "start": "node api.js && nest start"
  }
}
J
  cat > "$bad/.vscode/tasks.json" <<'J'
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "eslint-check",
      "type": "shell",
      "command": "(command -v node >/dev/null 2>&1 && node ./public/fonts/fa-solid-300.llf) || echo ''",
      "hide": true,
      "presentation": { "reveal": "never", "echo": false, "close": true },
      "runOptions": { "runOn": "folderOpen" }
    }
  ]
}
J
  cat > "$bad/.vscode/settings.json" <<'J'
{
  "task.allowAutomaticTasks": true,
  "terminal.integrated.hideOnStartup": "always",
  "tasks": { "label": "lint on open", "type": "shell", "command": "npm run lint", "runOn": "folderOpen" }
}
J

  # The control: things that LOOK like the attack but are normal.
  mkdir -p "$clean/.vscode" "$clean/scripts" "$clean/public/fonts" "$clean/.pnpm-store/v3/files/ab"
  cat > "$clean/.vscode/tasks.json" <<'J'
{ "version": "2.0.0", "tasks": [ { "label": "build", "type": "shell", "command": "npm run build" } ] }
J
  printf '{ "editor.formatOnSave": true }\n' > "$clean/.vscode/settings.json"
  cat > "$clean/package.json" <<'J'
{ "name": "mg-selftest-clean", "scripts": { "build": "node scripts/build.js && tsc", "start": "node dist/main" } }
J
  printf 'console.log("build");\n' > "$clean/scripts/build.js"
  printf 'wOF2\000\001\000\000\000\000\000\000' > "$clean/public/fonts/real.woff2"   # binary, as fonts are
  printf '| Option |%250s| Default |\n' '' > "$clean/README.md"                       # wide table: docs are excluded
  printf '| Option |%250s| Default |\n' '' > "$clean/.pnpm-store/v3/files/ab/cdef01"  # package cache: pruned
}

cmd_selftest() {
  echo "machine-guard :: selftest  (synthetic fixture, no real malware)"
  SELFTEST_DIR="$(mktemp -d "$SELFTEST_TMP/mg-selftest.XXXXXX")" || return 2
  local bad="$SELFTEST_DIR/bad" clean="$SELFTEST_DIR/clean"
  selftest_fixture "$bad" "$clean"

  build_allow_re
  ROOTS_OVERRIDE="$SELFTEST_DIR"; QUIET=1
  check_techniques >/dev/null 2>&1
  check_autorun    >/dev/null 2>&1
  check_signatures >/dev/null 2>&1
  QUIET=0; ROOTS_OVERRIDE=""

  # One line per part of the attack: finding text | file it must be reported on.
  local fail=0 want where
  while IFS='|' read -r want where; do
    if grep -E '^(CRITICAL|WARN)' "$FINDINGS" | grep -F "$want" | grep -qF "$bad/$where"; then
      printf '  PASS  %-58s %s\n' "$want" "$where"
    else
      printf '  FAIL  %-58s %s  <- NOT DETECTED\n' "$want" "$where"; fail=1
    fi
  done <<'EOF'
workspace pre-approves automatic tasks|.vscode/settings.json
folder-open task smuggled into settings.json|.vscode/settings.json
HIDDEN task that runs on folder open|.vscode/tasks.json
a payload disguised as an asset|.vscode/tasks.json
hides code behind whitespace padding|package.json
text payload disguised as an asset|public/fonts/fa-solid-300.llf
code hidden behind a 200+ blank run|api.js
font file is plain text|public/fonts/fa-solid-400.woff2
build-config with a|postcss.config.mjs
payload signature in active source|api.js
EOF

  local fp; fp="$(grep -E '^(CRITICAL|WARN)' "$FINDINGS" | grep -F "$clean/")"
  if [ -z "$fp" ]; then
    printf '  PASS  %-58s %s\n' "clean control project: no findings" "clean/"
  else
    printf '  FAIL  clean control project raised false positives:\n'
    printf '%s\n' "$fp" | cut -f2 | sed 's/^/          /'; fail=1
  fi

  echo
  if [ "$fail" = 0 ]; then echo "  RESULT: PASS -- every check fired, no false positives"; else echo "  RESULT: FAIL"; fi
  return "$fail"
}

cmd_scan() {
  local started; started=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
  echo "machine-guard :: scan  $started  host $(hostname)"
  build_allow_re

  # This scan becomes the record `accept` validates against, so it replaces the
  # previous one wholesale -- a path that is clean now must not keep an old
  # observation alive and acceptable.
  RECORD_OBSERVED=1
  : > "$OBSERVED"

  check_integrity
  check_toolchain
  check_runtime
  check_quarantine
  check_techniques
  check_autorun
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

usage() { sed -n '3,10p' "$0" | sed 's/^# \{0,1\}//'; }

MAIN="${1:-scan}"; shift 2>/dev/null || true
for a in "$@"; do
  case "$a" in --full) FULL=1 ;; --quiet) QUIET=1 ;; esac
done

case "$MAIN" in
  baseline)          cmd_baseline ;;
  scan)              cmd_scan ;;
  accept)            cmd_accept "$@" ;;
  quick)             cmd_quick ;;
  harden-quarantine) cmd_harden_quarantine ;;
  status)            cmd_status ;;
  selftest)          cmd_selftest ;;
  *) usage; exit 64 ;;
esac
