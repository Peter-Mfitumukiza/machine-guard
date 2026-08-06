# machine-guard

Integrity-first compromise detection for a developer machine, built after the
2026-06-26 → 2026-08-04 compromise (trojaned global `npm` + clipboard/seed
stealer + a worm that force-pushed forged commits to ~56 repositories).

## Why it is shaped this way

**Integrity is the core; signatures are the garnish.** Signature matching only
finds the campaign you already know about. This operator rotates the campaign ID
per infected host (`A8-4114-1`, `A8-4169-2`), rotates C2 through Ethereum
transactions, and has used at least three different carrier files
(`postcss.config.mjs`, `jest.config.js`, `eslint.config.mjs`). A signature list
is permanently one variant behind.

Asking *"has something that should never change, changed?"* is variant-agnostic.
Concretely: **it would have caught the 2026-06-26 compromise on 2026-06-26.**
`npm/lib/cli.js` changed and `com.clipboard-bot.plist` appeared, two hours apart.
Both are pure integrity signals. Neither requires knowing anything about the
malware.

**Detect techniques, not campaigns.** Campaign IDs rotate; tradecraft doesn't.
A >2000-char line in a build config catches the carrier trick whatever the
watermark says. A multi-kilobyte `-e` argv catches stage-2 whatever it contains.

**Deltas only.** On a clean machine the daily job prints nothing and writes one
line to `var/logs/history.log`. A report that repeats itself every morning gets
filtered to trash inside a fortnight, and then it protects nothing.

**Quarantine is scanned, not exempted.** Known artifacts are labelled
`KNOWN-QUARANTINED` — which means every run is a live end-to-end test against
real malware. But an executable bit anywhere under a quarantine root is
`CRITICAL`, because that is precisely where an attacker would hide.

## Usage

```bash
./machine-guard.sh baseline    # capture known-good state (do this on a clean machine)
./machine-guard.sh scan        # full scan
./machine-guard.sh scan --full # include informational findings
./machine-guard.sh quick       # toolchain hash check only (milliseconds)
./machine-guard.sh status      # baseline age, last result
./machine-guard.sh harden-quarantine   # strip exec bit from quarantine roots
```

Exit codes: `0` clean · `1` warnings · `2` CRITICAL

## Layered cadence

One daily job is the wrong shape. The npm implant re-stole credentials on
*every* npm invocation, so a 09:30 scan can leave 24 hours of exfiltration.

```bash
./install.sh all      # daily + pre-push hook + shell check
./install.sh status
./install.sh remove
```

| Layer | When | Cost | Catches |
|---|---|---|---|
| `shell` | every new shell | ms | toolchain modified since baseline |
| `hook`  | every `git push` | ms | **stops a stolen credential leaving the machine** |
| `daily` | 09:30 | ~30s | integrity drift, carriers, runtime, quarantine |

`install.sh` writes a LaunchAgent, appends to `~/.zshrc`, and sets
`git core.hooksPath` globally. Read it before running it.

## What it checks

1. **Integrity** — hash manifest diff (`config/watch.list`): package-manager
   entry points, LaunchAgents/Daemons, SSH keys, git config, shell rc files.
   Reports `CHANGED` / `NEW` / `REMOVED` / `MODE`.
2. **Package-manager entry points** — structural, baseline-independent. Genuine
   npm `cli.js` is ~407 B / 12 lines / longest line ~79. The implant made it
   70,483 B with a 70,074-char line.
3. **Runtime** — inline-eval processes matched by *executable* (not command-line
   substring), oversized argv, package-manager parentage, clipboard-stealer
   processes, live connections to known C2, new persistent launchd labels.
4. **Quarantine hygiene** — executable bits under any quarantine root.
5. **Carrier technique** — build-config files with pathologically long lines.
6. **Known signatures** — scoped, last, and least trusted.

## Tuning

- `config/watch.list` — what integrity covers. Everything listed is something
  you assert should never change silently.
- `config/allow.list` — regex suppressions. **Keep this tight.** It exists
  because security tooling and incident docs must contain IoC strings to work;
  a scanner that flags scanners trains you to ignore it. That failure is not
  hypothetical — it is exactly how one team's `malware-scan` CI ended up
  failing on its own `.husky/pre-push` during a live incident.

## Known limitations

Stated plainly, because a tool whose blind spots you don't know is worse than
one whose blind spots you do.

- **Baseline trust.** The manifest is only as good as the machine when captured.
  Baseline on a machine you have reason to believe is clean. `baseline` refuses
  to run when integrity CRITICALs are outstanding, unless `MG_FORCE=1`.
- **Point-in-time runtime checks.** A payload that runs between scans and exits
  is invisible to §3. The shell/pre-push layers narrow this window; they don't
  close it.
- **Signature section is inherently reactive.** It will not catch a new variant.
  That is why it is last and least trusted — sections 1, 2, 4 and 5 are the ones
  designed to survive a rebrand.
- **Not tamper-proof.** Anything running as your user can modify this tool, its
  manifest, or its LaunchAgent. It raises the cost of a quiet compromise; it does
  not make one impossible.
- **`allow.list` is an attack surface.** A path suppressed here is a path a
  payload could hide in. Review it when you change it.
