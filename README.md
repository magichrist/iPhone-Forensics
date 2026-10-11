# iPhone Forensics v5

**One command, one HTML report, zero guesswork.** Point it at a used iPhone and it
collects everything it safely can, then tells you what it found — and, just as
importantly, what it *cannot* tell you.

Local-first, read-only by default, and honest about the line between evidence and inference.

---

## 1. What it does

```bash
iphone-forensics devices     # what's plugged in, and the exact next command
iphone-forensics inspect     # full read-only inspection -> ./iphone-forensics-<stamp>/
```

`inspect` needs no flags. It discovers the device, runs every non-destructive
collector, and writes a run directory in the directory you ran it from:

```
iphone-forensics-20261011-090721/
├── report.html      ← open this first
├── report.json      ← machine-readable, everything the HTML shows
├── manifest.json    ← SHA-256 + size of every artifact
├── README.txt       ← what this directory is
└── evidence/        ← the collected artifacts, one file per collector
```

The HTML report is the product: an executive dashboard, inline SVG charts computed
from the run's own data, and eleven sections. No JavaScript, no CDN, no network —
it opens from a `file://` URL on a machine with no internet.

## 2. Genuine vs impossible

Read this before trusting any verdict. The report carries this table itself, in its
Technical appendix — here is the short version.

| Can establish | Cannot ever establish |
|---|---|
| Identity fields iOS reports (ProductType, build, serial…) | That a device is *genuine* or counterfeit |
| Battery/storage/thermal **candidates** when a tool exposes them | That a part was replaced (Apple has no public parts API) |
| A metadata change between two snapshots | Face ID / display / sensor health (needs a human) |
| Crash and panic **patterns**, weakly | That a device is malware-free |
| What the toolchain could not measure | Parts & Service History (on-device Settings only) |

The report never turns a gap into a verdict. A missing battery metric is
*inconclusive*, never a replaced battery. Every finding is labelled with **how** it
was established: *Verified*, *Inferred*, *Unknown*, or *Manual check required*.

## 3. Install

```bash
brew install libimobiledevice          # the native toolkit (required)
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
pip install -e ".[pymobiledevice3]"    # optional: app/process/crash/syslog access
```

If something is missing, `iphone-forensics doctor` tells you exactly what and how to
install it. It never fails — a missing optional tool is a **WARNING**, not an error.

## 4. A real session

```console
$ iphone-forensics devices
#   #  MODEL            NAME        CONNECTION  TRUST      UDID
#   1  iPhone 15        Ana's phone USB         validated  …CDEF

  Next: iphone-forensics inspect

$ iphone-forensics inspect
  [1/5] discovery        device selected (1 of 1)
  [2/5] collection       9 collectors
  [3/5] triage           crash artifacts scanned
  [4/5] assessment       0 blockers, 2 review items
  [5/5] report           written

  Sensitive collection is off. App inventory, process list, logs, crash pull,
  provisioning and backup require consent.
  Include them for this run? [y/N] N

  Run directory:  ./iphone-forensics-20261011-090721
  Report:         ./iphone-forensics-20261011-090721/report.html
  Verdict:        REVIEW — NEGOTIATE OR INVESTIGATE
  Findings:       1 blocker · 2 review · 5 info
```

Declining loses nothing: the run still completes, and the skipped items are recorded
as `skipped_by_user`, never as failures.

## 5. Where reports live

Output defaults to **the current working directory** — nothing lands on your Desktop
any more. Each run gets its own `iphone-forensics-<UTC stamp>/`; a second run in the
same second becomes `-1`, `-2`, and **never overwrites a previous run**.

```bash
iphone-forensics inspect --output ~/inspections     # advanced: choose the root
```

`iphone-forensics compare ./old-run/report.json` diffs two runs, separating real
device changes from environment differences. A field missing on one side is reported
as *not comparable* — never as a change.

## 6. Sensitive collection

App inventory, process lists, live log capture, crash pull, provisioning profiles,
full backups and MVT backup triage are **off by default**. On a TTY you get one
`y/N` prompt naming exactly what would be collected; in a non-interactive session
they stay off. The choice is recorded in `report.scope.sensitive_collection` as
`granted`, `declined`, or `not_requested`.

```bash
iphone-forensics inspect --yes-sensitive      # automation: consent up front
iphone-forensics inspect --no-sensitive       # automation: never prompt
```

Bounded log capture and full backups always need their own explicit flag — consent
never invents a capture window or takes a backup.

## 7. Reading the report

- **Coverage is not health.** A run can show 100% collection coverage and still
  surface defects. The two measure different things.
- **"Not collected" is not "fine".** Absent data renders as *not collected* or
  *not provided* — never as a zero or a pass.
- **Failed vs unavailable are different.** A missing tool, a declined consent, or a
  timeout is an *evidence gap* about your environment. Only a check that ran and
  returned a negative result is a finding about the device. The report says which.
- **Charts are computed, not drawn.** Every number in a chart is derived from
  `report.json` at render time. When the data is absent, the chart is absent.

---

## Advanced interface

The four commands above are the documented path. For scripting, per-stage control,
repair cases, and machine-readable output, the full engine stays available as
`iphone-surgery`:

```bash
iphone-forensics --help-advanced            # lists every flag and subcommand
iphone-surgery --help
```

```bash
iphone-surgery inspect --device <udid> --syslog-seconds 30
iphone-surgery case --new --udid <udid> --symptoms "battery drains"
iphone-surgery case --json                  # machine roll-up on stdout
iphone-surgery capabilities                 # the full capability matrix
iphone-surgery manual-tests                 # the guided physical test script
iphone-surgery compare --previous a/report.json --current b/report.json --out diff.json
iphone-surgery evidence-verify ./iphone-forensics-20261011-090721
```

Machine-readable outputs: `buyer --json`, `hardware --json`, `case --json`,
`compare --out`, `integrity --out`, `checklist --out`, `config --out`.

Exit codes: `0` clean · `1` findings · `2` usage/config · `3` no device ·
`4` ambiguous device · `5` partial · `6` tool failure.

### Configuration

`iphone-surgery config --out ./iphone-surgery.json` writes a template, auto-loaded
on startup. Precedence: **CLI flag > `--config` > `./iphone-surgery.json` > defaults**.

### v3/v4 compatibility

`report.json` and `manifest.json` are schema `5.0.0` and accept `3.x`/`4.x` on read,
so older run directories still compare and verify. The `iphone-audit-*` directory
name is retired; new runs use `iphone-forensics-*`.

---

## Safety and privacy

`inspect` performs **zero state changes**: no jailbreak, no lock or MDM bypass, no
firmware or settings modification, no deletion, no reset, no app or profile install,
no silent backup, no uploads. Everything stays on your machine.

Device identifiers (UDID, serial, IMEI) are masked in console output and in the
shareable `report-redacted.*` export. The private `report.json` and `evidence/`
retain the real values — they are the evidence of record. Treat a run directory as
sensitive and keep it local.

## Project layout

```
src/iphone_forensics/
├── cli.py           4-command facade (the documented path)
├── cli_v4.py        advanced engine: 16 subcommands
├── collectors.py    discovery + bounded, read-only collection
├── hardware.py      battery/storage normalization + subsystem checks
├── integrity.py     snapshot comparison, 9 classifications
├── analysis.py      findings, assessment, crash triage
├── buyer.py         20-point checklist and verdicts
├── evidence.py      run layout + the single manifest writer
├── reporting.py     offline HTML: dashboard, SVG charts, validator
├── capabilities.py  capability + claim matrices (source of truth)
├── models.py        collection statuses, epistemic labels
└── util.py          bounded subprocesses, redaction, hashing
```

## Development

```bash
python -m pytest -q      # 332 tests, offline: no device required
python -m ruff check src
```

The suite never requires hardware. Device-attached checks skip cleanly when no
iPhone is present.

## License

MIT — see [LICENSE](LICENSE).