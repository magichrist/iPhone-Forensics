# v5 Overview — All-in-One Suite Plan

## Mission
Collapse the public CLI to **4 commands** (`devices`, `inspect`, `doctor`, `compare`) on the single `iphone-forensics` entry point, with `inspect` orchestrating the full safe inspection and writing a timestamped run dir under the **current working directory**. Make `report.html` the main product (dashboard + evidence-derived SVG charts). Standardize collection statuses, keep honesty guarantees, keep everything local-first.

## Why (verified gap)
- Two entry points ship today: `iphone-forensics` (`cli.py`, legacy single-run, ~15 collector flags) and `iphone-surgery` (`cli_v4.py`, **16 subcommands**). Ordinary users must learn module internals to do a normal inspection.
- Output defaults to `~/Desktop/iphone-forensics` in both CLIs (`cli.py:42`, `cli_v4.py:36`). Task requires CWD default.
- Report has 15 sections and solid honesty copy but **no dashboard counts, no charts**, statistics are per-section tables.
- Statuses are fragmented: 7 health levels, 9 integrity classes, 3 collection states (`success`/`expected_end`/`failed_or_partial`). Task requires one consistent collection vocabulary (11 states).
- Sensitive collection is flag-gated (`--app-list`, `--crash-reports`, `--syslog-seconds`, `--backup`, …) with no consent prompt and no single "standard inspection" profile.

## Phase map
1. **P0 audit + harness** (`01-current-state-audit.md`) — freeze behavior baseline, add CLI-surface guard tests.
2. **P1 CLI collapse** (`02-cli-redesign.md`) — 4-command facade on `iphone-forensics`; `cli_v4.py` becomes the engine (import, don't fork); legacy flags → hidden compat layer.
3. **P2 CWD output + manifest** (`03-output-layout.md`) — run dir `./iphone-forensics-<stamp>/`, `evidence/` split, `README.txt`, unique-dir guarantee.
4. **P3 status model + rule engine** (`05-evidence-analysis-model.md`) — 11 collection states end-to-end, evidence trail fields, versioned rules.
5. **P4 report rebuild** (`04-html-report.md`) — dashboard, inline SVG, 11 required sections, a11y/print/offline.
6. **P5 honesty + safety** (`06-authenticity-honesty.md`, `07-safety-privacy.md`) — capability-claim matrix, consent flow, redaction audit.
7. **P6 tests + docs** (`08-testing.md`, `09-docs-structure.md`) — expand suite, README rewrite, doc dedup.
8. **Acceptance gate** (`10-implementation-phases.md`) — the §10 checklist mapped to verifiable commands.

## Non-goals
- No new runtime deps (argparse + stdlib only; charts are inline SVG, no JS libs, no CDN).
- No second implementation of collectors/analysis — reuse `collectors.py`, `hardware.py`, `integrity.py`, `analysis.py`, `buyer.py`, `evidence.py`, `reporting.py`, `capabilities.py`.
- `iphone_audit.py` keeps working (it calls `cli.main`).
- No hardware claims beyond evidence; no network calls; no state-changing operations in `inspect`.

## Acceptance checklist (from task §10, traced in `10-implementation-phases.md`)
Four commands max · devices table · one-command inspect · multi-device selector · no flag soup · CWD output · unique dirs · dashboard + real charts · failed-vs-unavailable explained · honest hardware conclusions · consent-gated sensitive collection · consistent redaction · JSON/HTML/manifest agreement · gap-aware compare · actionable doctor · matching docs · full suite green · device validation or honest limitation note.
