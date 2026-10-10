# v5 CLI Redesign — 4 Commands (task §2)

## Target interface (on `iphone-forensics` only)
```
iphone-forensics devices    # list + statuses + next step
iphone-forensics inspect    # full safe inspection → CWD run dir → report.html
iphone-forensics doctor     # environment diagnostics + install instructions
iphone-forensics compare ./previous-run/report.json   # gap-aware diff
iphone-forensics --help
```
`iphone-surgery` stays as the **advanced engine interface** (all 16 subcommands, unchanged) but is no longer the documented path. `iphone_audit.py` keeps calling `cli.main`.

## Command specs
- **devices**: reuse `collectors.discover_devices` + pairing validation. Table columns: # / model (ProductType→marketing where known) / device name / connection / trust-pairing (validated/unknown) / masked UDID (last-4 only). Footer: exact next command (`inspect`, or `inspect --device <full-udid>` when >1). Zero/one/many handled; exit 3 when none (still prints doctor hint).
- **inspect** (the product): auto-discover → auto-select if exactly 1 → numbered interactive selector if >1 (TTY only; non-TTY with >1 and no `--device` → exit 4 with non-interactive-safe message) → validate pairing/deps/permissions → capability discovery → **standard profile**: all non-destructive collectors ON (device-info, diagnostics All/GasGauge/WiFi/NAND, IORegistry planes, capability catalog, crash triage of already-present artifacts) + **sensitive profile OFF unless consented** (app/process lists, syslog streaming, crash pull, provisioning, backup, MVT): TTY → one `y/N` prompt listing scope; non-TTY → skip with documented note; `--yes-sensitive` / `--no-sensitive` flags for automation; `--device`, `--output` (advanced override), `--buyer-json` (compat) retained but hidden from basic help. Never aborts on one failed collector: record status, continue, banner the gaps. End: print run dir + `report.html` + `report.json` + verdict line + finding counts.
- **doctor**: python/package integrity, tool presence + versions (`--help` probe, never execute), discovery preconditions, report-deps (stdlib only — always OK), writability + free space of CWD output, optional-integration usability (mvt-ios, pmd3). Missing optional = WARNING + install line, never fatal.
- **compare**: args `compare <previous-report.json> [--current <report.json>]` (default current = newest `./iphone-forensics-*/report.json`). Classify every field: `changed` (both present, differ) / `unchanged` / `only_in_previous` / `only_in_current` / `not_comparable` (missing one side → **never a device change**). Separate environment block (tool versions, schema_version, collector sets) from device block. Reuse `integrity.assess_integrity` + continuity (cap: `not_detectable` continuity → overall ≤ inconclusive).

## Compatibility layer
- All current `cli.py` collector flags keep working but move to `inspect --advanced …` hidden group (suppressed from `--help`, visible in `--help-advanced`). No flag removed, none renamed.
- Implementation: new `cli.py` command dispatcher (~150 lines) that **imports** `cli_v4` engine functions (`cmd_devices`, `cmd_doctor`, `cmd_inspect`, compare helpers) — no forked logic. `cli_v4.py` untouched except small refactors if needed for import reuse.

## Affected modules
`cli.py` (rewrite dispatcher, keep `_run_mvt_backup`/`_finish` helpers or delegate), `cli_v4.py` (importable engine fns; selector + consent helpers added once, reused), `collectors.py` (selector needs per-device model/name — extend discovery return, keep old signature compat).

## Acceptance
- `--help` lists exactly 4 commands. `devices`/`inspect` alone complete a normal flow. No standard run requires a collector flag. Non-TTY runs never hang. `iphone_audit.py` works. CLI-surface guard test pins the 4-command list.
