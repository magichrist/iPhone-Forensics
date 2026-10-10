# v5 Current-State Audit (verified 2026-10-10)

## Entry points (`pyproject.toml`)
- `iphone-forensics = iphone_forensics.cli:main` — legacy single-run CLI.
- `iphone-surgery = iphone_forensics.cli_v4:main` — v4 engine, 16 subcommands.
- `iphone_audit.py` → `from iphone_forensics.cli import main`. Must keep working.

## CLI surface
- `cli.py`: ~15 flags (`--udid/--output/--buyer-json/--compare-json/--redact-identifiers/--mvt-backup/--init-buyer-checklist/--no-capability-catalog/--crash-reports/--app-list/--provisioning/--syslog-seconds/--pmd-syslog-seconds/--pmd-crash-reports/--pmd-processes/--pmd-app-list/--backup`). Single flow: discover → collect → triage → assess → finalize. Exits 0/2/3/4.
- `cli_v4.py` (16): `cmd_welcome/cmd_doctor/cmd_devices/cmd_inspect/cmd_integrity/cmd_evidence_verify/cmd_report/cmd_tools/cmd_checklist/cmd_case/cmd_buyer/cmd_hardware/cmd_diagnose/cmd_capabilities/cmd_compare/cmd_config`. Welcome on no-args, `--config` + CWD auto-load, `--quiet/--verbose`, staged `[1/5]` progress, exit codes 0/1/2/3/4 (+5/6 reserved). `capabilities` renders `capabilities.py` (30 rows); `integrity`/`compare` print continuity; `case --json` emits machine roll-up.

## Engines (genuinely implemented, tested)
- `collectors.py`: discovery, help-only capability catalog, libimobiledevice + pmd3 adapters, bounded timeouts.
- `hardware.py`: battery/storage normalization, 10 manual subsystems, 7-level assessment, panic keyword triage.
- `integrity.py`: 9 classes, `normalize_device()`, continuity guard, buyer cross-check.
- `analysis.py`: findings, assessment, report compare, crash triage + recurrence.
- `buyer.py`: 20-item checklist, v3 + v4 verdicts, rule trace, non-string-status guard.
- `evidence.py`: v4 manifest + v3-compat verify. `reporting.py`: 15-section offline HTML + redacted pair + incomplete banner + §12 unknown panel. `models.py`: dataclasses with round-trip. `repair.py`: case + QA + `case_to_json`. `capabilities.py`: 30-row matrix + helpers. `util.py`: bounded subprocesses, traversal-safe names, sha256.

## Output today
- Root `~/Desktop/iphone-forensics`, run `iphone-audit-<stamp>/` with `report.html/report.json/manifest.json/buyer-checklist.json/raw/`. No `evidence/` split, no `README.txt`.

## Tests
- 15 files in `tests/`, ~211 passing: collectors, buyer (+phase4), capabilities, recurrence/integration, evidence, hardware (+keywords), integrity phase3, phase1 CLI, reporting (+phase5), security/reliability, spec health, v4 workflows.

## Gaps vs v5 task
1. 16 subcommands + ~15 flags ≫ 4-command max. 2. CWD not the default. 3. No dashboard counts/charts. 4. Three status vocabularies, no `permission_denied/tool_missing/skipped_by_user` etc. 5. No interactive device selector or consent prompt. 6. No `evidence/` + `README.txt` layout. 7. `compare` is field-level; gap-vs-change distinction is partial. 8. Duplication risk: two CLIs, two verdict spellings, two manifest writers (`reporting.create_manifest` v3-list vs `evidence.build_manifest` v4-dict).

## Dead code / consistency notes (verify during P0)
- `reporting.create_manifest` vs `evidence.build_manifest` — converge on one writer.
- `buyer.evaluate` vs `evaluate_v4` — keep both, document which surface uses which.
- `cli_v4` `tools` vs `doctor` overlap — fold into 4-command design.
- `models.py` UP037-style quotes — cosmetic, ignore.
