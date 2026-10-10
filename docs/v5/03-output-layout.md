# v5 Output Layout — CWD Run Dir (task §3)

## Target
```
./iphone-forensics-20261010-201500/
├── report.html
├── report.json
├── manifest.json
├── README.txt
└── evidence/
    ├── device-info.json
    ├── hardware.json
    ├── battery.json
    ├── integrity.json
    ├── diagnostics.json
    └── collection-log.json
```
Only files with real collected evidence are generated; `raw/` command dumps move under `evidence/` (or `evidence/` replaces `raw/` with the same content + normalized JSON sidecars). `manifest.json` describes exactly what exists (no phantom entries).

## Rules
- **Default root = `os.getcwd()`**, resolved at run start. `~/Desktop` default is removed; `--output <dir>` advanced override stays. Config `output_root` still honored (precedence: `--output` > `--config` > `./iphone-surgery.json` > CWD).
- **Unique dirs**: `iphone-forensics-<UTC stamp>`; on collision append `-1/-2…`. Never overwrite; never clean previous runs. Stamp uses UTC (`%Y%m%d-%H%M%S`).
- `report.html` is the entry point; `README.txt` (~20 lines: what this dir is, open report.html first, privacy warning, tool versions, timestamps).
- `report.json` keeps `schema_version` (bump to `5.0.0`, accept 3.x/4.x on read) and matches `docs/v5` schema doc.
- Hashes: SHA-256 per artifact in `manifest.json` (reuse `evidence.build_manifest`; retire `reporting.create_manifest` or make it delegate). Provenance per artifact: collector, source, timestamps (host UTC + device event time where known), tool versions, outcome status, stdout/stderr sizes.
- Sensitive evidence stays local; redacted exports (`report-redacted.*`) only with explicit flag; never transmitted.

## Affected modules
`cli.py` + `cli_v4.py` (`_new_run_dir`, `_new_report`, `_finish_run`, config `output_root`), `evidence.py` (single manifest writer, `evidence/` layout), `reporting.py` (`finalize` paths), `util.py` (`secure_mkdir` 0700 reuse).

## Acceptance
- Run from a temp CWD creates exactly one new `iphone-forensics-*/` dir there (nothing on Desktop). Re-runs never collide. Manifest ↔ files agree (verify passes). Missing collectors produce no files and no manifest entries. Tests: CWD-output test, uniqueness/collision test, manifest-agreement test, no-phantom-files test.
