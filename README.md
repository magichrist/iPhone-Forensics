# iPhone Forensics v3

**A local-first, buyer-focused iPhone inspection tool for macOS.** It combines `libimobiledevice` CLI collectors and optional `pymobiledevice3` CLI capabilities, produces a detailed **HTML report** (primary deliverable), a machine-readable JSON report, raw command evidence, a buyer checklist, and a SHA-256 manifest.

> **Honest scope:** no ordinary paired-Mac tool can inspect every protected iOS artifact or certify that a used phone is genuine, free of spyware, free of hidden repairs, water-resistant, or free of latent hardware faults. Unknown means unknown. The buyer must independently verify activation/ownership and carrier eligibility and physically test the phone.

## What v3 includes

- Buyer verdict based on **critical checklist gaps**, not a misleading single hardware score.
- Editable 20-point buyer checklist covering Activation Lock, Remote Management, carrier eligibility, repair history, battery, screen/touch, Face ID, cameras, audio, buttons, charging, wireless, cellular, GPS/NFC, physical damage, storage claims, and transaction documentation.
- Device metadata and identity consistency reporting when exposed by iOS.
- Safe native diagnostic requests and IORegistry collection when `libimobiledevice` tools support them.
- Optional `pymobiledevice3` app/process inventory, crash report pull, bounded live logs, and explicit full-backup option.
- Capability catalog that records CLI help for installed tools; it **does not run every command** and does not imply that all capabilities have been exercised.
- Correct bounded live-log capture with a monotonic deadline and explicit expected-stream-end status.
- Raw stdout/stderr files, collection exit status and duration, toolchain inventory, evidence manifest, and HTML report.
- Conservative findings: collection failures are evidence gaps, not automatic hardware faults.
- Redaction-friendly report layout; raw JSON and logs can contain private data and should not be shared unredacted.
- Unit tests for scoring, parsers, HTML escaping, and the checklist template.

## Requirements

- macOS recommended; Python 3.11 or newer.
- `libimobiledevice` recommended. `pymobiledevice3` is optional but improves coverage.
- iPhone unlocked and connected with a data-capable cable; approve **Trust This Computer** when prompted.

### Install

```bash
brew install libimobiledevice
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[pymobiledevice3]'
```

For development/tests:

```bash
python -m pip install -e '.[pymobiledevice3,dev]'
pytest
```

You can omit the optional extra if you only want `libimobiledevice`:

```bash
python -m pip install -e .
```

## Quick start

```bash
iphone-forensics
```

Or without installing the console entry point:

```bash
PYTHONPATH=src python -m iphone_forensics.cli
```

Default output root is `~/Desktop/iphone-forensics/`. Each run creates a timestamped directory containing:

- `report.html` — **the main human-readable buyer report**
- `report.json` — machine-readable findings and assessment
- `buyer-checklist.json` — editable buyer inputs/checklist snapshot
- `manifest.json` — SHA-256 and size for collected evidence files
- `raw/` — command stdout/stderr, device metadata, and capability catalog

Open `report.html` in a browser. The report is standalone HTML and has responsive styling; it is not a PDF report generator.

## Buyer checklist workflow

Create a reusable editable checklist:

```bash
iphone-forensics --init-buyer-checklist ~/Desktop/iphone-buyer-checklist.json
```

Edit the JSON and set each check's `status` to one of:

- `pass` — you personally completed the check and it passed
- `fail` — you completed the check and it failed
- `not_tested` — unknown / not checked
- `not_applicable` — genuinely irrelevant; critical checks should generally not be marked N/A

Then run the inspection using your inputs:

```bash
iphone-forensics --buyer-json ~/Desktop/iphone-buyer-checklist.json
```

Compare against an earlier inspection and optionally generate identifier-masked shareable HTML/JSON:

```bash
iphone-forensics --compare-json ~/Desktop/iphone-forensics/iphone-audit-OLD/report.json
iphone-forensics --redact-identifiers
iphone-forensics --compare-json /path/to/previous/report.json --redact-identifiers
```

The redacted export masks common device identifiers in the exported report files. It does **not** redact raw evidence, the private `report.json`, or the buyer checklist; do not share those unreviewed.

Example JSON structure:

```json
{
  "buyer": {
    "asking_price": 650,
    "currency": "USD",
    "country_or_region": "Azerbaijan",
    "advertised_model": "iPhone 15",
    "advertised_storage": "128 GB",
    "seller_notes": "Seller claims original screen"
  },
  "checks": {
    "activation_lock": {"status": "not_tested", "notes": "Must verify during handoff"},
    "remote_management": {"status": "not_tested", "notes": ""},
    "carrier_eligibility": {"status": "not_tested", "notes": ""}
  },
  "observations": {
    "battery_max_capacity_percent": 91,
    "battery_cycle_count": null,
    "reported_storage_gb": 128,
    "repair_estimate": null,
    "carrier_eligibility_result": "not_checked"
  }
}
```

The CLI merges omitted checklist entries from its defaults. Never enter Apple Account passwords or other secrets into the checklist.

## Collection options

```bash
# Choose one phone when multiple are connected
iphone-forensics --udid YOUR_UDID

# Faster run: skip help/catalog discovery
iphone-forensics --no-capability-catalog

# Installed-app inventory (private information)
iphone-forensics --app-list --pmd-app-list

# Process list (private activity information)
iphone-forensics --pmd-processes

# Copy crash reports (may contain app/user details)
iphone-forensics --crash-reports --pmd-crash-reports

# Capture bounded live logs; maximum 120 seconds per tool
iphone-forensics --syslog-seconds 15 --pmd-syslog-seconds 15

# Provisioning inventory, if supported
iphone-forensics --provisioning

# Full backup: explicit opt-in, potentially very sensitive and large
iphone-forensics --backup libimobiledevice
iphone-forensics --backup pymobiledevice3

# Optional MVT scan of an existing backup you are authorized to examine
iphone-forensics --mvt-backup /path/to/existing/backup
```

The MVT backup scan can also run **offline without a connected iPhone** when no device toolkit is installed, provided `mvt-ios` is installed. The input must be an existing backup directory. MVT output may contain sensitive artifacts.

Backups are disabled by default. Only create one if you own the device or have clear authorization, and protect it like a personal-data archive. Tool command syntax and service availability can change across `pymobiledevice3` releases; check the generated capability catalog and installed CLI help when an optional operation is unsupported.

## What it does not pretend to automate

- **Activation Lock / Find My:** must be verified during seller erase and buyer activation. A connected-Mac metadata query is not conclusive.
- **Carrier blacklist / financing / SIM lock:** verify with the carrier or an authoritative provider. These are distinct checks.
- **Parts & Service History / Battery Health:** inspect Settings and record the result in the buyer checklist. Diagnostic APIs may expose some additional metrics but not all.
- **Physical condition:** perform the guided manual checks; software cannot reliably detect dead pixels, all camera faults, corrosion, water ingress, or damaged seals.
- **MDM and profiles:** inspect Settings → General → VPN & Device Management, and watch for Remote Management during setup.
- **Spyware/compromise:** optional `--mvt-backup` runs an installed `mvt-ios` against an existing authorized backup. It does not jailbreak the phone or acquire data itself; no clean result proves absence of compromise. Specialized analysis requires suitable artifacts and has its own limitations.
- **Market pricing:** price inputs are recorded for context; the project does not invent local market value or repair prices.

## Safety model

The default collection avoids erase, restore, reboot, shutdown, changing settings, installing/removing apps or profiles, Developer Mode changes, recovery operations, simulated location, notification posting, and packet capture. Some read operations can still reveal private information. Full backups, app/process inventory, crash reports, and logs are opt-in. Review commands before running them and keep reports private.

## Architecture

```text
src/iphone_forensics/
├── cli.py          # argument parsing, run lifecycle, output folder
├── collectors.py   # libimobiledevice + pymobiledevice3 CLI adapters
├── buyer.py        # checklist schema and buyer verdict logic
├── analysis.py     # conservative findings and evidence coverage assessment
├── reporting.py    # HTML report, JSON and SHA-256 manifest
└── util.py         # bounded subprocesses, streaming capture, safe filesystem helpers
```

## Troubleshooting

```bash
idevice_id -l
pymobiledevice3 usbmux list
iphone-forensics --no-capability-catalog
```

If no device is detected, unlock it, retry the trust prompt, try another data cable/USB port, and check the native commands above. A failed collector does not necessarily indicate a defective phone; pairing state, iOS version, permissions, and tool compatibility all matter.

## Project quality

Run the tests with `pytest`. Tests are local and do not require a connected iPhone. Hardware integration remains dependent on the real phone, iOS build, cable, trust state, and installed CLI versions.

## References

- `libimobiledevice`: https://github.com/libimobiledevice/libimobiledevice
- `pymobiledevice3`: https://github.com/doronz88/pymobiledevice3
- `pymobiledevice3` docs: https://doronz88.github.io/pymobiledevice3/
- Apple parts/service history: https://support.apple.com/en-us/102658
