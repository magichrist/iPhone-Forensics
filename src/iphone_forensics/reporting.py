from __future__ import annotations

import html
import math
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from .buyer import CHECKLIST, evaluate
from .capabilities import (COVERAGE_LEVELS, category_for_collector, claim_rules, coverage_counts,
                           forbidden_inferences, get_matrix)
from .util import redact, sha256_file, write_json

# Missing telemetry must stay visibly missing. Never coerce absent data to 0/False/"" —
# "unknown" and "zero" mean opposite things in a forensic report (spec §12 / report-schema.md).
MISSING = "not provided"

# v5 §4C report outline: exactly these 11 sections, in this order. The v4 report
# rendered 15 flat sections; v5 groups them under the reader-oriented outline
# without dropping any content.
SECTION_TITLES: tuple[str, ...] = (
    "Executive summary",
    "Device identity and configuration",
    "Hardware and components",
    "Battery and power",
    "Parts, repairs and integrity",
    "System integrity and configuration",
    "Reliability and diagnostics",
    "Buyer checklist",
    "Risks, findings and actions",
    "Evidence and coverage",
    "Technical appendix",
)

# Old heading text -> the v5 section that absorbed it. Rendered as extra anchors so
# an external deep link that points at a v4 fragment (`#8-hardware-health-assessment-v4`)
# still lands on the right section instead of a dead link. docs/v5/10 lists this as
# the mitigation for the section renumber.
SECTION_ALIASES: tuple[tuple[str, str], ...] = (
    ("Executive summary", "Executive summary"),
    ("Buyer-critical blockers", "Buyer checklist"),
    ("Device identity (reported by iOS)", "Device identity and configuration"),
    ("Comparison with previous inspection", "Device identity and configuration"),
    ("Buyer checklist and physical tests", "Buyer checklist"),
    ("Buyer-entered observations", "Buyer checklist"),
    ("Diagnostic metric candidates", "Reliability and diagnostics"),
    ("Hardware health assessment (v4)", "Hardware and components"),
    ("Hardware integrity assessment (v4)", "Parts, repairs and integrity"),
    ("Crash and panic triage", "Reliability and diagnostics"),
    ("Automated findings", "Risks, findings and actions"),
    ("Unknown / unavailable / unsupported / skipped tests", "Risks, findings and actions"),
    ("Collection coverage", "Evidence and coverage"),
    ("Toolchain, evidence integrity, and raw files", "Technical appendix"),
    ("Scope, limitations, and next steps", "Technical appendix"),
)

# Which report sections a failed collector leaves unevaluable. Keyword match on the
# collector name; anything unmatched falls back to the evidence-level default.
# Sections are named by title, not number: several v5 panels are only rendered when
# that data exists, so a hard number could point at an absent heading. Titles must
# match SECTION_TITLES exactly.
_COLLECTOR_SECTION_HINTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("device-info", ("Device identity and configuration", "Reliability and diagnostics",
                     "Hardware and components", "Battery and power")),
    ("connected-devices", ("Device identity and configuration",)),
    ("pairing", ("Device identity and configuration",)),
    ("diagnostics", ("Reliability and diagnostics", "Hardware and components",
                     "Battery and power")),
    ("ioreg", ("Reliability and diagnostics", "Hardware and components")),
    ("crash", ("Reliability and diagnostics",)),
    ("syslog", ("Reliability and diagnostics",)),
    ("provisioning", ("Device identity and configuration",)),
    ("installed-apps", ("Reliability and diagnostics",)),
    ("processes", ("Reliability and diagnostics",)),
    ("backup", ("Reliability and diagnostics",)),
    ("mvt", ("Reliability and diagnostics",)),
)

_DEFAULT_UNEVALUABLE = ("Risks, findings and actions", "Evidence and coverage")

# ---------------------------------------------------------------- v5 dashboard
# Dashboard outcome buckets. These are *epistemic* buckets (what we can say about a
# result), never health grades: nothing here may imply a device is fine.
#
# The mapping is deliberately local and total. A status that is absent, blank, or
# unknown lands in "inconclusive" — the dashboard must never promote an unrecognized
# or missing status into "passed". Gaps map to skipped/unsupported so an unmeasured
# check can never be read as a clean result.
NOT_COLLECTED = "not collected"

OUTCOME_BUCKETS: tuple[str, ...] = ("passed", "warning", "failed", "inconclusive",
                                    "unsupported", "skipped")

# Hardware check statuses (models.HEALTH_STATUSES) -> dashboard bucket.
#   degraded -> warning: it is a measured non-pass that needs review, not a hard
#   failure, and never a pass.
_HARDWARE_STATUS_BUCKET: dict[str, str] = {
    "pass": "passed",
    "pass_with_warnings": "warning",
    "degraded": "warning",
    "fail": "failed",
    "inconclusive": "inconclusive",
    "not_tested": "skipped",
    "unsupported": "unsupported",
}

# Collector statuses (models.COLLECTION_STATUSES + v4 legacy aliases) -> bucket.
# A collector that could not run (missing tool, denied permission, error, operator
# skip) is a gap in evidence, so it maps to "skipped" rather than to any pass/fail.
_COLLECTION_STATUS_BUCKET: dict[str, str] = {
    "collected": "passed",
    "passed": "passed",
    "warning": "warning",
    "failed": "failed",
    "inconclusive": "inconclusive",
    "unsupported": "unsupported",
    "permission_denied": "skipped",
    "tool_missing": "skipped",
    "collection_error": "skipped",
    "skipped_by_user": "skipped",
    "not_applicable": "skipped",
    # v4 / v3 strings still present in older run directories.
    "success": "passed",
    "expected_end": "passed",
    "failed_or_partial": "skipped",
}

# Severity order for "top issues" and the severity chart (most severe first).
_SEVERITY_RANK: dict[str, int] = {"BLOCKER": 0, "WARNING": 1, "REVIEW": 2, "INFO": 3}

# Series colours. Fixed and self-contained — no theme, font, or CDN dependency.
_BUCKET_COLOR: dict[str, str] = {
    "passed": "#176b43",
    "warning": "#8b5a00",
    "failed": "#9c2525",
    "inconclusive": "#5e6a78",
    "unsupported": "#6b4f9c",
    "skipped": "#9aa5b1",
}


def esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _val(value: Any, missing: str = MISSING) -> Any:
    """Render absent telemetry as `missing`, never as 0 / False / empty string."""
    if value is None:
        return missing
    if isinstance(value, str) and not value.strip():
        return missing
    return value


def _bucket_of(status: Any, mapping: dict[str, str]) -> str:
    """Map any status string onto a dashboard bucket; unknown never becomes 'passed'."""
    try:
        key = str(status if status is not None else "").strip().lower()
    except (TypeError, ValueError):  # pragma: no cover - defensive, exotic status objects
        return "inconclusive"
    return mapping.get(key, "inconclusive")


# Plain-language "what does this status actually mean" column (task §10.10).
# The distinction the report must never blur: a *negative result* is a finding
# about the device; every other gap is an absence of evidence about it.
_GAP_OUTCOME: dict[str, str] = {
    "failed": "Check ran and returned a negative result — a real finding.",
    "inconclusive": "Evidence collected but insufficient to decide.",
    "unsupported": "This device/iOS/toolchain cannot answer this question.",
    "permission_denied": "Blocked by pairing or permissions — re-trust and retry.",
    "tool_missing": "Tool not installed — install it, nothing learned about the device.",
    "collection_error": "Command failed or timed out — inspect its stderr.",
    "skipped_by_user": "Not collected — sensitive collection was not consented to.",
    "not_applicable": "Does not apply to this device.",
}


def _gap_outcome(status: Any) -> str:
    """Human explanation for a non-passing collector status."""
    try:
        return _GAP_OUTCOME.get(str(status if status is not None else "").strip().lower(),
                                "No usable evidence collected for this step.")
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return "No usable evidence collected for this step."


def _consent_rows(report: dict[str, Any]) -> str:
    """Render the sensitive-collection consent record (docs/v5/07).

    A reader must be able to tell, from the report alone, whether the run was
    allowed to collect app inventories, logs, or backups — and whether anything
    was skipped because the operator declined. Declining is presented as a
    choice, never as a defect.
    """
    scope = report.get("scope") if isinstance(report.get("scope"), dict) else {}
    state = scope.get("sensitive_collection")
    if state is None:
        return ("<p class='muted'>This run did not record a sensitive-collection consent "
                "decision (it predates that record). Sensitive items below appear as "
                "<i>not collected</i>.</p>")

    explanations = {
        "granted": "Granted. The operator consented, or named these collectors explicitly. "
                   "Everything listed here stays on this machine and is never transmitted.",
        "declined": "Declined or unavailable. These items were <b>not</b> collected. "
                    "Declining loses nothing in a standard inspection: the skipped items "
                    "are recorded as <i>skipped by operator</i>, not as failures.",
        "not_requested": "Not requested. This run was invoked directly without the consent "
                         "gate, so no sensitive collector was enabled by it.",
    }
    explanation = explanations.get(str(state), explanations["not_requested"])
    items = scope.get("sensitive_collection_items") or []
    item_cell = ", ".join(f"<code>{esc(item)}</code>" for item in items) if items else \
        "<span class='muted'>none named explicitly</span>"

    requested = [key for key in ("backup_requested", "logs_requested", "crash_reports_requested",
                                 "app_inventory_requested") if scope.get(key)]
    requested_cell = ", ".join(f"<code>{esc(key)}</code>" for key in requested) if requested else \
        "<span class='muted'>no sensitive collector ran</span>"

    # _Html cells: these three are generated markup (already escaped internally),
    # so the table must not escape them a second time and render the tags as
    # visible text. Everything device-derived inside them is escaped above.
    return _table(["Consent", "State", "Named on the command line", "Sensitive collectors that ran"],
                  [["Sensitive collection", _Html(f"<b>{esc(state)}</b>"),
                    _Html(item_cell), _Html(requested_cell)]],
                  "No consent record.") + f"<p class='muted'>{explanation}</p>"


# How each epistemic label reads in the report (docs/v5/05, §4 badges).
_EPISTEMIC_TEXT: dict[str, str] = {
    "observed": "Verified — read directly from evidence",
    "inferred": "Inferred — reasoned from evidence",
    "unknown": "Unknown — open question, not a conclusion",
    "needs_manual": "Manual check required",
}

# Accessible name + colour per label. Colour is never the only signal: the badge
# always carries its text (WCAG 1.4.1).
_EPISTEMIC_PILL: dict[str, str] = {
    "observed": "#176b43",     # good
    "inferred": "#8b5a00",     # warn
    "unknown": "#5e6a78",      # neutral
    "needs_manual": "#6b4f9c",  # manual/action
}


# Generated from _EPISTEMIC_PILL so the badge colour and its label can never
# drift apart; no device-derived text is ever interpolated here.
_EPISTEMIC_PILL_CSS = "".join(
    f".pill-{label}{{color:{color};border-color:{color}}}" for label, color in _EPISTEMIC_PILL.items()
)


def _audit_claim_matrix(report: dict[str, Any]) -> dict[str, Any]:
    """Run every claim gate and return the audit record stored in report.json.

    A violation is surfaced, never silently dropped: it is recorded, printed, and
    added as a BLOCKER finding, so a claim the matrix forbids is visible to whoever
    reads the report rather than quietly missing.
    """
    from .capabilities import audit_report
    from .hardware import audit_battery_claims
    from .integrity import audit_integrity_claims

    violations = audit_report(report) + audit_battery_claims(report) + audit_integrity_claims(report)
    for violation in violations:
        # Cosmetic only: an audit failure must never stop a report being written.
        print(f"[report] claim audit: {violation}", file=sys.stderr)
        if isinstance(report.get("findings"), list):
            report["findings"].append({
                "severity": "BLOCKER",
                "title": "An unsupported claim was produced and must not be relied on",
                "detail": violation,
                "epistemic": "observed",
                "evidence": [],
            })
    return {
        "checked": True,
        "violations": violations,
        "violation_count": len(violations),
        "note": ("A claim the matrix forbids was produced. It is recorded here and raised "
                 "as a BLOCKER; do not rely on any conclusion in this run until the "
                 "underlying code is fixed." if violations else
                 "No unsupported claims were produced by this run."),
    }


def _epistemic_badge(finding: dict[str, Any]) -> str:
    """Render one finding's epistemic badge.

    The label is resolved through `analysis.epistemic_for` rather than read
    blindly off the dict, so a report built without `finalize` (tests, library
    callers, `report --regenerate` on an older JSON) still badges every finding
    instead of printing a raw slug.
    """
    from .analysis import epistemic_for

    label = epistemic_for(finding) if isinstance(finding, dict) else "unknown"
    # _Html: this is generated markup, and the label is escaped above, so the
    # table must not escape the span a second time and show it as literal text.
    return _Html(f"<span class='pill pill-{esc(label)}'>"
                 f"{esc(_EPISTEMIC_TEXT.get(label, label))}</span>")


def _claim_matrix_panel() -> str:
    """What this tool may claim, and what it says instead when it cannot.

    Rendered from `capabilities.CLAIM_MATRIX`, the single source of truth shared
    with `iphone-forensics capabilities`, so the report and the CLI can never
    disagree about the limits of the evidence.
    """
    rows = [[row["claim"], row["requires"], row["otherwise"]]
            for row in claim_rules()]
    forbidden = [[row["wrong_claim"], row["correct"]] for row in forbidden_inferences()]
    return (
        "<h3>What this report may and may not claim</h3>"
        "<p class='muted'>Every conclusion below is bounded by this table. When the required "
        "evidence is absent, the report states the fallback wording instead of inferring a "
        "verdict from a gap.</p>"
        + _table(["Claim", "Requires", "Stated instead when unsupported"], rows,
                 "No claim rules declared.", caption="Claim matrix")
        + "<h3>Inferences this tool never draws</h3>"
        "<p class='muted'>These shortcuts would each turn missing evidence into either a "
        "reassuring verdict or an accusation. Both are wrong, so none is made.</p>"
        + _table(["Never claimed", "What this report says instead"], forbidden,
                 "No forbidden inferences declared.", caption="Forbidden inferences"))


def dashboard_counts(report: dict[str, Any]) -> dict[str, int]:
    """Recompute every dashboard count straight from the report structures.

    This is the *only* place counts are derived. `build_html` renders from it and
    `validate_report_html` re-derives through the same function, so a dashboard
    number can never silently disagree with the JSON it claims to summarize.

    Sources: hardware_assessment checks (per-check status) and the collection log
    (per-collector status). Both are counted; a run with neither is 0/0, which the
    dashboard must present as "no data", not as "0 passed".
    """
    counts = {bucket: 0 for bucket in OUTCOME_BUCKETS}

    hardware = report.get("hardware_assessment") if isinstance(report, dict) else None
    if isinstance(hardware, dict):
        for check in hardware.get("checks") or []:
            if isinstance(check, dict):
                counts[_bucket_of(check.get("status"), _HARDWARE_STATUS_BUCKET)] += 1

    collection = report.get("collection") if isinstance(report, dict) else None
    if isinstance(collection, (list, tuple)):
        for item in collection:
            if isinstance(item, dict):
                counts[_bucket_of(item.get("status"), _COLLECTION_STATUS_BUCKET)] += 1

    counts["checks_performed"] = sum(counts[bucket] for bucket in OUTCOME_BUCKETS)
    return counts


def _severity_counts(report: dict[str, Any]) -> dict[str, int]:
    """Findings per severity. Unknown severities are ignored, never rounded up."""
    counts: dict[str, int] = {}
    findings = report.get("findings") if isinstance(report, dict) else None
    if not isinstance(findings, (list, tuple)):
        return counts
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "").strip().upper()
        if severity:
            counts[severity] = counts.get(severity, 0) + 1
    return counts


def _top_issues(report: dict[str, Any], limit: int = 3) -> list[dict[str, Any]]:
    """Highest-severity findings first, stable within a severity, capped at `limit`.

    Only BLOCKER/WARNING/REVIEW findings qualify; INFO is not an "issue". When a run
    recorded none, the caller must say so rather than implying a clean device.
    """
    ranked: list[tuple[int, int, dict[str, Any]]] = []
    findings = report.get("findings") if isinstance(report, dict) else None
    if not isinstance(findings, (list, tuple)):
        return []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity") or "").strip().upper()
        if severity in {"BLOCKER", "WARNING", "REVIEW"}:
            ranked.append((_SEVERITY_RANK[severity], index, finding))
    ranked.sort(key=lambda row: (row[0], row[1]))
    return [finding for _, _, finding in ranked[:limit]]


def _measured_metrics(report: dict[str, Any]) -> list[tuple[str, str]]:
    """Battery/storage numbers that were genuinely measured in this run.

    Only hardware checks that carry an actual numeric measurement qualify. Anything
    absent stays out of the dashboard entirely and is rendered as "not collected" by
    the caller — never as 0%, 100%, or a plausible-looking placeholder.
    """
    hardware = report.get("hardware_assessment") or {}
    if not isinstance(hardware, dict):
        return []

    metrics: list[tuple[str, str]] = []
    for check in hardware.get("checks", []) or []:
        if not isinstance(check, dict):
            continue
        if str(check.get("subsystem") or "").strip().lower() not in {"battery", "storage"}:
            continue
        measurement = check.get("measurement")
        if not isinstance(measurement, (int, float)) or isinstance(measurement, bool):
            continue
        unit = str(check.get("measurement_unit") or "").strip()
        value = f"{measurement:g}" if isinstance(measurement, float) else str(measurement)
        label = str(check.get("question") or check.get("subsystem") or "measurement")
        metrics.append((label, f"{value}{' ' + unit if unit else ''}"))
    return metrics


def _device_facts(report: dict[str, Any], redact_identifiers: bool = False) -> list[tuple[str, str]]:
    """Device model + iOS/build + inspection time, each honestly missing when absent."""
    device = report.get("device") if isinstance(report.get("device"), dict) else {}
    rows: list[tuple[str, str]] = [
        ("Device model", _val(device.get("ProductType"))),
        ("Model number", _val(device.get("ModelNumber"))),
        ("Hardware model", _val(device.get("HardwareModel"))),
        ("iOS version", _val(device.get("ProductVersion"))),
        ("iOS build", _val(device.get("BuildVersion"))),
        ("Inspection started (UTC)", _val(report.get("started_at"))),
        ("Inspection finished (UTC)", _val(report.get("finished_at"))),
    ]
    if redact_identifiers:
        for label, key in (("Serial number", "SerialNumber"),
                           ("IMEI", "InternationalMobileEquipmentIdentity")):
            rows.append((label, _redact_identifier(device.get(key)) if device.get(key) else NOT_COLLECTED))
    return [(label, str(value)) for label, value in rows]


def _coverage_pairs(report: dict[str, Any]) -> list[tuple[str, int, int]]:
    """(category, collected-this-run, declared-capabilities) from the matrix.

    The capability matrix is static project data; the collected count reflects only
    what this run actually recorded. A category with declared capabilities and zero
    collected items is a gap, and the table labels it that way.
    """
    declared: dict[str, int] = {}
    for row in get_matrix():
        category = str(row.get("category") or "uncategorized")
        declared[category] = declared.get(category, 0) + 1

    collected: dict[str, int] = {}
    for item in report.get("collection", []) or []:
        if not isinstance(item, dict):
            continue
        status = _bucket_of(item.get("status"), _COLLECTION_STATUS_BUCKET)
        if status in {"passed", "warning", "failed", "inconclusive"}:
            # Explicit mapping, not a substring guess: no collector name contains
            # a capability category name, so the old test matched nothing and the
            # table could only ever render zero.
            category = category_for_collector(str(item.get("name") or ""))
            if category in declared:
                collected[category] = collected.get(category, 0) + 1
    return [(category, collected.get(category, 0), total)
            for category, total in sorted(declared.items())]


def _svg_donut(counts: dict[str, int], title: str = "Outcome distribution") -> str:
    """Inline SVG donut. Numbers live only in attributes; labels are escaped text.

    No JavaScript, no <script>, no external references, no fonts, no animation: the
    report must render identically from a file:// URL on a machine with no network.
    Every segment carries a <title> so a screen reader announces it, and the caller
    always emits a text table with the same numbers for print.
    """
    entries = [(name, int(counts.get(name, 0) or 0)) for name in OUTCOME_BUCKETS]
    total = sum(value for _, value in entries)
    if total <= 0:
        # Nothing was evaluated. An empty ring would read as "0 problems"; say nothing.
        return ""

    radius, thickness, cx, cy = 52.0, 22.0, 70.0, 70.0
    circumference = 2.0 * math.pi * radius
    segments: list[str] = []
    offset = 0.0
    for name, value in entries:
        if value <= 0:
            continue
        fraction = value / total
        dash = circumference * fraction
        color = _BUCKET_COLOR.get(name, "#5e6a78")
        segments.append(
            f"<circle cx='{cx:g}' cy='{cy:g}' r='{radius:g}' fill='none' stroke='{color}' "
            f"stroke-width='{thickness:g}' stroke-dasharray='{dash:.3f} {circumference - dash:.3f}' "
            f"stroke-dashoffset='{-offset:.3f}' transform='rotate(-90 {cx:g} {cy:g})'>"
            f"<title>{esc(name)}: {value}</title></circle>")
        offset += dash

    legend = "".join(
        f"<text x='132' y='{18 + 14 * index:g}' font-size='11' fill='#5e6a78'>{esc(name)}: {value}</text>"
        for index, (name, value) in enumerate(entries) if value > 0)
    legend += f"<text x='132' y='{18 + 14 * len([e for e in entries if e[1] > 0]):g}' " \
              f"font-size='11' fill='#17202b'>Total: {total}</text>"

    # No xmlns attribute: inline SVG inside HTML5 needs no namespace declaration, and
    # the report must contain zero "http" strings (offline guarantee, see tests).
    return ("<svg class='chart' viewBox='0 0 260 140' width='260' height='140' role='img' "
            f"aria-label='{esc(title)}'>"
            f"<title>{esc(title)}</title>{''.join(segments)}{legend}</svg>")


def _svg_bars(pairs: list[tuple[str, int]], title: str = "Distribution",
              color: str = "#2459a9", value_format: str = "{value}") -> str:
    """Inline SVG horizontal bar chart. Numbers only in attributes, labels escaped.

    An all-zero or empty series returns "" so the caller can print one honest
    "no data collected" line instead of an axis of zeroes that looks like a result.
    """
    rows = [(str(label), int(value)) for label, value in pairs]
    if not rows or all(value <= 0 for _, value in rows):
        return ""

    max_value = max(value for _, value in rows)
    row_height, label_width, bar_width = 22, 150, 340
    height = row_height * len(rows)
    bars: list[str] = []
    for index, (label, value) in enumerate(rows):
        y = index * row_height
        length = bar_width * (value / max_value) if max_value else 0.0
        text = value_format.format(value=value)
        bars.append(
            f"<text x='0' y='{y + 14:g}' font-size='11' fill='#17202b'>{esc(label)}</text>"
            f"<rect x='{label_width}' y='{y + 3:g}' width='{length:.3f}' height='13' fill='{color}'>"
            f"<title>{esc(label)}: {esc(text)}</title></rect>"
            f"<text x='{label_width + length + 6:.3f}' y='{y + 14:g}' font-size='11' "
            f"fill='#5e6a78'>{esc(text)}</text>")
    # No xmlns here either — see _svg_donut: the report must contain no "http" strings.
    return (f"<svg class='chart' viewBox='0 0 560 {height}' width='560' height='{height}' role='img' "
            f"aria-label='{esc(title)}'><title>{esc(title)}</title>{''.join(bars)}</svg>")


def _chart_panel(heading: str, note: str, chart: str, headers: list[str],
                 rows: list[list[Any]], empty: str) -> str:
    """Chart + its text/table equivalent. Panels render only when data exists."""
    return (f"<section class='panel chart-panel'><h3>{esc(heading)}</h3>"
            f"<p class='muted'>{esc(note)}</p>{chart}{_table(headers, rows, empty)}</section>")


def _outcome_charts(report: dict[str, Any], counts: dict[str, int]) -> str:
    """Donut + bars + collector table, or a single honest 'no data collected' line."""
    collectors = [item for item in report.get("collection", []) or [] if isinstance(item, dict)]
    if counts["checks_performed"] <= 0 and not collectors:
        return ("<section class='panel chart-panel'><h3>Check outcomes</h3>"
                "<p class='muted'>No checks were performed and no collectors were recorded in this "
                "run — outcome counts were not collected. This is an absence of data, not a pass.</p>"
                "</section>")

    parts: list[str] = []
    donut_rows = [[name, counts[name]] for name in OUTCOME_BUCKETS]
    parts.append(_chart_panel(
        "Check outcomes", "Share of evaluated checks and collector steps by epistemic outcome.",
        _svg_donut(counts), ["Outcome", "Count"], donut_rows,
        "No check outcomes were recorded."))

    severity = _severity_counts(report)
    severity_rows = [[name, severity[name]] for name in sorted(severity, key=lambda s: _SEVERITY_RANK.get(s, 99))]
    parts.append(_chart_panel(
        "Findings by severity", "Automated findings only — a human or a later inspection may find more.",
        _svg_bars([(name, severity[name]) for name, _ in severity_rows],
                  title="Findings by severity", color="#9c2525"),
        ["Severity", "Findings"], severity_rows, "No automated findings were recorded."))

    collector_rows = [[item.get("name", ""), item.get("status", ""),
                       _val(item.get("returncode")), _val(item.get("duration_seconds"))]
                      for item in collectors]
    collector_counts = {bucket: 0 for bucket in OUTCOME_BUCKETS}
    for item in collectors:
        collector_counts[_bucket_of(item.get("status"), _COLLECTION_STATUS_BUCKET)] += 1
    parts.append(_chart_panel(
        "Collector success", "One entry per collector step recorded in this run.",
        _svg_bars([(bucket, collector_counts[bucket]) for bucket in OUTCOME_BUCKETS],
                  title="Collector outcomes", color="#2459a9"),
        ["Collector", "Status", "Exit code", "Seconds"], collector_rows,
        "No collection commands were run."))
    return "".join(parts)


def _coverage_charts(report: dict[str, Any]) -> str:
    """Coverage by category from the capability matrix + what this run collected."""
    pairs = _coverage_pairs(report)
    if not pairs:
        return ""
    rows = [[category, collected, declared, "collected" if collected else "not collected"]
            for category, collected, declared in pairs]
    chart = _svg_bars([(category, collected) for category, collected, _ in pairs],
                      title="Coverage by category", color="#176b43")
    return _chart_panel(
        "Coverage by category",
        "Declared capabilities per category (project data) next to what this run actually "
        "collected. Coverage is not health: a category can be fully covered and still hide defects.",
        chart, ["Category", "Collected this run", "Declared capabilities", "State"],
        rows, "No capability categories are declared.")


def _dashboard(report: dict[str, Any], redact_identifiers: bool = False) -> str:
    """Executive dashboard rendered directly under section 1.

    Every value here is either measured or explicitly marked missing. Absent data
    renders as "not collected" — the dashboard must never manufacture a reassuring
    verdict out of a gap (spec §4 / docs/v5/04-html-report.md).
    """
    counts = dashboard_counts(report)
    severity = _severity_counts(report)
    assessment = report.get("assessment") if isinstance(report.get("assessment"), dict) else {}

    performed = counts["checks_performed"]
    performed_label = f"{performed}" if performed else NOT_COLLECTED

    # `data-dash-count` carries the machine-checkable number that
    # validate_report_html recomputes against report.json. The *displayed* text is a
    # separate node, so an unmeasured run can read "not collected" while the attribute
    # still carries the true zero — validation never parses display text.
    outcome_tiles = "".join(
        f"<div class='stat'><span class='muted'>{esc(name.capitalize())}</span>"
        f"<b data-dash-key='{esc(name)}' data-dash-count='{esc(counts[name])}'>"
        f"{esc(counts[name] if performed else NOT_COLLECTED)}</b></div>"
        for name in OUTCOME_BUCKETS)

    severity_tiles = "".join(
        f"<div class='stat'><span class='muted'>{esc(name)}</span>"
        f"<b>{esc(severity.get(name, 0))}</b></div>"
        for name in ("BLOCKER", "WARNING", "REVIEW", "INFO"))

    facts_rows = [[label, value] for label, value in _device_facts(report, redact_identifiers)]
    completeness_rows = [
        ["Automated verdict", _val(assessment.get("verdict"))],
        ["Assessment status", _val(assessment.get("status"))],
        ["Collectors completed", (f"{_val(assessment.get('collection_successful'))}"
                                   f"/{_val(assessment.get('collection_total'))}")],
        ["Failed or partial collectors", _val(assessment.get("collection_failed_or_partial"))],
        ["Identity fields present", (f"{_val(assessment.get('identity_fields_present'))}"
                                     f"/{_val(assessment.get('identity_fields_expected'))}")],
    ]

    metrics = _measured_metrics(report)
    if metrics:
        metrics_rows = [[label, value] for label, value in metrics]
        metrics_block = _table(["Measured metric", "Value"], metrics_rows, "No metrics measured.")
    else:
        metrics_block = (f"<p class='muted'><b>Battery / storage metrics: {esc(NOT_COLLECTED)}.</b> "
                         "No numeric measurement was recorded for these subsystems in this run. "
                         "Absent metrics are unknown, not normal.</p>")

    top = _top_issues(report)
    if top:
        top_rows = [[item.get("severity", ""), item.get("title", "")] for item in top]
        top_block = _table(["Severity", "Top issue"], top_rows, "")
    else:
        top_block = ("<p class='muted'><b>Top issues: none recorded.</b> No BLOCKER, WARNING, or "
                     "REVIEW finding was produced by this run. That reflects only what was "
                     "collected — it is not a clean bill of health.</p>")

    return (
        "<div class='dash' id='dashboard'>"
        "<h3>Executive dashboard</h3>"
        "<div class='stats'>"
        "<div class='stat'><span class='muted'>Checks performed</span>"
        f"<b data-dash-key='checks_performed' data-dash-count='{esc(performed)}'>"
        f"{esc(performed_label)}</b></div>"
        f"<div class='stat'><span class='muted'>Findings recorded</span><b>{esc(len(report.get('findings', []) or []))}</b></div>"
        f"<div class='stat'><span class='muted'>Automated verdict</span><b>{esc(_val(assessment.get('verdict'), NOT_COLLECTED))}</b></div>"
        "</div>"
        f"<h4>Outcome counts</h4><div class='stats'>{outcome_tiles}</div>"
        f"<h4>Findings by severity</h4><div class='stats'>{severity_tiles}</div>"
        f"<h4>Device and inspection</h4>{_table(['Field', 'Value'], facts_rows, 'No identity data collected.')}"
        f"<h4>Outcome and completeness</h4>{_table(['Field', 'Value'], completeness_rows, 'No assessment recorded.')}"
        f"<h4>Battery and storage</h4>{metrics_block}"
        f"<h4>Top issues to resolve before purchase</h4>{top_block}"
        "</div>"
    )


def create_manifest(run_dir: Path) -> dict[str, Any]:
    """Write `manifest.json` for *run_dir*.

    This is a **thin delegation** to :func:`evidence.build_manifest`, which is the
    single writer of the manifest format. It previously re-implemented the walk
    here with a narrower exclusion set and emitted a bare v3 list, so the same file
    could be written two incompatible ways depending on the call path. Kept as a
    name because callers and tests import it from here.

    Must be called **after** every artifact is written: it hashes the directory as
    it finds it, so hashing before the reports land produces a manifest that fails
    its own verification on the next run.
    """
    from .evidence import build_manifest

    return build_manifest(run_dir)


# Matches a numbered section: its opening <section ...> immediately followed by its
# <h2>N. Title</h2>. Anchors are attached to the section element, leaving the heading
# text itself untouched (so it stays greppable, copy-pastable and screen-reader clean).
_SECTION_RE = re.compile(
    r"(<section class=(?:'[^']*'|\"[^\"]*\"))>(\s*)(<h2>)(\d+)\.\s*([^<]+)(</h2>)")


def _add_toc_and_anchors(html_doc: str) -> str:
    """Give every numbered section a stable id and insert a linked table of contents.

    Built by scanning the *rendered* HTML rather than from SECTION_TITLES, so a
    conditionally-rendered section that is absent from this run never appears in the
    contents list. That keeps the outline honest instead of listing dead anchors.

    Pure string surgery on our own output: device-derived text was already escaped when
    rendered, and nothing here re-interprets it.
    """
    sections = [(m.group(4), m.group(5).strip()) for m in _SECTION_RE.finditer(html_doc)]
    if not sections:
        return html_doc

    anchors = {f"{number}|{title}": f"s{number}-{_slug(title)}" for number, title in sections}

    # Old heading text -> the v5 section that absorbed it. Each becomes an extra
    # anchor so a deep link to a v4 fragment still lands somewhere meaningful.
    legacy_anchors: dict[str, list[str]] = {}
    for old_heading, new_heading in SECTION_ALIASES:
        for number, title in sections:
            if title == new_heading:
                legacy_anchors.setdefault(f"{number}|{title}", []).append(_slug(old_heading))

    def _replace(match: re.Match[str]) -> str:
        # group 1 is the <section ...> opening tag *without* its closing '>',
        # which the pattern consumes separately.
        open_tag, space, _h2, number, title, close = match.groups()
        anchor = anchors[f"{number}|{title}"]
        # Legacy anchors are emitted as empty spans: they give an old fragment a
        # landing point without adding visible content or a second heading.
        legacy = "".join(f"<span id='{old}' class='sr-only'></span>"
                         for old in legacy_anchors.get(f"{number}|{title}", []))
        return (f"{open_tag} id='{anchor}' aria-labelledby='{anchor}-h'>{space}"
                f"<h2 id='{anchor}-h'>{number}. {title.strip()}{close}{legacy}")

    html_doc = _SECTION_RE.sub(_replace, html_doc)

    toc_items = "".join(
        f"<li><a href='#{anchors[f'{number}|{title}']}'>"
        f"<span class='toc-num'>{number}</span> {esc(title)}</a></li>"
        for number, title in sections)
    nav = ("<nav class='toc' aria-label='Report sections'>"
           "<h2 class='toc-heading'>Contents</h2>"
           f"<ol class='toc-list'>{toc_items}</ol></nav>")
    skip = "<a class='skip-link' href='#main-content'>Skip to report content</a>"
    return html_doc.replace("<main>", f'<main id="main-content">{skip}\n{nav}', 1)


def _slug(text: str) -> str:
    """Filesystem/URL-safe anchor id for a heading."""
    out = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return out or "section"


class _Html(str):
    """A string that is already trusted markup and must not be escaped again.

    Tables escape every cell, which is correct for data but destroyed the
    epistemic pills and the consent cells: readers saw
    `&lt;span class='pill...&gt;` as literal text. Escaping stays the default; a
    cell must *opt in* to being pre-rendered, so a device-supplied string can
    never reach the document unescaped by accident.
    """

    __slots__ = ()


def _table(headers: list[str], rows: list[list[Any]], empty: str,
           caption: str = "", *, collapsible: bool = False) -> str:
    """Render a table with real semantics.

    * every header carries `scope="col"` so a screen reader can announce the column
      while reading a cell;
    * a visually-hidden `<caption>` names the table (WCAG 1.3.1) — sighted readers get
      the surrounding heading instead, screen-reader users get a name for the table
      itself rather than an unlabelled grid;
    * `collapsible=True` wraps a long table in `<details>`, which is the only
      collapse mechanism that works with scripting disabled. Browsers cannot sort a
      table without JavaScript, so this offers disclosure, never a sort control that
      silently does nothing.
    """
    head = "".join(f"<th scope='col'>{esc(h)}</th>" for h in headers)

    def cell_html(cell: Any) -> str:
        # Opt-in only: a _Html cell is trusted markup, anything else is escaped.
        return str(cell) if isinstance(cell, _Html) else esc(cell)

    body = "".join("<tr>" + "".join(f"<td>{cell_html(cell)}</td>" for cell in row) + "</tr>"
                   for row in rows)
    if not body:
        body = f"<tr><td colspan='{len(headers)}'>{esc(empty)}</td></tr>"
    caption_html = f"<caption class='sr-only'>{esc(caption)}</caption>" if caption else ""
    table = (f"<table>{caption_html}<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>")
    if not collapsible:
        return f"<div class='table-wrap'>{table}</div>"
    return (f"<details class='disclose'><summary>Show all {esc(len(rows))} rows</summary>"
            f"<div class='table-wrap'>{table}</div></details>")


def _hardware_section(report: dict[str, Any]) -> str:
    """Section 3 (hardware & components) and its battery/power split. Empty when absent."""
    hardware = report.get("hardware_assessment") or {}
    subsystems = hardware.get("subsystems", {})
    if not subsystems:
        return ""

    def status_rows(keys: list[str]) -> list[list[str]]:
        return [[name, status] for name, status in subsystems.items() if name in keys]

    battery_keys = {"battery", "charging_manual"}
    battery_subsystems = set(battery_keys & set(subsystems))
    other = [name for name in subsystems if name not in battery_subsystems]

    def check_rows(keys: set[str]) -> list[list[str]]:
        return [[c.get("subsystem", ""), c.get("question", ""), c.get("status", ""),
                 c.get("measurement", ""), c.get("confidence", "")]
                for c in hardware.get("checks", []) if c.get("subsystem") in keys]

    def warn_rows(keys: set[str]) -> list[list[str]]:
        return [[c.get("subsystem", ""), c.get("question", ""), c.get("explanation", "")]
                for c in hardware.get("warnings", []) if c.get("subsystem") in keys]

    parts: list[str] = []

    # --- Section 3: hardware and components
    parts.append(
        f"<section class='panel'><h2>3. Hardware and components</h2>"
        f"{_table(['Subsystem', 'Overall status'], status_rows(other), 'No component assessment was recorded.')}"
        f"{_table(['Subsystem', 'Question', 'Status', 'Measurement', 'Confidence'], check_rows(set(other)), 'No individual component checks recorded.')}"
        f"{_table(['Subsystem', 'Warning / review item', 'Explanation'], warn_rows(set(other)), '')}"
        f"<p class='muted'>{esc(hardware.get('disclaimer', ''))}</p></section>")

    # --- Section 4: battery and power (its own section in the v5 outline)
    battery_part = (
        f"<section class='panel'><h2>4. Battery and power</h2>"
        f"{_table(['Subsystem', 'Overall status'], status_rows(list(battery_subsystems)), 'No battery assessment was recorded. A missing battery metric is <b>not</b> evidence of a replaced battery.')}"
        f"{_table(['Subsystem', 'Question', 'Status', 'Measurement', 'Confidence'], check_rows(battery_subsystems), 'No battery checks recorded.')}"
        f"{_table(['Subsystem', 'Warning / review item', 'Explanation'], warn_rows(battery_subsystems), '')}"
        "<p class='muted'>Battery metrics here are tool-reported candidates. Confirm charge cycles and battery health in "
        "Settings &rarr; Battery &rarr; Battery Health before treating any of them as a service-history fact.</p></section>")

    return "".join(parts) + battery_part


def _integrity_section(report: dict[str, Any]) -> str:
    """Section 5 (parts, repairs & integrity). Empty when there is nothing to show."""
    integrity = report.get("integrity_assessment") or {}
    # `continuity` is v4-only: a v3 report has no such key and must render exactly as
    # before. It is also the one field that must be shown even when classifications and
    # changes are both empty — "no differences found" between two snapshots that may not
    # describe the same physical device is not a pass, and hiding the key would let an
    # empty panel imply one.
    continuity = integrity.get("continuity")
    if not (integrity.get("classifications") or integrity.get("changes") or continuity):
        return ""
    overall = integrity.get("overall", "inconclusive")
    if overall == "suspicious":
        integrity_verdict_class = "high"
    elif overall == "change_detected":
        integrity_verdict_class = "warn"
    else:
        integrity_verdict_class = "neutral"
    continuity_line = f"<p class='muted'>Device continuity: {esc(continuity)}</p>" if continuity else ""
    class_rows = [[field_name, status] for field_name, status in integrity.get("classifications", {}).items()]
    change_rows = [[ch.get("field", ""), ch.get("previous", ""), ch.get("current", ""),
                    ch.get("classification", ch.get("status", "")), ch.get("confidence", "")]
                   for ch in integrity.get("changes", [])]
    return (
        f"<section class='panel'><h2>5. Parts, repairs and integrity</h2>"
        f"<div class='verdict {integrity_verdict_class}'>Integrity status: {esc(overall)}</div>"
        f"{continuity_line}"
        f"{_table(['Field / item', 'Classification'], class_rows, 'No classifications')}"
        f"{_table(['Changed field', 'Previous', 'Current', 'Classification', 'Confidence'], change_rows, 'No changes between snapshots')}"
        "<p class='muted'>A metadata difference is a <i>change detected</i>, never proof of a replaced part. "
        "Apple exposes no public API for parts-pairing state or repair history; Parts &amp; Service History "
        "lives in on-device Settings only.</p>"
        f"<p class='muted'>{esc(integrity.get('disclaimer', ''))}</p></section>")


def _redact_identifier(value: Any) -> str:
    """Mask an identifier. Delegates to the single util helper (docs/v5/07)."""
    return redact(value)


# Keys whose *values* are identifiers wherever they appear in the report tree.
# Redaction used to be positional — it masked `device`, `target_udid`,
# `connected_devices` and `collection[].command` and left everything else alone,
# so a UDID inside a finding's free-text `detail` reached report-redacted.json in
# the clear. Redaction is now recursive over these keys plus known identifier
# values, so no new field can silently opt out of it.
IDENTIFIER_KEYS = frozenset({
    "SerialNumber", "InternationalMobileEquipmentIdentity", "UniqueDeviceID", "UDID",
    "WiFiAddress", "BluetoothAddress", "IMEI", "IMSI", "MEID", "ICCID", "PhoneNumber",
})


def _scrub_identifiers(value: Any, secrets: tuple[str, ...]) -> Any:
    """Return a deep copy of *value* with every known identifier masked.

    Two independent passes, because an identifier can appear either as a *value
    under a known key* or as *free text* anywhere at all:

    1. dict keys in :data:`IDENTIFIER_KEYS` are masked by key name, regardless of
       which section they sit in.
    2. any remaining string has every known secret value (the real UDID, serial,
       IMEI, MAC) replaced with its masked form, which is what catches a UDID
       embedded in a finding's `detail` sentence.

    The copy is deep, so the caller's report is never mutated — the private
    report.json and the redacted report must not share a single list.
    """
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and key in IDENTIFIER_KEYS and isinstance(item, str):
                out[key] = _redact_identifier(item)
            else:
                out[key] = _scrub_identifiers(item, secrets)
        return out
    if isinstance(value, list):
        return [_scrub_identifiers(item, secrets) for item in value]
    if isinstance(value, tuple):
        return tuple(_scrub_identifiers(item, secrets) for item in value)
    if isinstance(value, str):
        masked = value
        for secret in secrets:
            if secret and len(secret) >= 6:
                masked = masked.replace(secret, _redact_identifier(secret))
        return masked
    return value


def _report_secrets(report: dict[str, Any]) -> tuple[str, ...]:
    """Every literal identifier value this run knows, longest first.

    Ordered longest-first so a serial that is a prefix of a longer string cannot
    mask only part of it.
    """
    candidates: list[str] = []

    def take(value: Any) -> None:
        if isinstance(value, str) and len(value.strip()) >= 6:
            candidates.append(value.strip())

    device = report.get("device")
    if isinstance(device, dict):
        for key in IDENTIFIER_KEYS:
            take(device.get(key))
    take(report.get("target_udid"))
    for udid in report.get("connected_devices", []) or []:
        take(udid)
    return tuple(sorted(set(candidates), key=len, reverse=True))


def _partial_collection_banner(report: dict[str, Any], assessment: dict[str, Any]) -> str:
    """Visible warning when collection was incomplete (spec §12 / phase-5 task 2).

    A partial run must never read like a healthy one, so the banner names the exact
    report sections that could not be evaluated instead of only counting failures.
    """
    collection = [c for c in report.get("collection", []) if isinstance(c, dict)]
    # Any step that produced no usable evidence leaves sections unevaluable, so
    # the banner must fire for all of them — a partial run must never read like a
    # healthy one. The banner's *wording* still separates the two kinds: a real
    # negative result is a finding about the device, while a missing tool, a
    # declined consent, or a timeout is only an absence of evidence.
    failed = [c for c in collection
              if _bucket_of(c.get("status"), _COLLECTION_STATUS_BUCKET) not in {"passed", "warning"}]
    incomplete_status = assessment.get("status") == "incomplete"
    if not failed and not incomplete_status:
        return ""

    sections: list[str] = []
    for item in failed:
        name = str(item.get("name", "") or "").lower()
        matched = False
        for keyword, mapped in _COLLECTOR_SECTION_HINTS:
            if keyword in name:
                for section in mapped:
                    if section not in sections:
                        sections.append(section)
                matched = True
        if not matched:
            for section in _DEFAULT_UNEVALUABLE:
                if section not in sections:
                    sections.append(section)
    if incomplete_status and not sections:
        # Status is incomplete even when every collector reported success — typically
        # missing identity fields. Identity-dependent sections are what cannot stand.
        for section in ("Device identity (reported by iOS)", "Comparison with previous inspection"):
            if section not in sections:
                sections.append(section)

    failed_names = [str(c.get("name") or "unnamed collector") for c in failed]
    reasons: list[str] = []
    if failed_names:
        negative = [c for c in failed
                    if _bucket_of(c.get("status"), _COLLECTION_STATUS_BUCKET) == "failed"]
        if negative:
            reasons.append(f"{len(negative)} check(s) ran and returned a negative result: "
                           + ", ".join(str(c.get("name") or "unnamed") for c in negative) + ".")
        unavailable = [c for c in failed if c not in negative]
        if unavailable:
            reasons.append(
                f"{len(unavailable)} of {len(collection)} collector step(s) produced no usable "
                "evidence — an environment or permission gap, not a device fault: "
                + ", ".join(str(c.get("name") or "unnamed") for c in unavailable) + ".")
    if incomplete_status:
        reasons.append("The automated assessment status is 'incomplete' — evidence gaps remain.")
    if not collection:
        reasons.append("No collection commands were recorded for this report.")

    section_items = "".join(f"<li>{esc(section)}</li>" for section in sections)
    reason_items = "".join(f"<li>{esc(reason)}</li>" for reason in reasons)
    return (
        "<section class='panel banner-incomplete' role='alert'>"
        "<h2>⚠ INCOMPLETE COLLECTION — THIS REPORT IS NOT A COMPLETE ASSESSMENT</h2>"
        f"<p><b>Read this first.</b> Collection did not finish cleanly. The sections below could "
        f"not be fully evaluated and must be treated as <b>inconclusive</b>, not as passes and not "
        f"as failures. Do not rely on absent data as a negative result.</p>"
        f"<ul>{reason_items}</ul>"
        + (f"<p><b>Sections that cannot be evaluated from this run:</b></p><ul>{section_items}</ul>"
           if section_items else "")
        + "<p class='muted'>Resolve the failed collectors (toolchain, trust pairing, permissions, "
          "timeouts) and rerun before drawing conclusions. See "
          "'Unknown / unavailable / unsupported / skipped tests' for the full gap list.</p></section>"
    )


def _unknown_panel(report: dict[str, Any]) -> str:
    """Explicit unknown/unavailable/unsupported/skipped panel (spec §12, phase-5 task 3).

    Sourced from the capability matrix so the report cannot drift from what the
    toolchain can and cannot establish. Counts come from the same data as the panel
    rows; nothing here is a pass/fail judgement.
    """
    matrix = get_matrix()
    counts = coverage_counts()
    manual = [row for row in matrix if row.get("coverage") == "manual"]
    unsupported = [row for row in matrix if row.get("coverage") == "unsupported"]
    partial = [row for row in matrix if row.get("coverage") == "partial"]

    def rows_for(rows: list[dict[str, str]]) -> list[list[Any]]:
        return [[row.get("category", ""), row.get("item", ""), row.get("coverage", ""),
                 row.get("requirements", ""), row.get("limits", "")] for row in rows]

    counts_items = "".join(
        f"<li><b>{esc(level)}</b>: {esc(counts.get(level, 0))}</li>" for level in COVERAGE_LEVELS)
    total = len(matrix)
    # v5 §4C: this panel is a subsection of "Risks, findings and actions", so it
    # emits no <section>/<h2> of its own.
    return (
        "<h3>Unknown, unavailable, unsupported and skipped tests</h3>"
        f"<p>This subsection exists so that a reader never mistakes <i>not measured</i> for "
        f"<i>measured and fine</i>. It is generated from the project's capability matrix "
        f"({esc(total)} declared capabilities) and lists what software cannot decide, plus what "
        f"this specific run did not collect. Absence of evidence is never a pass.</p>"
        f"<p><b>Capability coverage across the whole project:</b></p><ul>{counts_items}</ul>"
        f"<h3>Can never be established in software ({esc(len(unsupported))})</h3>"
        "<p class='muted'>The tool will never claim these. They require an authorized service "
        "provider, on-device inspection, or are physically impossible to determine.</p>"
        + _table(["Category", "Item", "Coverage", "Why it is not automatic / requirements", "Limits"],
                 rows_for(unsupported), "No unsupported capabilities declared.") +
        f"<h3>Requires a guided manual test ({esc(len(manual))})</h3>"
        "<p class='muted'>A human must run these. Software output can never decide them; a "
        "successful automated run leaves them unverified.</p>"
        + _table(["Category", "Item", "Coverage", "How it is tested / requirements", "Limits"],
                 rows_for(manual), "No manual capabilities declared.") +
        f"<h3>Partial coverage — tool hints only ({esc(len(partial))})</h3>"
        "<p class='muted'>These produce hints, not verdicts. A missing value here means "
        "<i>not tested</i> (newer iOS versions frequently withhold diagnostics), never "
        "<i>healthy</i>.</p>"
        + _table(["Category", "Item", "Coverage", "Source", "Limits"],
                 rows_for(partial), "No partial capabilities declared.") +
        "<h3>Skipped / unavailable in this specific run</h3>"
        "<p class='muted'>Collectors that failed, timed out, were not requested, or whose tool is "
        "not installed. Each line is an evidence gap for the sections named above &mdash; "
        "<b>not</b> a finding that something is wrong with the device.</p>"
        + _table(["Collector", "Status", "Outcome", "Exit code", "Timed out", "Duration (s)"],
                 [[c.get("name", ""), c.get("status", ""), _gap_outcome(c.get("status")),
                   _val(c.get("returncode")), _val(c.get("timed_out")), _val(c.get("duration_seconds"))]
                  for c in report.get("collection", []) if isinstance(c, dict)
                  and _bucket_of(c.get("status"), _COLLECTION_STATUS_BUCKET)
                  not in {"passed", "warning"}],
                 "Every collector produced usable evidence. Manual and unsupported "
                 "capabilities above still require a human.")
    )


_VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input",
                        "link", "meta", "param", "source", "track", "wbr"})


class _ReportHTMLParser(HTMLParser):
    """Collect unclosed tags, anchors/hrefs, and the rendered dashboard counts.

    stdlib only (spec: re-parse the written report without a dependency). Tags inside
    comments/attributes are not parsed as tags, and SVG child elements are tracked the
    same way as HTML ones so `<circle>`/`<rect>` must close too.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.problems: list[str] = []
        self.hrefs: list[str] = []
        self.counts: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value for key, value in attrs}
        # A dashboard tile carries its bucket name in data-dash-key and its value in
        # data-dash-count. The value is an attribute, not the text node, so a tile that
        # *displays* "not collected" still validates against the true count behind it.
        key = attributes.get("data-dash-key")
        if key is not None and attributes.get("data-dash-count") is not None:
            self.counts[str(key)] = str(attributes["data-dash-count"])
        href = attributes.get("href")
        if href:
            self.hrefs.append(href)
        if tag not in _VOID_TAGS:
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value for key, value in attrs}
        href = attributes.get("href")
        if href:
            self.hrefs.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag in _VOID_TAGS:
            return
        if tag not in self.stack:
            self.problems.append(f"stray closing tag </{tag}>")
            return
        while self.stack:
            open_tag = self.stack.pop()
            if open_tag == tag:
                break
            self.problems.append(f"unclosed tag <{open_tag}> closed by </{tag}>")

    def close(self) -> None:  # type: ignore[override]
        super().close()
        for open_tag in self.stack:
            self.problems.append(f"unclosed tag <{open_tag}> at end of document")


def validate_report_html(html_text: str, report: dict[str, Any]) -> list[str]:
    """Re-parse rendered HTML and report structural/semantic problems.

    Checks (spec §4C validation):
      1. basic well-formedness — unclosed / stray tags;
      2. every rendered evidence link resolves to something recorded in the report;
      3. dashboard counts equal a fresh recomputation from the report structures.

    Never raises: a validation failure must not stop report generation. Returns a
    list of human-readable error strings (empty when the document is clean).
    """
    errors: list[str] = []
    parser = _ReportHTMLParser()
    try:
        parser.feed(html_text)
        parser.close()
    except (AssertionError, ValueError, TypeError) as exc:  # pragma: no cover - html.parser is tolerant
        return [f"HTML could not be parsed: {exc}"]
    errors.extend(parser.problems)

    # (2) Evidence links must resolve to a path the report actually records.
    # Every step tolerates a malformed report: validation is a diagnostic aid and
    # must never become the reason a report fails to be written.
    try:
        known: set[str] = set()
        findings = report.get("findings") if isinstance(report, dict) else None
        if isinstance(findings, (list, tuple)):
            for finding in findings:
                if isinstance(finding, dict):
                    for path in finding.get("evidence") or []:
                        known.add(str(path))
        collection = report.get("collection") if isinstance(report, dict) else None
        if isinstance(collection, (list, tuple)):
            for item in collection:
                if isinstance(item, dict):
                    for key in ("stdout_file", "stderr_file"):
                        if item.get(key):
                            known.add(str(item[key]))
        for href in parser.hrefs:
            if href.startswith(("#", "mailto:")):
                continue
            target = href.split("#", 1)[0]
            if target and target not in known:
                errors.append(f"evidence link not found in report: {target}")
    except (AttributeError, TypeError, ValueError) as exc:
        errors.append(f"evidence links could not be checked: {exc}")

    # (3) Dashboard counts must match a fresh recomputation from the JSON.
    try:
        expected = dashboard_counts(report)
        rendered = parser.counts
        for name in OUTCOME_BUCKETS:
            if name not in rendered:
                errors.append(f"dashboard count missing from HTML: {name}")
                continue
            try:
                if int(rendered[name]) != int(expected[name]):
                    errors.append(f"dashboard count mismatch for {name}: "
                                  f"HTML {rendered[name]} != JSON {expected[name]}")
            except (TypeError, ValueError):
                errors.append(f"dashboard count is not a number for {name}: {rendered[name]!r}")
        if "checks_performed" in rendered:
            try:
                if int(rendered["checks_performed"]) != int(expected["checks_performed"]):
                    errors.append("dashboard count mismatch for checks_performed: "
                                  f"HTML {rendered['checks_performed']} != JSON {expected['checks_performed']}")
            except (TypeError, ValueError):
                errors.append("dashboard checks_performed is not a number")
        # A rendered zero must be a real zero, not a gap: the dashboard shows
        # "not collected" for those, and the attribute carries the true count.
    except (AttributeError, TypeError, ValueError) as exc:  # pragma: no cover - total function
        errors.append(f"dashboard counts could not be recomputed: {exc}")

    return errors


def build_html(run_dir: Path, report: dict[str, Any], redact_identifiers: bool = False) -> None:
    device = report.get("device", {}) if isinstance(report.get("device"), dict) else {}
    # v5 §4C splits identity (§2) from configuration (§6): §2 is "which device is
    # this", §6 is "what state is it in". Capacity/activation used to sit in the
    # identity list; they are configuration facts and belong in §6.
    identity_fields = ["DeviceName", "ProductType", "ProductVersion", "BuildVersion",
                       "ModelNumber", "HardwareModel", "SerialNumber",
                       "InternationalMobileEquipmentIdentity"]
    config_fields = ["ActivationState", "CarrierBundleVersion", "ProductName",
                     "DeviceColor", "BasebandVersion", "TimeZone", "TotalDiskCapacity",
                     "TotalDataCapacity"]
    important = identity_fields + config_fields
    sensitive_keys = {"SerialNumber", "InternationalMobileEquipmentIdentity", "UniqueDeviceID", "UDID", "WiFiAddress", "BluetoothAddress"}
    identity_rows = [[key, _redact_identifier(device.get(key)) if redact_identifiers and key in sensitive_keys else device.get(key)]
                     for key in important if device.get(key) is not None]
    config_rows = [[key, _redact_identifier(device.get(key)) if redact_identifiers and key in sensitive_keys else device.get(key)]
                   for key in config_fields if device.get(key) is not None]
    for capacity_key in ("TotalDiskCapacity", "TotalDataCapacity"):
        value = device.get(capacity_key)
        try:
            capacity_bytes = int(value)
            identity_rows.append([f"{capacity_key} (decimal GB, derived)", f"{capacity_bytes / 1_000_000_000:.2f} GB"])
        except (TypeError, ValueError):
            pass
    findings = report.get("findings", [])
    finding_rows = [[f.get("severity", "INFO"), f.get("title", ""), f.get("detail", ""), ", ".join(f.get("evidence", []))] for f in findings]
    epistemic_rows = [[f.get("severity", "INFO"), f.get("title", ""), _epistemic_badge(f)]
                      for f in findings]
    # Missing collection telemetry stays "not provided" — a collector that never ran is not a
    # collector that returned zero bytes / exit code 0.
    collection_rows = [[c.get("name"), c.get("status"), _val(c.get("returncode")),
                        _val(c.get("duration_seconds")), _val(c.get("stdout_bytes")),
                        _val(c.get("stderr_bytes"))]
                       for c in report.get("collection", []) if isinstance(c, dict)]
    tool_rows = [[name, path or "not installed"] for name, path in report.get("tools", {}).items()]
    diagnostic_rows = [[m.get("source"), m.get("key"), _val(m.get("value")), m.get("interpretation")]
                       for m in report.get("diagnostic_candidates", [])]
    limits = report.get("limitations", [])
    crash_triage = report.get("crash_triage", {})
    crash_rows = [[item.get("path"), item.get("category"), _val(item.get("timestamp")),
                   _val(item.get("procName", item.get("name"))), _val(item.get("panicString"))]
                  for item in crash_triage.get("panic_candidates", []) + crash_triage.get("crash_candidates", [])]
    assessment = report.get("assessment", {}) if isinstance(report.get("assessment"), dict) else {}
    checklist_eval = assessment.get("buyer_checklist", evaluate(report.get("buyer_data")))
    checklist_data = report.get("buyer_data") or {}
    checks = checklist_data.get("checks", {}) if isinstance(checklist_data, dict) else {}
    buyer_rows = []
    for item in CHECKLIST:
        entry = checks.get(item["id"], {}) if isinstance(checks, dict) else {}
        buyer_rows.append([item["category"], item["label"], (entry.get("status", "not_tested") if isinstance(entry, dict) else "not_tested"),
                           (entry.get("notes", "") if isinstance(entry, dict) else ""), "Critical" if item["critical"] else "Standard"])
    buyer = checklist_data.get("buyer", {}) if isinstance(checklist_data, dict) else {}
    observations = checklist_data.get("observations", {}) if isinstance(checklist_data, dict) else {}
    currency = buyer.get("currency") or "USD"  # documented default; template() always sets it
    # Buyer-supplied observations are free text: an omitted field is "not provided", never 0.
    buyer_summary = [["Asking price", _val(buyer.get("asking_price"))], ["Currency", currency],
                     ["Country/region", _val(buyer.get("country_or_region"))],
                     ["Advertised model", _val(buyer.get("advertised_model"))],
                     ["Advertised storage", _val(buyer.get("advertised_storage"))],
                     ["Battery maximum capacity (%)", _val(observations.get("battery_max_capacity_percent"))],
                     ["Battery cycle count", _val(observations.get("battery_cycle_count"))],
                     ["Reported storage (GB)", _val(observations.get("reported_storage_gb"))],
                     ["Repair estimate", _val(observations.get("repair_estimate"))],
                     ["Carrier eligibility", _val(observations.get("carrier_eligibility_result"), "not_checked")]]
    buyer_summary_rows = [[k, v] for k, v in buyer_summary]
    asking = buyer.get("asking_price")
    repair = observations.get("repair_estimate")
    projected_cost = None
    try:
        if asking is not None and repair is not None:
            projected_cost = float(asking) + float(repair)
    except (TypeError, ValueError):
        projected_cost = None
    if projected_cost is not None:
        buyer_summary_rows.append(["Asking price + buyer-entered repair estimate",
                                   f"{projected_cost:g} {currency} (not a market valuation)"])
    if report.get("comparison"):
        comparison_rows = [[item.get("field"), item.get("previous"), item.get("current"), item.get("status")] for item in report["comparison"].get("changes", [])]
    else:
        comparison_rows = []
    severity_class = "high" if assessment.get("status") == "high_risk" else "warn" if assessment.get("status") in {"incomplete", "review"} else "neutral"
    # A partial run must never be styled or worded like a healthy one.
    incomplete_banner = _partial_collection_banner(report, assessment)
    if incomplete_banner and severity_class == "neutral":
        severity_class = "warn"
    unknown_panel = _unknown_panel(report)
    claim_matrix = _claim_matrix_panel()
    hardware_sections = _hardware_section(report)
    integrity_section = _integrity_section(report)
    # v5 dashboard + charts render directly under section 1. They read the same
    # `dashboard_counts` the validator recomputes, so the numbers cannot drift.
    dashboard = _dashboard(report, redact_identifiers=redact_identifiers)
    charts = _outcome_charts(report, dashboard_counts(report)) + _coverage_charts(report)
    html_doc = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>iPhone Forensics v{esc(report.get("version"))} — Buyer Inspection Report</title>
<style>
:root{{
  --bg:#eef1f6;--panel:#fff;--ink:#131b26;--muted:#5b6674;--line:#d7dee6;--accent:#1f4f9c;
  --accent-soft:#e8f0fb;--high:#8f2020;--warn:#7d5100;--good:#14603a;
  --shadow:0 1px 2px #0d1b2a0f,0 6px 18px #0d1b2a0a;--radius:14px;
  --mono:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,monospace;
}}
@media (prefers-color-scheme:dark){{:root{{
  --bg:#0e1319;--panel:#161d26;--ink:#e6ecf3;--muted:#9aa7b6;--line:#2a3542;--accent:#7fb0f5;
  --accent-soft:#17263a;--high:#f08a8a;--warn:#e0b25e;--good:#6cd39a;
  --shadow:0 1px 2px #0006,0 6px 18px #0004;}}}}
@media (prefers-reduced-motion:reduce){{*{{animation-duration:.01ms !important;transition-duration:.01ms !important;scroll-behavior:auto !important}}}}
*{{box-sizing:border-box}}
html{{scroll-behavior:smooth;scroll-padding-top:1rem}}
body{{margin:0;background:var(--bg);color:var(--ink);
  font:16px/1.62 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility}}
main{{max-width:1140px;margin:0 auto;padding:28px 20px 72px}}
h1{{font-size:clamp(1.75rem,4.2vw,2.7rem);line-height:1.15;margin:.2em 0 .3em;letter-spacing:-.022em;font-weight:760}}
h2{{font-size:1.3rem;line-height:1.3;margin:0 0 14px;letter-spacing:-.012em;font-weight:720}}
h3{{font-size:1.02rem;margin:22px 0 8px;font-weight:700;letter-spacing:-.006em}}
h4{{font-size:.78rem;margin:20px 0 8px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;font-weight:700}}
p{{margin:9px 0}}
code{{font-family:var(--mono);font-size:.88em;background:var(--accent-soft);padding:.1em .38em;border-radius:5px;overflow-wrap:anywhere}}
.muted{{color:var(--muted)}}
.panel{{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:22px 24px;margin:18px 0;box-shadow:var(--shadow)}}
.panel>h2:first-child{{margin-top:0}}
.hero{{border-top:5px solid var(--accent)}}

/* --- accessibility helpers ------------------------------------------------ */
.sr-only{{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap;border:0}}
.skip-link{{position:absolute;left:-9999px;top:0;background:var(--accent);color:#fff;padding:10px 16px;border-radius:0 0 8px 0;z-index:99;font-weight:600}}
.skip-link:focus{{left:0}}
:focus-visible{{outline:2.5px solid var(--accent);outline-offset:2px;border-radius:3px}}
.anchor{{opacity:0;margin-left:.4em;font-size:.7em;color:var(--accent);text-decoration:none;font-weight:600}}
h2:hover .anchor,.anchor:focus{{opacity:1}}

/* --- table of contents ---------------------------------------------------- */
.toc{{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:18px 22px;margin:18px 0;box-shadow:var(--shadow)}}
.toc-heading{{font-size:.78rem;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);margin:0 0 10px}}
.toc-list{{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(255px,1fr));gap:2px 22px;counter-reset:none}}
.toc-list li{{margin:0}}
.toc-list a{{display:flex;gap:9px;align-items:baseline;padding:5px 8px;border-radius:7px;color:var(--ink);text-decoration:none;font-size:.9rem;line-height:1.4}}
.toc-list a:hover{{background:var(--accent-soft);color:var(--accent)}}
.toc-num{{flex:0 0 auto;min-width:1.55em;font-variant-numeric:tabular-nums;font-weight:700;color:var(--accent);font-size:.82rem}}

/* --- dashboard ------------------------------------------------------------ */
.dash{{margin-top:18px}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:10px;margin-top:10px}}
.stat{{border:1px solid var(--line);border-radius:11px;padding:11px 13px;background:var(--bg)}}
.stat .muted{{display:block;font-size:.73rem;text-transform:uppercase;letter-spacing:.055em;margin-bottom:3px}}
.stat b{{display:block;font-size:1.22rem;font-weight:740;line-height:1.25;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}}
.verdict{{padding:15px 17px;border-radius:11px;font-weight:700;font-size:1.05rem;line-height:1.45}}
.verdict.high{{background:#fce8e8;color:var(--high)}}
.verdict.warn{{background:#fff3d9;color:var(--warn)}}
.verdict.neutral{{background:#e8f5ee;color:var(--good)}}
@media (prefers-color-scheme:dark){{.verdict.high{{background:#3a1c1c}}.verdict.warn{{background:#382c14}}.verdict.neutral{{background:#16301f}}}}
.callout{{border-left:4px solid var(--accent);padding:11px 14px;background:var(--accent-soft);border-radius:0 8px 8px 0}}
.banner-incomplete{{border:2px solid var(--high);background:#fdeaea}}
.banner-incomplete h2{{color:var(--high);margin-bottom:10px}}
.banner-incomplete ul{{margin:8px 0;padding-left:22px}}
.banner-incomplete li{{margin:5px 0}}
@media (prefers-color-scheme:dark){{.banner-incomplete{{background:#2c1618}}}}

/* --- tables --------------------------------------------------------------- */
.table-wrap{{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}}
table{{width:100%;border-collapse:collapse;min-width:520px;font-size:.92rem}}
th,td{{text-align:left;vertical-align:top;padding:9px 11px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}}
th{{background:var(--bg);font-size:.76rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:700;position:sticky;top:0}}
tbody tr:hover{{background:var(--accent-soft)}}
tbody tr:last-child td{{border-bottom:none}}
.disclose{{margin:10px 0}}
.disclose>summary{{cursor:pointer;font-weight:650;padding:7px 12px;border:1px solid var(--line);border-radius:9px;background:var(--bg);display:inline-block;font-size:.88rem}}
.disclose>summary:hover{{background:var(--accent-soft)}}

/* --- pills & charts ------------------------------------------------------- */
.pill{{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:2px 9px;font-size:.76rem;font-weight:700;white-space:nowrap}}
.chart{{max-width:100%;height:auto;overflow:visible}}
.chart-panel{{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:16px 18px;margin:14px 0;box-shadow:var(--shadow)}}
.chart-panel h3{{margin-top:0}}

footer{{margin-top:30px;padding-top:16px;border-top:1px solid var(--line);color:var(--muted);font-size:.86rem}}

/* --- responsive ----------------------------------------------------------- */
@media(max-width:640px){{
  main{{padding:16px 11px 48px}}
  .panel{{padding:16px 15px}}
  .stat b{{font-size:1.1rem}}
  .toc-list{{grid-template-columns:1fr}}
  table{{min-width:440px}}
}}

/* --- print ---------------------------------------------------------------- */
@media print{{
  :root{{--bg:#fff;--panel:#fff;--ink:#000;--muted:#333;--line:#bbb;--shadow:none}}
  body{{background:#fff;font-size:10.5pt}}
  main{{max-width:none;padding:0}}
  .panel{{border:1px solid #ccc;box-shadow:none;padding:12px;margin:10px 0;break-inside:avoid;page-break-inside:avoid}}
  h2,h3,h4{{break-after:avoid;page-break-after:avoid}}
  table{{min-width:0;font-size:9pt}}
  th{{background:#eee !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
  .skip-link,.anchor,.disclose>summary{{display:none !important}}
  .disclose{{display:block !important}}
  .disclose>*{{display:revert !important}}
  .chart-panel{{break-inside:avoid;page-break-inside:avoid}}
  .toc{{break-after:avoid}}
  a{{color:#000;text-decoration:none}}
  footer{{border-top:1px solid #ccc}}
}}
</style></head><body><main>
<header><p class="muted">LOCAL DEVICE INSPECTION · V{esc(report.get("version"))}</p><h1>Used iPhone Inspection Report</h1><p class="muted">Started {esc(report.get("started_at"))} · Finished {esc(report.get("finished_at"))}</p></header>
<section class="panel hero"><h2>1. Executive summary</h2><div class="verdict {severity_class}">{esc(assessment.get("verdict", "INCOMPLETE — NO ASSESSMENT"))}</div><p>{esc(assessment.get("description", ""))}</p>
<div class="stats"><div class="stat"><span class="muted">Collectors completed</span><b>{esc(_val(assessment.get("collection_successful")))}/{esc(_val(assessment.get("collection_total")))}</b></div><div class="stat"><span class="muted">Failed / partial</span><b>{esc(_val(assessment.get("collection_failed_or_partial")))}</b></div><div class="stat"><span class="muted">Identity fields</span><b>{esc(_val(assessment.get("identity_fields_present")))}/{esc(_val(assessment.get("identity_fields_expected")))}</b></div><div class="stat"><span class="muted">Checklist passed</span><b>{esc(_val(checklist_eval.get("counts", {}).get("pass")))}/{len(CHECKLIST)}</b></div></div>
<p class="callout"><b>Interpretation:</b> missing or inaccessible data is unknown, not a pass or a device defect. This tool cannot certify authenticity, hardware health, water resistance, Activation Lock status, or blacklist eligibility.</p>
{dashboard}
{charts}
</section>
{incomplete_banner}
<section class="panel"><h2>2. Device identity and configuration</h2>
<h3>Identity, as reported by iOS</h3>{_table(["Field","Reported value"], identity_rows, "No parsed identity fields. Check collected metadata and Settings → General → About.")}
<p class="muted">Identifiers such as serial number, IMEI and UDID are sensitive. Reported values are not cryptographic proof of authenticity.{" This HTML export masks identifiers; the private JSON and evidence remain unredacted." if redact_identifiers else ""}</p>
<h3>Change since the previous inspection</h3>{_table(["Field","Previous","Current","Assessment"], comparison_rows, "No previous report was supplied for comparison.")}</section>
{hardware_sections}
{integrity_section}
<section class="panel"><h2>6. System integrity and configuration</h2>{_table(["Field","Reported value"], config_rows, "No configuration fields were collected.")}
<p class="muted">Activation state and carrier fields are reported by iOS and are not independently verified here. An
activated device bound to another account, or an unexpected Remote Management profile, must be resolved with the
seller before payment.</p></section>
<section class="panel"><h2>7. Reliability and diagnostics</h2>
<h3>Diagnostic metric candidates</h3><p>These are source fields whose names look relevant to battery, capacity, thermal, voltage, or storage. They are not normalized or interpreted as health scores; verify units and semantics against the source/tool version.</p>{_table(["Source","Field","Raw value","Caveat"], diagnostic_rows, "No candidate metrics were exposed by the collected diagnostics. This is inconclusive.")}
<h3>Crash and panic triage</h3><p>{esc(crash_triage.get("interpretation", "No crash artifact triage was performed."))}</p><p>Files scanned: {esc(_val(crash_triage.get("files_scanned")))} · Crash/diagnostic candidates: {esc(_val(crash_triage.get("crash_or_diagnostic_count")))} · Panic/watchdog candidates: {esc(_val(crash_triage.get("panic_or_watchdog_candidate_count")))}</p>{_table(["Artifact","Category","Timestamp","Process","Panic signature (if present)"], crash_rows, "No collected crash-report files to triage. This does not mean the phone has no crash history.")}</section>
<section class="panel"><h2>8. Buyer checklist</h2>
<h3>Buyer-critical blockers</h3>{_table(["Status","Item"], [["FAILED", x] for x in checklist_eval.get("critical_failures", [])] + [["NOT VERIFIED", x] for x in checklist_eval.get("critical_unknowns", [])], "No critical checklist gaps were recorded. That is not the same as a verified-clean device: most items default to not tested until a human records them.")}
<h3>Checklist and physical tests</h3><p>Update <code>buyer-checklist.json</code> with statuses <code>pass</code>, <code>fail</code>, <code>not_tested</code>, or <code>not_applicable</code>, then rerun with <code>--buyer-json</code>.</p>
{_table(["Category","Check","Status","Notes","Priority"], buyer_rows, "No checks")}
<h3>Buyer-entered observations</h3>{_table(["Field","Value"], buyer_summary_rows, "No observations")}</section>
<section class="panel"><h2>9. Risks, findings and actions</h2>{_table(["Severity","Finding","Interpretation","Evidence files"], finding_rows, "No automated findings. This is not a health certification.")}
<h3>How each finding was established</h3>
<p class='muted'>Every finding states how it was established. <b>Verified</b> means read directly from collected evidence. <b>Inferred</b> means reasoned from evidence, with the reasoning shown. <b>Unknown</b> means an open question, not a conclusion. <b>Manual check required</b> means this tool cannot observe it and a person must look.</p>
{_table(["Severity","Finding","How this was established"], epistemic_rows, "No findings to label.")}
{unknown_panel}</section>
<section class="panel"><h2>10. Evidence and coverage</h2>{_table(["Collector","Status","Outcome","Exit code","Seconds","Output bytes","Error bytes"], collection_rows, "No collection commands were run.")}
<p class="muted">An expected end of a bounded live log stream is normal. Nonzero exits and timeouts should be reviewed in the evidence files before interpretation. A missing entry here means the collector never reported — it is not a zero-length success.</p>
<p class="muted"><b>Coverage is not health.</b> A run can show full collection coverage and still surface defects; the two
measure different things and neither substitutes for the other.</p></section>
<section class="panel"><h2>11. Technical appendix</h2>
<h3>Toolchain and evidence integrity</h3>{_table(["Tool","Detected path"], tool_rows, "No tool inventory")}
<p class="muted">Capability catalogs contain tool help output only. The presence of a command does not mean the project has safely executed every capability it advertises.</p>
<p>SHA-256 digests and sizes are stored in <code>manifest.json</code>. They help detect changes after collection; they do not prove that device-originated data is authentic.</p><p>Machine-readable companion: <code>report.json</code>. Raw command output and capability help are in <code>evidence/</code>. Keep this directory private.</p>
<h3>What was collected, and with what authority</h3>{_consent_rows(report)}
{claim_matrix}
<h3>Limitations</h3>
<ul>{''.join(f'<li>{esc(item)}</li>' for item in limits)}</ul>
<h3>Recommended pre-payment sequence</h3><ol><li>Seller signs out of Apple Account / Find My and erases the phone.</li><li>Connect to the internet and confirm setup does not request the previous owner's credentials or show unexpected Remote Management.</li><li>Confirm carrier eligibility using the intended carrier or a trusted authoritative provider.</li><li>Complete physical tests and inspect Parts & Service History and Battery Health in Settings.</li><li>Agree on price, return terms, and proof of sale only after unresolved critical checks are settled.</li></ol></section>
<footer>iPhone Forensics v{esc(report.get("version"))} · Generated locally · HTML is the primary human-readable report; JSON and manifest are companion evidence files.</footer>
</main></body></html>'''
    # Anchors + contents list, applied to the assembled document so the outline can
    # only ever describe sections that actually rendered in this run.
    html_doc = _add_toc_and_anchors(html_doc)
    # Re-parse what we just rendered and embed the verdict as a comment. Validation
    # must never block report generation, so a validator failure is reported, not raised.
    issues = validate_report_html(html_doc, report)
    summary = "clean" if not issues else f"{len(issues)} issues"
    html_doc = html_doc.replace("</main>", f"<!-- report-validation: {summary} -->\n</main>", 1)
    for issue in issues[:5]:
        # Cosmetic only: a validation problem is surfaced, never raised, so the
        # report is still written and the reader still gets their document.
        print(f"[report] HTML validation: {issue}", file=sys.stderr)
    (run_dir / "report.html").write_text(html_doc, encoding="utf-8")


def finalize(run_dir: Path, report: dict[str, Any], redact_identifiers: bool = False) -> None:
    report["finished_at"] = report.get("finished_at") or __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    # Every finding states how we know (docs/v5/05). Applied here, at the single
    # choke point every run passes through, so a finding appended from any module
    # cannot reach report.json or the HTML unlabeled.
    from .analysis import label_findings

    if isinstance(report.get("findings"), list):
        label_findings(report["findings"])
    # Enforce the claim matrix before anything is written: an unsupported claim must
    # not be able to reach report.json or the HTML. The audit runs last because it
    # checks the data the earlier stages produced.
    report["claim_audit"] = _audit_claim_matrix(report)

    # Write every artifact *first*, then hash. The manifest used to be written
    # before report.json and the redacted pair, so it hashed the previous run's
    # copies and failed its own verification on the very next check.
    write_json(run_dir / "report.json", report)
    build_html(run_dir, report, redact_identifiers=redact_identifiers)
    if redact_identifiers:
        # Deep copy, then scrub recursively. A shallow `dict(report)` shared the
        # `collection` list with the private report, so masking a command here
        # silently corrupted report.json as well.
        redacted = _scrub_identifiers(report, _report_secrets(report))
        write_json(run_dir / "report-redacted.json", redacted)
        # report-redacted.html is generated from the redacted copy; never include raw evidence links.
        build_html(run_dir, redacted, redact_identifiers=True)
        generated = (run_dir / "report.html").read_text(encoding="utf-8")
        (run_dir / "report-redacted.html").write_text(generated, encoding="utf-8")
        build_html(run_dir, report, redact_identifiers=False)
    create_manifest(run_dir)
