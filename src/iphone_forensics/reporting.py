from __future__ import annotations

import html
import sys
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

from .util import redact, write_json

# Missing telemetry must stay visibly missing. Never coerce absent data to 0/False/"" —
# "unknown" and "zero" mean opposite things in a forensic report (spec §12 / report-schema.md).
MISSING = "not provided"

# v5 §4C report outline: exactly these 11 sections, in this order. The v4 report
# v5.2 brief-report outline rendered by build_html: five sections, in this order.
# The historical outline (SECTION_TITLES below) is retained as documentation of what
# the v4/v5 verbose report carried; the HTML now renders only what a professional
# reader scans: findings, device facts, hardware numbers, and this run's gaps. All
# prose, charts, capability matrices and repeated disclaimers are gone.
SECTION_TITLES: tuple[str, ...] = (
    "Summary",
    "Findings",
    "Device",
    "Hardware",
    "Collection gaps",
)

# Old heading text -> the section that absorbed it. No longer rendered as anchors:
# the brief report is a single short page and needs no table of contents. The
# mapping is kept so legacy deep links and external tooling that referenced the
# verbose outline still resolve to a sensible section name.
SECTION_ALIASES: tuple[tuple[str, str], ...] = (
    ("Executive summary", "Summary"),
    ("Device identity (reported by iOS)", "Device"),
    ("Comparison with previous inspection", "Device"),
    ("Diagnostic metric candidates", "Hardware"),
    ("Hardware health assessment (v4)", "Hardware"),
    ("Hardware integrity assessment (v4)", "Hardware"),
    ("Battery and power", "Hardware"),
    ("System integrity and configuration", "Device"),
    ("Reliability and diagnostics", "Hardware"),
    ("Crash and panic triage", "Hardware"),
    ("Parts, repairs and integrity", "Hardware"),
    ("Automated findings", "Findings"),
    ("Risks, findings and actions", "Findings"),
    ("Collection coverage", "Collection gaps"),
    ("Evidence and coverage", "Collection gaps"),
)


# ---------------------------------------------------------------- v5 dashboard
# Dashboard outcome buckets. These are *epistemic* buckets (what we can say about a
# result), never health grades: nothing here may imply a device is fine.
#
# The mapping is deliberately local and total. A status that is absent, blank, or
# unknown lands in "inconclusive" — the dashboard must never promote an unrecognized
# or missing status into "passed". Gaps map to skipped/unsupported so an unmeasured
# check can never be read as a clean result.
NOT_COLLECTED = "not collected"

OUTCOME_BUCKETS: tuple[str, ...] = (
    "passed",
    "warning",
    "failed",
    "inconclusive",
    "unsupported",
    "skipped",
)

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


def _ratio(numerator: Any, denominator: Any, missing: str = MISSING) -> str:
    """Render an `n/d` pair as a count, or state the absence once.

    Rendering `_val` on each side independently produced the literal string
    "not provided/not provided": two honest placeholders concatenated into something
    that reads as a broken fraction. A pair is only a ratio when both halves exist;
    otherwise it is one fact — the measurement was not recorded.
    """
    num = _val(numerator, "")
    den = _val(denominator, "")
    if num == "" or den == "":
        return missing
    return f"{num}/{den}"


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
        return _GAP_OUTCOME.get(
            str(status if status is not None else "").strip().lower(),
            "No usable evidence collected for this step.",
        )
    except (TypeError, ValueError):  # pragma: no cover - defensive
        return "No usable evidence collected for this step."


# Human wording for each epistemic label. Paired with `_EPISTEMIC_PILL`, which
# carries the colour for the same labels. The text is the signal; the colour is only
# reinforcement, because colour alone is not an accessible cue (WCAG 1.4.1).
_EPISTEMIC_TEXT: dict[str, str] = {
    "observed": "Verified — read from collected evidence",
    "inferred": "Inferred — reasoned from evidence",
    "unknown": "Unknown — open question, not a conclusion",
    "needs_manual": "Manual check required",
}


def _audit_claim_matrix(report: dict[str, Any]) -> dict[str, Any]:
    """Run every claim gate and return the audit record stored in report.json.

    A violation is surfaced, never silently dropped: it is recorded, printed, and
    added as a BLOCKER finding, so a claim the matrix forbids is visible to whoever
    reads the report rather than quietly missing.
    """
    from .capabilities import audit_report
    from .hardware import audit_battery_claims
    from .integrity import audit_integrity_claims

    violations = (
        audit_report(report) + audit_battery_claims(report) + audit_integrity_claims(report)
    )
    for violation in violations:
        # Cosmetic only: an audit failure must never stop a report being written.
        print(f"[report] claim audit: {violation}", file=sys.stderr)
        if isinstance(report.get("findings"), list):
            report["findings"].append(
                {
                    "severity": "BLOCKER",
                    "title": "An unsupported claim was produced and must not be relied on",
                    "detail": violation,
                    "epistemic": "observed",
                    "evidence": [],
                }
            )
    return {
        "checked": True,
        "violations": violations,
        "violation_count": len(violations),
        "note": (
            "A claim the matrix forbids was produced. It is recorded here and raised "
            "as a BLOCKER; do not rely on any conclusion in this run until the "
            "underlying code is fixed."
            if violations
            else "No unsupported claims were produced by this run."
        ),
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
    return _Html(
        f"<span class='pill pill-{esc(label)}'>{esc(_EPISTEMIC_TEXT.get(label, label))}</span>"
    )


# The claim matrix, the forbidden-inference list, the limitations list and the
# pre-payment sequence are policy *about this tool*, not evidence *about the device*.
# They render identically on every device and every run, so they were removed from the
# report body: a per-device forensic document should not carry a wall of boilerplate
# that says nothing about the iPhone in front of it.
#
# Deleting the rendering does NOT delete the guarantee. The matrix is still the single
# source of truth in `capabilities.CLAIM_MATRIX`, it still backs `iphone-forensics
# capabilities`, and `_audit_claim_matrix` still gates every run inside `finalize` by
# inspecting the report data before a byte is written. Enforcement reads data, not
# markup, so it is unaffected by what the HTML does or does not show.


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


def _measured_metrics(report: dict[str, Any]) -> list[tuple[str, str, str]]:
    """Every hardware check that carries an actual numeric measurement.

    Any absent measurement stays out of the table entirely and renders as one honest
    "not collected" line — never as 0%, 100%, or a plausible-looking placeholder.
    """
    hardware = report.get("hardware_assessment") or {}
    if not isinstance(hardware, dict):
        return []

    metrics: list[tuple[str, str, str]] = []
    for check in hardware.get("checks", []) or []:
        if not isinstance(check, dict):
            continue
        measurement = check.get("measurement")
        if not isinstance(measurement, (int, float)) or isinstance(measurement, bool):
            continue
        unit = str(check.get("measurement_unit") or "").strip()
        value = f"{measurement:g}" if isinstance(measurement, float) else str(measurement)
        subsystem = str(check.get("subsystem") or "").strip()
        item = str(check.get("question") or subsystem or "measurement")
        metrics.append((subsystem, item, f"{value}{' ' + unit if unit else ''}"))
    return metrics


def _device_facts(
    report: dict[str, Any], redact_identifiers: bool = False
) -> list[tuple[str, str]]:
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
        for label, key in (
            ("Serial number", "SerialNumber"),
            ("IMEI", "InternationalMobileEquipmentIdentity"),
        ):
            rows.append(
                (label, _redact_identifier(device.get(key)) if device.get(key) else NOT_COLLECTED)
            )
    return [(label, str(value)) for label, value in rows]


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
class _Html(str):
    """A string that is already trusted markup and must not be escaped again.

    Tables escape every cell, which is correct for data but destroyed the
    epistemic pills and the consent cells: readers saw
    `&lt;span class='pill...&gt;` as literal text. Escaping stays the default; a
    cell must *opt in* to being pre-rendered, so a device-supplied string can
    never reach the document unescaped by accident.
    """

    __slots__ = ()


def _table(
    headers: list[str],
    rows: list[list[Any]],
    empty: str,
    caption: str = "",
    *,
    collapsible: bool = False,
) -> str:
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

    body = "".join(
        "<tr>" + "".join(f"<td>{cell_html(cell)}</td>" for cell in row) + "</tr>" for row in rows
    )
    if not body:
        body = f"<tr><td colspan='{len(headers)}'>{esc(empty)}</td></tr>"
    caption_html = f"<caption class='sr-only'>{esc(caption)}</caption>" if caption else ""
    table = f"<table>{caption_html}<thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
    if not collapsible:
        return f"<div class='table-wrap'>{table}</div>"
    return (
        f"<details class='disclose'><summary>Show all {esc(len(rows))} rows</summary>"
        f"<div class='table-wrap'>{table}</div></details>"
    )


def _redact_identifier(value: Any) -> str:
    """Mask an identifier. Delegates to the single util helper (docs/v5/07)."""
    return redact(value)


# Keys whose *values* are identifiers wherever they appear in the report tree.
# Redaction used to be positional — it masked `device`, `target_udid`,
# `connected_devices` and `collection[].command` and left everything else alone,
# so a UDID inside a finding's free-text `detail` reached report-redacted.json in
# the clear. Redaction is now recursive over these keys plus known identifier
# values, so no new field can silently opt out of it.
IDENTIFIER_KEYS = frozenset(
    {
        "SerialNumber",
        "InternationalMobileEquipmentIdentity",
        "UniqueDeviceID",
        "UDID",
        "WiFiAddress",
        "BluetoothAddress",
        "IMEI",
        "IMSI",
        "MEID",
        "ICCID",
        "PhoneNumber",
    }
)


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
    """Terse alert when collection was incomplete: a partial run must never read healthy.

    Names the non-completing collector steps verbatim; the Environment/permission
    distinction ("not a device fault") is carried by the gaps table, not by prose here.
    """
    collection = [c for c in report.get("collection", []) if isinstance(c, dict)]
    failed = [
        c
        for c in collection
        if _bucket_of(c.get("status"), _COLLECTION_STATUS_BUCKET) not in {"passed", "warning"}
    ]
    incomplete_status = assessment.get("status") == "incomplete"
    if not failed and not incomplete_status:
        return ""

    lines = [
        f"{c.get('name') or 'unnamed'}: {c.get('status') or 'unknown status'}"
        for c in failed
    ]
    if incomplete_status:
        lines.append("assessment status: incomplete")
    if not collection:
        lines.append("no collection steps recorded")
    items = "".join(f"<li>{esc(line)}</li>" for line in lines)
    return (
        "<section class='panel banner-incomplete' role='alert'>"
        "<h2>Incomplete collection — affected areas are inconclusive</h2>"
        f"<ul class='gap-list'>{items}</ul>"
        "<p class='muted'>Not a device fault until a check ran and returned a negative "
        "result. Fix the toolchain/permissions and rerun.</p></section>"
    )


_VOID_TAGS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)


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
    except (
        AssertionError,
        ValueError,
        TypeError,
    ) as exc:  # pragma: no cover - html.parser is tolerant
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
                    errors.append(
                        f"dashboard count mismatch for {name}: "
                        f"HTML {rendered[name]} != JSON {expected[name]}"
                    )
            except (TypeError, ValueError):
                errors.append(f"dashboard count is not a number for {name}: {rendered[name]!r}")
        if "checks_performed" in rendered:
            try:
                if int(rendered["checks_performed"]) != int(expected["checks_performed"]):
                    errors.append(
                        "dashboard count mismatch for checks_performed: "
                        f"HTML {rendered['checks_performed']} != JSON {expected['checks_performed']}"
                    )
            except (TypeError, ValueError):
                errors.append("dashboard checks_performed is not a number")
        # A rendered zero must be a real zero, not a gap: the dashboard shows
        # "not collected" for those, and the attribute carries the true count.
    except (AttributeError, TypeError, ValueError) as exc:  # pragma: no cover - total function
        errors.append(f"dashboard counts could not be recomputed: {exc}")

    return errors


def _outcome_counts_table(report: dict[str, Any]) -> str:
    """The one table that summarizes how much was evaluated, and how it came out.

    Every count is recomputed here and carries its value in a `data-dash-*`
    attribute so `validate_report_html` can re-derive the same numbers from
    report.json at validation time. A run that evaluated nothing displays
    "not collected" instead of a row of zeroes — a zero would read as a result.
    """
    counts = dashboard_counts(report)
    performed = counts["checks_performed"]
    rows: list[list[Any]] = [[
        "checks performed",
        _Html(f"<b data-dash-key='checks_performed' data-dash-count='{esc(performed)}'>"
              f"{esc(performed if performed else NOT_COLLECTED)}</b>"),
    ]]
    for name in OUTCOME_BUCKETS:
        shown = counts[name] if performed else NOT_COLLECTED
        rows.append([
            name,
            _Html(f"<b data-dash-key='{esc(name)}' data-dash-count='{esc(counts[name])}'>"
                  f"{esc(shown)}</b>"),
        ])
    return _table(["Outcome", "Checks and collector steps"], rows, "")


def build_html(run_dir: Path, report: dict[str, Any], redact_identifiers: bool = False) -> None:
    """Render the brief HTML report (v5.2 presentation, v5.0.0 JSON unchanged).

    The reader is assumed to be a professional who knows what a cycle count, a
    provisioning profile or a panic string is. The report is therefore a dense
    table-first document: the verdict, the count summary, every non-INFO finding,
    the raw identity/configuration facts, the measured hardware numbers with their
    non-pass checks and integrity assessment, and the collector gaps of this run.
    Explanatory prose, per-section disclaimers, charts and project-level capability
    tables are gone; report.json remains the complete record.
    """
    device = report.get("device", {}) if isinstance(report.get("device"), dict) else {}
    identity_fields = [
        "DeviceName",
        "ProductType",
        "ProductVersion",
        "BuildVersion",
        "ModelNumber",
        "HardwareModel",
        "SerialNumber",
        "InternationalMobileEquipmentIdentity",
        "BoardId",
        "UniqueDeviceID",
        "UDID",
        "ActivationState",
        "CarrierBundleVersion",
        "BasebandVersion",
        "DeviceColor",
        "TimeZone",
        "TotalDiskCapacity",
        "TotalDataCapacity",
    ]
    sensitive_keys = {
        "SerialNumber",
        "InternationalMobileEquipmentIdentity",
        "UniqueDeviceID",
        "UDID",
        "WiFiAddress",
        "BluetoothAddress",
    }
    identity_rows = [
        [
            key,
            _redact_identifier(device.get(key))
            if redact_identifiers and key in sensitive_keys
            else device.get(key),
        ]
        for key in identity_fields
        if device.get(key) is not None
    ]
    for capacity_key in ("TotalDiskCapacity", "TotalDataCapacity"):
        value = device.get(capacity_key)
        try:
            capacity_bytes = int(value)
            identity_rows.append(
                [f"{capacity_key} (decimal GB, derived)", f"{capacity_bytes / 1_000_000_000:.2f} GB"]
            )
        except (TypeError, ValueError):
            pass

    # Read-only provenance signals, raw values only.
    provenance = report.get("provenance")
    if isinstance(provenance, dict) and provenance:
        for key, label in (
            ("activation_state", "Activation state (host query)"),
            ("mounted_images", "DeveloperDiskImage mounted"),
            ("developer_mode", "Developer Mode"),
            ("companion_devices", "Paired companion devices"),
        ):
            entry = provenance.get(key)
            if isinstance(entry, dict) and entry.get("value"):
                identity_rows.append([label, entry["value"]])

    if report.get("comparison"):
        comparison_rows = [
            [item.get("field"), item.get("previous"), item.get("current"), item.get("status")]
            for item in report["comparison"].get("changes", [])
        ]
    else:
        comparison_rows = []

    findings = [
        f for f in report.get("findings", []) or [] if isinstance(f, dict)
    ]
    brief_findings = [
        f for f in findings if str(f.get("severity", "")).strip().upper() != "INFO"
    ]
    info_count = len(findings) - len(brief_findings)
    finding_rows = [
        [
            f.get("severity", "INFO"),
            f.get("title", ""),
            _epistemic_badge(f),
            f.get("detail", ""),
            ", ".join(str(path) for path in (f.get("evidence") or [])),
        ]
        for f in brief_findings
    ]

    severity = _severity_counts(report)
    non_pass_checks = []
    metrics = _measured_metrics(report)
    hardware = report.get("hardware_assessment") if isinstance(report.get("hardware_assessment"), dict) else {}
    for check in hardware.get("checks", []) or []:
        if isinstance(check, dict) and _bucket_of(check.get("status"), _HARDWARE_STATUS_BUCKET) != "passed":
            unit = str(check.get("measurement_unit") or "").strip()
            raw = check.get("measurement")
            value = MISSING if raw is None else (
                f"{raw:g}{' ' + unit if unit else ''}" if isinstance(raw, (int, float))
                else str(raw)
            )
            non_pass_checks.append(
                [
                    check.get("subsystem", ""),
                    check.get("question", ""),
                    check.get("status", ""),
                    value,
                    check.get("confidence", ""),
                ]
            )

    integrity = report.get("integrity_assessment") if isinstance(report.get("integrity_assessment"), dict) else {}
    integrity_data = bool(
        integrity.get("classifications") or integrity.get("changes") or integrity.get("overall")
    )
    if integrity_data:
        class_rows = [
            [field_name, status]
            for field_name, status in (integrity.get("classifications") or {}).items()
        ]
        change_rows = [
            [
                ch.get("field", ""),
                ch.get("previous", ""),
                ch.get("current", ""),
                ch.get("classification", ch.get("status", "")),
            ]
            for ch in integrity.get("changes", [])
        ]
    else:
        class_rows = change_rows = []

    collection = [c for c in report.get("collection", []) if isinstance(c, dict)]
    gap_rows = [
        [
            c.get("name", ""),
            c.get("status", ""),
            _gap_outcome(c.get("status")),
            _val(c.get("returncode")),
            _val(c.get("duration_seconds")),
        ]
        for c in collection
        if _bucket_of(c.get("status"), _COLLECTION_STATUS_BUCKET) not in {"passed", "warning"}
    ]

    assessment = report.get("assessment", {}) if isinstance(report.get("assessment"), dict) else {}
    incomplete_banner = _partial_collection_banner(report, assessment)
    counts = dashboard_counts(report)
    total_checks = counts["checks_performed"]
    severity_class = (
        "high"
        if assessment.get("status") == "high_risk"
        else "warn"
        if assessment.get("status") in {"incomplete", "review"}
        else "neutral"
    )
    # A partial run must never be styled or worded like a healthy one.
    if incomplete_banner and severity_class == "neutral":
        severity_class = "warn"

    # --- section construction ------------------------------------------------
    summary_rows = [
        ["assessment status", _val(assessment.get("status"))],
        [
            "collectors completed",
            _ratio(assessment.get("collection_successful"), assessment.get("collection_total")),
        ],
        ["collector gaps", _val(assessment.get("collection_failed_or_partial"))],
        [
            "identity fields",
            _ratio(
                assessment.get("identity_fields_present"),
                assessment.get("identity_fields_expected"),
            ),
        ],
    ]
    severity_summary = " · ".join(
        f"{name} {severity.get(name, 0)}" for name in ("BLOCKER", "WARNING", "REVIEW", "INFO")
    )

    if brief_findings:
        findings_body = _table(
            ["Severity", "Finding", "How established", "Detail", "Evidence"],
            finding_rows,
            "",
        )
    else:
        verdict_shown = (
            f"<p class='muted'>no findings recorded from {esc(total_checks if total_checks else NOT_COLLECTED)} "
            "evaluated checks — not a certification.</p>"
            if total_checks
            else f"<p class='muted'>checks: {NOT_COLLECTED}</p>"
        )
        findings_body = verdict_shown

    char_rows = [
        [subsystem, item, value] for subsystem, item, value in metrics
    ]
    hardware_parts: list[str] = []
    if char_rows:
        hardware_parts.append(
            _table(["Subsystem", "Item", "Measured value"], char_rows, "")
        )
    if non_pass_checks:
        hardware_parts.append(
            _table(
                ["Subsystem", "Item", "Status", "Value", "Confidence"],
                non_pass_checks,
                "",
            )
        )
    if hardware_parts:
        hardware_parts.append(
            f"<p class='muted'>Battery/storage: "
            f"<b>{esc('measured above' if char_rows else NOT_COLLECTED)}</b>."
            + (" Cycle counts are tool-reported candidates." if char_rows else "")
            + "</p>"
        )
    elif not integrity_data:
        hardware_parts.append(f"<p class='muted'>hardware and battery: {esc(NOT_COLLECTED)}.</p>")
    if integrity_data:
        hardware_parts.append(
            "<p class='muted'>integrity: "
            "<b>" + esc(integrity.get("overall", "inconclusive")) + "</b></p>"
            + _table(
                ["Field", "Classification"],
                class_rows,
                "No classifications",
            )
            + _table(
                ["Changed field", "Previous", "Current", "Classification"],
                change_rows,
                "No changes between snapshots",
            )
        )

    if gap_rows:
        gaps_body = _table(
            ["Collector", "Status", "Outcome", "Exit code", "Seconds"],
            gap_rows,
            "",
        )
    else:
        done = len(collection)
        gaps_body = (
            f"<p class='muted'>no collection steps recorded</p>"
            if not done
            else f"<p class='muted'>all {esc(done)} collector steps produced usable evidence "
            "— absence of findings is not certification.</p>"
        )

    redaction_note = (
        "  <p class='muted'>Identifiers masked in this HTML export; report.json keeps the values.</p>"
        if redact_identifiers
        else ""
    )
    comparison_block = (
        _table(
            ["Field", "Previous", "Current", "Assessment"],
            comparison_rows,
            "No changes detected",
        )
        if comparison_rows
        else f"<p class='muted'>comparison: not collected</p>"
    )

    html_doc = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>iPhone Inspection — {esc(assessment.get("verdict", "INCOMPLETE"))}</title>
<style>
:root{{
  --bg:#eef1f6;--panel:#fff;--ink:#131b26;--muted:#5b6674;--line:#d7dee6;--accent:#1f4f9c;
  --accent-soft:#e8f0fb;--high:#8f2020;--warn:#7d5100;--good:#14603a;
}}
@media (prefers-color-scheme:dark){{:root{{
  --bg:#0e1319;--panel:#161d26;--ink:#e6ecf3;--muted:#9aa7b6;--line:#2a3542;--accent:#7fb0f5;
  --accent-soft:#17263a;--high:#f08a8a;--warn:#e0b25e;--good:#6cd39a;}}}}
@media (prefers-reduced-motion:reduce){{*{{animation-duration:.01ms !important;transition-duration:.01ms !important;scroll-behavior:auto !important}}}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}}
main{{max-width:960px;margin:0 auto;padding:24px 18px 48px}}
h1{{font-size:1.6rem;margin:.2em 0 .3em;letter-spacing:-.02em}}
h2{{font-size:1.15rem;margin:0 0 10px;letter-spacing:-.01em}}
.panel{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px 18px;margin:14px 0}}
.panel>h2:first-child{{margin-top:0}}
.muted{{color:var(--muted)}}
.verdict{{padding:10px 14px;border-radius:9px;font-weight:700;font-size:1.05rem;margin-bottom:8px}}
.verdict.high{{background:#fce8e8;color:var(--high)}}
.verdict.warn{{background:#fff3d9;color:var(--warn)}}
.verdict.neutral{{background:#e8f5ee;color:var(--good)}}
@media (prefers-color-scheme:dark){{.verdict.high{{background:#3a1c1c}}.verdict.warn{{background:#382c14}}.verdict.neutral{{background:#16301f}}}}
.banner-incomplete{{border:2px solid var(--high);background:#fdeaea}}
.banner-incomplete h2{{color:var(--high)}}
.gap-list{{margin:6px 0;padding-left:20px}}
.banner-incomplete li{{margin:3px 0}}
.table-wrap{{width:100%;overflow-x:auto}}
table{{width:100%;border-collapse:collapse;font-size:.9rem}}
th,td{{text-align:left;vertical-align:top;padding:7px 10px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}}
th{{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}}
tbody tr:last-child td{{border-bottom:none}}
footer{{margin-top:24px;padding-top:12px;border-top:1px solid var(--line);color:var(--muted);font-size:.85rem}}
@media print{{
  :root{{--bg:#fff;--panel:#fff;--ink:#000;--muted:#333;--line:#bbb}}
  body{{background:#fff;font-size:10pt}}
  main{{max-width:none;padding:0}}
  .panel{{border:1px solid #ccc;padding:10px;margin:8px 0;break-inside:avoid}}
  th{{background:#eee;-webkit-print-color-adjust:exact;print-color-adjust:exact}}
}}
</style></head><body><main>
<header><h1>iPhone Inspection</h1><p class="muted">Started {esc(report.get("started_at"))} · Finished {esc(report.get("finished_at"))}</p></header>
{incomplete_banner}
<section class="panel hero"><h2>1. Summary</h2>
<div class="verdict {severity_class}">{esc(assessment.get("verdict", "INCOMPLETE — NO ASSESSMENT"))}</div>
{_outcome_counts_table(report)}
<h3>Outcome and completeness</h3>{_table(["Field", "Value"], summary_rows, "No assessment recorded.")}
<p class="muted">findings: {esc(severity_summary)}</p></section>
<section class="panel"><h2>2. Findings</h2>{findings_body}{f"<p class='muted'>INFO findings: {info_count} — details in report.json.</p>" if info_count else ""}</section>
<section class="panel"><h2>3. Device identity and configuration</h2>{_table(["Field", "Reported value"], identity_rows, f"device identity: {NOT_COLLECTED}")}{redaction_note}
<h3>Change since the previous inspection</h3>{comparison_block}</section>
<section class="panel"><h2>4. Hardware, battery and integrity</h2>{"".join(hardware_parts)}</section>
<section class="panel"><h2>5. Collection gaps</h2>{gaps_body}</section>
<footer>iPhone Forensics v{esc(report.get("version"))} · Generated locally · report.json is the evidence of record.
Labels: Verified = read from evidence · Inferred = reasoned · Unknown = open question · Manual check required = a person must look.
Not collected &ne; fine · failed &ne; unavailable · no authenticity / replacement / health verdicts.</footer>
</main></body></html>"""
    # Re-parse what was rendered and note the verdict as a comment. Validation must
    # never block report generation, so a validator failure is reported, not raised.
    issues = validate_report_html(html_doc, report)
    summary = "clean" if not issues else f"{len(issues)} issues"
    html_doc = html_doc.replace("</main>", f"<!-- report-validation: {summary} -->\n</main>", 1)
    for issue in issues[:5]:
        print(f"[report] HTML validation: {issue}", file=sys.stderr)
    (run_dir / "report.html").write_text(html_doc, encoding="utf-8")


def finalize(run_dir: Path, report: dict[str, Any], redact_identifiers: bool = False) -> None:
    report["finished_at"] = (
        report.get("finished_at")
        or __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
    )
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
