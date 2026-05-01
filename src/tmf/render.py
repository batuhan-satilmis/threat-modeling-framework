"""Markdown risk-register renderer."""

from __future__ import annotations

from collections import defaultdict

from tmf.model import Threat, ThreatModel

_STRIDE_LABELS = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information_disclosure": "Information Disclosure",
    "denial_of_service": "Denial of Service",
    "elevation_of_privilege": "Elevation of Privilege",
}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

_SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "ℹ️",
}


def render_markdown(model: ThreatModel) -> str:
    lines: list[str] = []
    lines.append(f"# Threat Model — {model.title}")
    lines.append("")
    if model.scope:
        lines.append("## Scope")
        lines.append("")
        lines.append(model.scope)
        lines.append("")

    if model.trust_boundaries:
        lines.append("## Trust boundaries")
        lines.append("")
        lines.append("| ID | Crosses | Trust |")
        lines.append("|---|---|---|")
        for tb in model.trust_boundaries:
            lines.append(f"| {tb.id} | {tb.crosses} | {tb.trust} |")
        lines.append("")

    # Risk register summary
    by_severity = defaultdict(int)
    for t in model.threats:
        by_severity[t.severity] += 1
    lines.append("## Risk register summary")
    lines.append("")
    for sev in ("critical", "high", "medium", "low", "info"):
        if by_severity[sev]:
            lines.append(f"- {_SEVERITY_EMOJI[sev]} **{sev.title()}**: {by_severity[sev]}")
    lines.append("")

    # Group threats by STRIDE category, then sort by severity then ID
    by_stride: dict[str, list[Threat]] = defaultdict(list)
    for t in model.threats:
        by_stride[t.stride].append(t)

    lines.append("## Threats")
    lines.append("")
    for stride_key, label in _STRIDE_LABELS.items():
        threats = by_stride.get(stride_key, [])
        if not threats:
            continue
        threats.sort(key=lambda t: (_SEVERITY_ORDER.get(t.severity, 99), t.id))
        lines.append(f"### {label}")
        lines.append("")
        lines.append("| # | Severity | Title | Mitigation | Status | MITRE |")
        lines.append("|---|---|---|---|---|---|")
        for t in threats:
            mitre = ", ".join(t.mitre) if t.mitre else ""
            mitigation = t.mitigation.replace("\n", " ").strip()
            lines.append(
                f"| {t.id} | {_SEVERITY_EMOJI.get(t.severity, '')} {t.severity.title()} "
                f"| {t.title} | {mitigation} | {t.status} | {mitre} |"
            )
        lines.append("")

    return "\n".join(lines)
