"""MITRE ATT&CK technique-ID validator.

Loose validation: technique IDs match T#### or T####.### sub-techniques.
We don't require a network call to MITRE; the ID format itself is enough
to catch typos.
"""

from __future__ import annotations

import re

from tmf.model import ThreatModel

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


def validate_mitre_ids(model: ThreatModel) -> list[str]:
    errs: list[str] = []
    for t in model.threats:
        for tid in t.mitre:
            if not _TECHNIQUE_RE.match(tid):
                errs.append(
                    f"{t.id}: '{tid}' does not look like a MITRE ATT&CK ID "
                    "(expected T#### or T####.###)"
                )
    return errs
