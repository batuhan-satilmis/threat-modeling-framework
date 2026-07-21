"""End-to-end tests against the example payment-flow YAML.

These exercise the parse → validate → MITRE-lint → render pipeline. New
threats added to the example must keep all four steps green.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from tmf.model import ThreatModel
from tmf.render import render_markdown
from tmf.ids import validate_mitre_ids


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "saas-payment-flow.yaml"


def _load_model() -> ThreatModel:
    data = yaml.safe_load(EXAMPLE.read_text())
    return ThreatModel.from_dict(data)


def test_example_loads_and_validates():
    model = _load_model()
    assert model.title == "SaaS Payment Flow"
    assert len(model.threats) == 16
    assert model.validate() == []


def test_example_renders():
    model = _load_model()
    out = render_markdown(model)
    assert "Threat Model — SaaS Payment Flow" in out
    assert "Spoofing" in out
    assert "T-001" in out
    assert "T1190" in out  # MITRE ID rendered through


def test_mitre_ids_validate():
    model = _load_model()
    assert validate_mitre_ids(model) == []


def test_no_duplicate_threat_ids():
    model = _load_model()
    ids = [t.id for t in model.threats]
    assert len(ids) == len(set(ids)), f"duplicate threat IDs: {sorted(ids)}"


def test_card_testing_threat_present_and_high_severity():
    """T-013: card-testing abuse is the kind of fraud-economics threat that's
    easy to leave out of a STRIDE walkthrough — it doesn't fit cleanly under
    spoofing or DoS, and Stripe handles a lot of it for you. The example keeps
    it explicitly so reviewers see it called out."""
    model = _load_model()
    t013 = next((t for t in model.threats if t.id == "T-013"), None)
    assert t013 is not None
    assert t013.stride == "denial_of_service"
    assert t013.severity == "high"
    assert "T1499" in t013.mitre
    assert "card-testing" in t013.title.lower() or "card-test" in t013.title.lower()


def test_webhook_timestamp_replay_threat_distinct_from_cross_tenant_replay():
    """T-014 (temporal replay within tolerance) is distinct from T-008
    (cross-tenant replay). Both should remain in the model."""
    model = _load_model()
    ids = {t.id for t in model.threats}
    assert {"T-008", "T-014"}.issubset(ids)
    t014 = next(t for t in model.threats if t.id == "T-014")
    assert t014.stride == "tampering"
    assert "tolerance" in t014.description.lower()


def test_coupon_redemption_race_is_tampering():
    """T-015: classic check-then-act race. STRIDE classification = tampering
    (manipulating redemption-ledger state)."""
    model = _load_model()
    t015 = next((t for t in model.threats if t.id == "T-015"), None)
    assert t015 is not None
    assert t015.stride == "tampering"
    # Mitigation must mention the canonical fix (UNIQUE constraint / ON CONFLICT).
    assert "UNIQUE" in t015.mitigation or "ON CONFLICT" in t015.mitigation


def test_rendered_md_lists_every_threat():
    """The Markdown risk-register should reference every threat ID."""
    model = _load_model()
    out = render_markdown(model)
    for t in model.threats:
        assert t.id in out, f"{t.id} missing from rendered output"


def test_summary_counts_match_threats():
    """The 'Risk register summary' totals should equal the actual threat counts."""
    model = _load_model()
    out = render_markdown(model)
    # Count severities in the source data
    counts: dict[str, int] = {}
    for t in model.threats:
        counts[t.severity] = counts.get(t.severity, 0) + 1
    # Verify each appears in the summary block
    summary_block = out.split("## Risk register summary", 1)[1].split("##", 1)[0]
    for sev, n in counts.items():
        assert f"**{sev.title()}**: {n}" in summary_block, (
            f"summary missing {sev}={n}; got:\n{summary_block}"
        )


def test_portal_session_bearer_url_threat_present():
    """T-016: the Stripe billing-portal session URL is a bearer token. The
    common leak surfaces (Referer, JSON body echo, access logs, support-desk
    paste) map cleanly to elevation_of_privilege — anyone who obtains the URL
    can act on the customer's billing without authenticating to our app.
    Distinct from T-002 (customer-ID spoof, server-side) and T-008 (webhook
    replay across tenants, server-to-server)."""
    model = _load_model()
    t016 = next((t for t in model.threats if t.id == "T-016"), None)
    assert t016 is not None
    assert t016.stride == "elevation_of_privilege"
    assert t016.severity == "high"
    # Description must call out at least one concrete leak path.
    desc = t016.description.lower()
    assert "referer" in desc or "referrer" in desc or "json body" in desc
    # Mitigation must name the two structural fixes (302 redirect + referrer policy).
    mit = t016.mitigation.lower()
    assert "302" in mit or "redirect" in mit
    assert "referrer-policy" in mit or "referrer policy" in mit or "no-referrer" in mit
    # MITRE tag must include T1539 (Steal Web Session Cookie), the closest
    # ATT&CK technique for a URL that behaves like a session token.
    assert "T1539" in t016.mitre
