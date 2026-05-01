"""End-to-end test: render the example payment-flow YAML."""

from __future__ import annotations

from pathlib import Path

import yaml

from tmf.model import ThreatModel
from tmf.render import render_markdown
from tmf.ids import validate_mitre_ids


EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "saas-payment-flow.yaml"


def test_example_loads_and_validates():
    data = yaml.safe_load(EXAMPLE.read_text())
    model = ThreatModel.from_dict(data)
    assert model.title == "SaaS Payment Flow"
    assert len(model.threats) == 12
    assert model.validate() == []


def test_example_renders():
    data = yaml.safe_load(EXAMPLE.read_text())
    model = ThreatModel.from_dict(data)
    out = render_markdown(model)
    assert "Threat Model — SaaS Payment Flow" in out
    assert "Spoofing" in out
    assert "T-001" in out
    assert "T1190" in out  # MITRE ID rendered through


def test_mitre_ids_validate():
    data = yaml.safe_load(EXAMPLE.read_text())
    model = ThreatModel.from_dict(data)
    assert validate_mitre_ids(model) == []
