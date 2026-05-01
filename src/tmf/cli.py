"""Command-line entry point for tmf.

    tmf render path/to/model.yaml --out OUTPUT.md
    tmf lint path/to/model.yaml
    tmf ids path/to/model.yaml
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from tmf.ids import validate_mitre_ids
from tmf.model import ThreatModel
from tmf.render import render_markdown


def _load(path: str) -> ThreatModel:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return ThreatModel.from_dict(data or {})


def cmd_render(args: argparse.Namespace) -> int:
    model = _load(args.input)
    errs = model.validate()
    if errs:
        for e in errs:
            print(f"error: {e}", file=sys.stderr)
        return 1

    out = render_markdown(model)
    if args.out:
        Path(args.out).write_text(out, encoding="utf-8")
        print(
            f"Loaded threat model: {model.title} ({len(model.threats)} threats)",
            file=sys.stderr,
        )
        print(f"Rendered to {args.out}", file=sys.stderr)
    else:
        print(out)
    return 0


def cmd_lint(args: argparse.Namespace) -> int:
    model = _load(args.input)
    errs = model.validate()
    if not errs:
        print("ok")
        return 0
    for e in errs:
        print(e, file=sys.stderr)
    return 1


def cmd_ids(args: argparse.Namespace) -> int:
    model = _load(args.input)
    errs = validate_mitre_ids(model)
    if not errs:
        print(f"ok — {sum(len(t.mitre) for t in model.threats)} MITRE IDs validated")
        return 0
    for e in errs:
        print(e, file=sys.stderr)
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="tmf")
    sub = p.add_subparsers(dest="cmd", required=True)

    p_r = sub.add_parser("render", help="Render YAML threat model to Markdown.")
    p_r.add_argument("input")
    p_r.add_argument("--out", default=None)
    p_r.set_defaults(func=cmd_render)

    p_l = sub.add_parser("lint", help="Validate YAML schema + required fields.")
    p_l.add_argument("input")
    p_l.set_defaults(func=cmd_lint)

    p_i = sub.add_parser("ids", help="Validate MITRE ATT&CK technique IDs.")
    p_i.add_argument("input")
    p_i.set_defaults(func=cmd_ids)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
