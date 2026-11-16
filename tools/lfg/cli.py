"""Command-line entry point for lfg."""

import argparse
import dataclasses
import datetime
import json
import re
import sys
from pathlib import Path

from lfg import __version__
from lfg.cfn_yaml import TemplateLoadError, load_template
from lfg.policy import Violation, blocking, check
from lfg.spec import SpecLoadError, load_spec, validate_spec

_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _validate_spec(args: argparse.Namespace) -> int:
    spec_path = Path(args.function_dir) / "function.spec.yaml"
    try:
        spec = load_spec(spec_path)
    except SpecLoadError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    errors = validate_spec(spec)
    if errors:
        for error in errors:
            print(f"{error.path}: {error.message}")
        return 1
    print(f"OK: {spec['name']}")
    return 0


def _fail(message: str) -> int:
    print(f"error: {' '.join(message.split())}", file=sys.stderr)
    return 2


def _line(v: Violation) -> str:
    suffix = f" [ACCEPTED until {v.accepted_until}]" if v.accepted else ""
    return f"{v.rule_id}  {v.location}  {v.message}{suffix}"


def _policy_check(args: argparse.Namespace) -> int:
    today = datetime.datetime.now(datetime.UTC).date()
    if args.today is not None:
        try:
            if not _DATE.fullmatch(args.today):
                raise ValueError
            today = datetime.date.fromisoformat(args.today)
        except ValueError:
            return _fail(f"--today must be a date written YYYY-MM-DD, not {args.today!r}")
    directory = Path(args.function_dir)
    try:
        spec = load_spec(directory / "function.spec.yaml")
        errors = validate_spec(spec)
        if errors:
            for error in errors:
                print(f"{error.path}: {error.message}")
            return 1
        template = load_template(directory / "template.yaml")
    except (SpecLoadError, TemplateLoadError) as exc:
        return _fail(str(exc))
    violations = check(spec, template, directory / "src", today)
    count = len(blocking(violations))
    if args.format == "json":
        print(json.dumps({
            "function": spec["name"],
            "blocking": count,
            "violations": [dataclasses.asdict(v) for v in violations],
        }, indent=2))
    else:
        for violation in violations:
            print(_line(violation))
        print(f"BLOCKED: {count} violation(s)" if count else f"OK: {spec['name']} (0 violations)")
    return 1 if count else 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lfg")
    parser.add_argument("--version", action="version", version=f"lfg {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("validate-spec", help="validate a function.spec.yaml")
    p.add_argument("function_dir")
    p.set_defaults(func=_validate_spec)
    p = sub.add_parser("policy-check", help="check a function against the policy rules")
    p.add_argument("function_dir")
    p.add_argument("--today", help="date for expiring acceptances, YYYY-MM-DD (default: today)")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.set_defaults(func=_policy_check)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _build_parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
