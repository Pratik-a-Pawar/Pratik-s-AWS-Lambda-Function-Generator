"""Command-line entry point for lfg."""

import argparse
import sys
from pathlib import Path

from lfg import __version__
from lfg.spec import SpecLoadError, load_spec, validate_spec


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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lfg")
    parser.add_argument("--version", action="version", version=f"lfg {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("validate-spec", help="validate a function.spec.yaml")
    p.add_argument("function_dir")
    p.set_defaults(func=_validate_spec)
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        args = _build_parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
