"""Load and validate function specs against the JSON Schema."""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "function-spec.schema.json"


class SpecLoadError(Exception):
    """The spec file is missing, is not valid YAML, or is not a mapping."""


@dataclass(frozen=True)
class SpecError:
    path: str
    message: str


def load_spec(path: Path) -> dict:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise SpecLoadError(f"cannot read {path}: {exc.strerror or exc}") from exc
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecLoadError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecLoadError(f"{path}: top level must be a mapping")
    return data


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def _dotted(parts) -> str:
    out = ""
    for part in parts:
        if isinstance(part, int):
            out += f"[{part}]"
        else:
            out += f".{part}" if out else str(part)
    return out or "(root)"


def validate_spec(spec: dict) -> list[SpecError]:
    errors = [SpecError(_dotted(e.absolute_path), e.message) for e in _validator().iter_errors(spec)]
    return sorted(errors, key=lambda e: e.path)
