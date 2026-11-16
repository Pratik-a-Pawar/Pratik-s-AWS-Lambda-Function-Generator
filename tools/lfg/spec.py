"""Load and validate function specs against the JSON Schema."""

import datetime
import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator

from lfg.yaml_util import UniqueKeyLoader

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "function-spec.schema.json"


class SpecLoadError(Exception):
    """The spec file is missing, is not valid YAML, or is not a mapping."""


@dataclass(frozen=True)
class SpecError:
    path: str
    message: str


def _iso_dates(node):
    """Convert YAML date/datetime scalars to ISO-8601 strings."""
    if isinstance(node, (datetime.date, datetime.datetime)):
        return node.isoformat()
    if isinstance(node, dict):
        return {key: _iso_dates(value) for key, value in node.items()}
    if isinstance(node, list):
        return [_iso_dates(item) for item in node]
    return node


def load_spec(path: Path) -> dict:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise SpecLoadError(f"cannot read {path}: {getattr(exc, 'strerror', None) or exc}") from exc
    try:
        data = yaml.load(text, Loader=UniqueKeyLoader)
    except (RecursionError, MemoryError):
        raise SpecLoadError(f"{path} is nested too deeply to read") from None
    except (yaml.YAMLError, ValueError) as exc:
        raise SpecLoadError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise SpecLoadError(f"{path}: top level must be a mapping")
    try:
        return _iso_dates(data)
    except RecursionError:
        raise SpecLoadError(f"{path} is nested too deeply to read") from None


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
