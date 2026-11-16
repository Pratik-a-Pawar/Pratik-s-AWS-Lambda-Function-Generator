"""Run a lab's acceptance checks, as listed in labs/manifest.yaml."""

import os
import subprocess
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

import yaml

from lfg.yaml_util import UniqueKeyLoader

MANIFEST = Path("labs") / "manifest.yaml"


class ManifestError(ValueError):
    """labs/manifest.yaml is missing or malformed."""


def _no_control_characters(value: str, lab: str, key: str) -> None:
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value):
        raise ManifestError(f"{MANIFEST}: lab {lab!r} {key!r} has a control character")


def _string_list(entry: dict, key: str, lab: str) -> list[str]:
    value = entry.get(key)
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ManifestError(f"{MANIFEST}: lab {lab!r} needs a list of strings for {key!r}")
    for item in value:
        _no_control_characters(item, lab, key)
    return value


def _relative_path(value: object, lab: str, key: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestError(f"{MANIFEST}: lab {lab!r} {key!r} needs non-empty strings")
    _no_control_characters(value, lab, key)
    if _escapes_root(value):
        raise ManifestError(f"{MANIFEST}: lab {lab!r} {key!r} path escapes the repository: {value}")
    return value


def load_manifest(root: Path) -> dict:
    """Return the manifest's `labs` mapping, keyed by lab number."""
    path = root / MANIFEST
    try:
        with path.open(encoding="utf-8") as handle:
            data = yaml.load(handle, Loader=UniqueKeyLoader)
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ManifestError(f"cannot read {path}: {' '.join(str(exc).split())}") from exc
    labs = data.get("labs") if isinstance(data, dict) else None
    if not isinstance(labs, dict):
        raise ManifestError(f"{MANIFEST}: top level must be a mapping with a 'labs' mapping")
    for lab, entry in labs.items():
        if not isinstance(lab, str) or not isinstance(entry, dict):
            raise ManifestError(f"{MANIFEST}: lab {lab!r} must be a quoted number with a mapping")
        if not isinstance(entry.get("title"), str):
            raise ManifestError(f"{MANIFEST}: lab {lab!r} needs a string 'title'")
        _string_list(entry, "checks", lab)
        _relative_path(entry.get("dir"), lab, "dir")
        for owned in _string_list(entry, "owned", lab):
            _relative_path(owned, lab, "owned")
    return labs


def _escapes_root(path: str) -> bool:
    posix, windows = PurePosixPath(path), PureWindowsPath(path)
    return posix.is_absolute() or windows.is_absolute() or ".." in posix.parts + windows.parts


def run(lab: str, root: Path, extra_args: list[str] | None = None) -> int:
    """Run pytest on the lab's checks: pytest's exit code, or 2 for unusable input."""
    try:
        labs = load_manifest(root)
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if lab not in labs:
        print(f"error: unknown lab {lab!r}; try 'lfg labcheck --list'", file=sys.stderr)
        return 2
    checks = labs[lab]["checks"]
    if not checks:
        print(f"Lab {lab} has no checks yet")
        return 0
    resolved_root = root.resolve()
    paths = []
    for check in checks:
        try:
            path = (root / check).resolve()
            usable = path.is_file() and path.is_relative_to(resolved_root)
        except (ValueError, OSError):
            usable = False
        if check.startswith("-") or _escapes_root(check) or not usable:
            print(f"error: lab {lab!r} check {check!r} is not a file in the repository",
                  file=sys.stderr)
            return 2
        paths.append(str(path))
    env = {k: v for k, v in os.environ.items() if k not in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS")}
    command = [sys.executable, "-m", "pytest", *paths, *(extra_args or [])]
    code = subprocess.run(command, cwd=root, env=env, check=False).returncode
    if code in (0, 1):
        return code
    if code == 5:
        print("error: no tests were collected", file=sys.stderr)
        return 1
    print(f"error: pytest could not run the checks (exit code {code})", file=sys.stderr)
    return 2
