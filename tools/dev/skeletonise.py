"""Generate the learner branch: replace each lab's owned files with their skeletons.

Run once by the maintainer, from a clean checkout of the reference solutions.
"""

import shutil
import sys
from pathlib import Path, PurePosixPath, PureWindowsPath

import yaml

_MANIFEST = Path("labs") / "manifest.yaml"


def _load_labs(root: Path) -> dict:
    # Imported lazily so the script also runs where lfg is installed only as a path.
    from lfg.yaml_util import UniqueKeyLoader

    with (root / _MANIFEST).open(encoding="utf-8") as handle:
        data = yaml.load(handle, Loader=UniqueKeyLoader)
    return data["labs"]


def _checked(path: str) -> str:
    posix, windows = PurePosixPath(path), PureWindowsPath(path)
    if posix.is_absolute() or windows.is_absolute() or ".." in posix.parts + windows.parts:
        raise ValueError(f"owned path escapes the repository: {path}")
    return path


def apply(root: Path) -> list[Path]:
    """Copy <dir>/skeleton/<path> over <path> for every owned file; delete the skeletons.

    Validates every lab before changing anything, so a failure leaves the tree untouched.
    """
    plan: list[tuple[Path, Path]] = []
    skeleton_dirs: list[Path] = []
    for lab in _load_labs(root).values():
        skeleton_dir = root / _checked(lab["dir"]) / "skeleton"
        skeleton_dirs.append(skeleton_dir)
        for owned in lab["owned"]:
            source = skeleton_dir / _checked(owned)
            if not source.is_file():
                raise FileNotFoundError(f"no skeleton for owned file {owned}: expected {source}")
            plan.append((source, root / owned))
    replaced = []
    for source, target in plan:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        replaced.append(target)
    for skeleton_dir in skeleton_dirs:
        shutil.rmtree(skeleton_dir, ignore_errors=True)
    return replaced


if __name__ == "__main__":
    repo = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repo / "tools"))
    for changed in apply(repo):
        print(changed.relative_to(repo))
