"""Generate the learner branch: replace each lab's owned files with their skeletons.

Run once by the maintainer, with the project virtualenv, from a clean checkout of the
reference solutions.
"""

import shutil
import sys
from pathlib import Path

from lfg.labcheck import ManifestError, load_manifest


def _inside(path: Path, root: Path) -> bool:
    return path.resolve().is_relative_to(root)



def _plan(root: Path) -> tuple[list[tuple[Path, Path]], list[Path]]:
    """Check every lab and return (copies, skeleton directories), changing nothing."""
    resolved_root = root.resolve()
    copies: list[tuple[Path, Path]] = []
    skeleton_dirs: list[Path] = []
    for lab in load_manifest(root).values():
        lab_dir = root / lab["dir"]
        skeleton_dir = lab_dir / "skeleton"
        for directory in (lab_dir, skeleton_dir):
            if directory.is_symlink() or not _inside(directory, resolved_root):
                raise ValueError(f"lab directory is a symlink or escapes the repository: {directory}")
        if skeleton_dir.exists():
            skeleton_dirs.append(skeleton_dir)
        for owned in lab["owned"]:
            source = skeleton_dir / owned
            target = root / owned
            if source.is_symlink() or not _inside(source, resolved_root):
                raise ValueError(f"skeleton is a symlink or escapes the repository: {source}")
            if not source.is_file():
                raise FileNotFoundError(f"no skeleton for owned file {owned}: expected {source}")
            if target.is_symlink() or not _inside(target, resolved_root):
                raise ValueError(f"owned path is a symlink or escapes the repository: {owned}")
            if target.is_dir():
                raise ValueError(f"owned path is a directory: {owned}")
            for parent in target.parents:
                if parent == root:
                    break
                if parent.exists() and not parent.is_dir():
                    raise ValueError(f"owned path has a file where a directory is needed: {parent}")
            copies.append((source, target))
    return copies, skeleton_dirs


def apply(root: Path) -> list[Path]:
    """Copy <dir>/skeleton/<path> over <path> for every owned file; delete the skeletons.

    Validates every lab before changing anything, so a failure leaves the tree untouched.
    """
    copies, skeleton_dirs = _plan(root)
    replaced = []
    for source, target in copies:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        replaced.append(target)
    for skeleton_dir in skeleton_dirs:
        shutil.rmtree(skeleton_dir)
    return replaced


def main(root: Path | None = None) -> int:
    root = root or Path(__file__).resolve().parents[2]
    try:
        replaced = apply(root)
    except (ManifestError, ValueError, FileNotFoundError) as exc:
        print(f"error: {' '.join(str(exc).split())}", file=sys.stderr)
        return 2
    for path in replaced:
        print(path.relative_to(root))
    return 0


if __name__ == "__main__":
    sys.exit(main())
