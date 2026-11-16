import importlib.util
import os
from pathlib import Path

import pytest
from lfg.labcheck import ManifestError

_PATH = Path(__file__).resolve().parents[2] / "tools" / "dev" / "skeletonise.py"
_SPEC = importlib.util.spec_from_file_location("skeletonise", _PATH)
skeletonise = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(skeletonise)


def make_repo(tmp_path: Path, owned: list[str], skeletons: dict[str, str],
              lab_dir: str = "labs/01") -> Path:
    (tmp_path / "labs").mkdir(exist_ok=True)
    lines = "\n".join(f"      - {o}" for o in owned)
    owned_yaml = f"\n{lines}" if owned else " []"
    (tmp_path / "labs" / "manifest.yaml").write_text(
        f'labs:\n  "01":\n    title: One\n    dir: {lab_dir}\n'
        f"    owned:{owned_yaml}\n    checks: []\n",
        encoding="utf-8",
    )
    (tmp_path / "tools").mkdir(exist_ok=True)
    (tmp_path / "tools" / "real.py").write_text("real\n", encoding="utf-8")
    (tmp_path / "tools" / "other.py").write_text("other\n", encoding="utf-8")
    for name, content in skeletons.items():
        path = tmp_path / lab_dir / "skeleton" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


def untouched(root: Path) -> bool:
    return (root / "tools" / "real.py").read_text() == "real\n" and (
        root / "labs" / "01" / "skeleton").is_dir()


def test_owned_file_is_replaced_by_skeleton(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    assert skeletonise.apply(root) == [root / "tools" / "real.py"]
    assert (root / "tools" / "real.py").read_text() == "skeleton\n"


def test_skeleton_directory_is_removed(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    skeletonise.apply(root)
    assert not (root / "labs" / "01" / "skeleton").exists()


def test_unowned_file_is_unchanged(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    skeletonise.apply(root)
    assert (root / "tools" / "other.py").read_text() == "other\n"


def test_missing_skeleton_raises_and_changes_nothing(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py", "tools/other.py"], {"tools/real.py": "skeleton\n"})
    with pytest.raises(FileNotFoundError, match="tools/other.py"):
        skeletonise.apply(root)
    assert untouched(root)


@pytest.mark.parametrize("owned", ["../escape.py", "tools/../../escape.py", "/etc/escape.py"])
def test_escaping_path_raises_and_changes_nothing(tmp_path, owned):
    root = make_repo(tmp_path, [owned], {})
    with pytest.raises(ValueError, match="escape"):
        skeletonise.apply(root)
    assert (root / "tools" / "real.py").read_text() == "real\n"


def test_owned_path_through_symlink_out_of_repo_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "repo"
    root.mkdir()
    make_repo(root, ["tools/real.py", "link/x.py"],
              {"tools/real.py": "skeleton\n", "link/x.py": "skeleton\n"})
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="link/x.py"):
        skeletonise.apply(root)
    assert not (outside / "x.py").exists()
    assert untouched(root)


def test_lab_dir_symlinked_out_of_repo_is_refused(tmp_path):
    outside = tmp_path / "outside"
    (outside / "skeleton" / "tools").mkdir(parents=True)
    (outside / "skeleton" / "tools" / "real.py").write_text("skeleton\n")
    root = tmp_path / "repo"
    root.mkdir()
    make_repo(root, ["tools/real.py"], {}, lab_dir="evil")
    (root / "evil").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="evil"):
        skeletonise.apply(root)
    assert (outside / "skeleton").is_dir()
    assert (root / "tools" / "real.py").read_text() == "real\n"


def test_symlinked_skeleton_directory_is_refused(tmp_path):
    outside = tmp_path / "outside"
    (outside / "tools").mkdir(parents=True)
    (outside / "tools" / "real.py").write_text("skeleton\n")
    root = tmp_path / "repo"
    root.mkdir()
    make_repo(root, ["tools/real.py"], {})
    (root / "labs" / "01").mkdir()
    (root / "labs" / "01" / "skeleton").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="skeleton"):
        skeletonise.apply(root)
    assert (outside / "tools" / "real.py").is_file()
    assert (root / "tools" / "real.py").read_text() == "real\n"


def test_symlinked_skeleton_source_is_refused(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    secret = tmp_path / "secret.txt"
    secret.write_text("secret\n")
    source = root / "labs" / "01" / "skeleton" / "tools" / "real.py"
    source.unlink()
    source.symlink_to(secret)
    with pytest.raises(ValueError, match="real.py"):
        skeletonise.apply(root)
    assert untouched(root)


def test_symlinked_target_is_refused(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    victim = tmp_path / "victim.txt"
    victim.write_text("victim\n")
    (root / "tools" / "real.py").unlink()
    (root / "tools" / "real.py").symlink_to(victim)
    with pytest.raises(ValueError, match="real.py"):
        skeletonise.apply(root)
    assert victim.read_text() == "victim\n"


def test_directory_target_fails_before_anything_is_changed(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py", "tools/dd"],
                     {"tools/real.py": "skeleton\n", "tools/dd": "skeleton\n"})
    (root / "tools" / "dd").mkdir()
    with pytest.raises(ValueError, match="dd"):
        skeletonise.apply(root)
    assert untouched(root)


def test_target_whose_parent_is_a_file_fails_before_anything_is_changed(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py", "tools/other.py/x.py"],
                     {"tools/real.py": "skeleton\n", "tools/other.py/x.py": "skeleton\n"})
    with pytest.raises(ValueError, match="other.py"):
        skeletonise.apply(root)
    assert untouched(root)


def test_skeleton_source_that_is_a_directory_fails_before_anything_is_changed(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py", "tools/other.py"], {"tools/real.py": "skeleton\n"})
    (root / "labs" / "01" / "skeleton" / "tools" / "other.py").mkdir()
    with pytest.raises(FileNotFoundError, match="other.py"):
        skeletonise.apply(root)
    assert untouched(root)


def test_deletion_failure_is_not_swallowed(tmp_path, monkeypatch):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})

    def boom(path):
        raise OSError("cannot delete")

    monkeypatch.setattr(skeletonise.shutil, "rmtree", boom)
    with pytest.raises(OSError, match="cannot delete"):
        skeletonise.apply(root)


def test_main_applies_and_prints_replaced_paths(tmp_path, capsys):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    assert skeletonise.main(root) == 0
    assert capsys.readouterr().out.strip() == "tools/real.py"


@pytest.mark.parametrize("setup", ["no_manifest", "escape", "missing_skeleton"])
def test_main_reports_errors_in_one_line_and_returns_2(tmp_path, capsys, setup):
    if setup == "no_manifest":
        root = tmp_path
    elif setup == "escape":
        root = make_repo(tmp_path, ["../x.py"], {})
    else:
        root = make_repo(tmp_path, ["tools/real.py"], {})
    assert skeletonise.main(root) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and err.count("\n") == 1


def test_manifest_error_is_a_value_error():
    assert issubclass(ManifestError, ValueError)


def test_owned_path_repeated_in_one_lab_is_refused(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py", "tools/real.py"], {"tools/real.py": "skeleton\n"})
    with pytest.raises(ValueError, match="tools/real.py"):
        skeletonise.apply(root)
    assert untouched(root)


def test_owned_path_shared_by_two_labs_is_refused(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    manifest = root / "labs" / "manifest.yaml"
    manifest.write_text(
        manifest.read_text()
        + '  "02":\n    title: Two\n    dir: labs/02\n    owned: [tools/real.py]\n'
        "    checks: []\n",
        encoding="utf-8",
    )
    other = root / "labs" / "02" / "skeleton" / "tools"
    other.mkdir(parents=True)
    (other / "real.py").write_text("second\n")
    with pytest.raises(ValueError, match="tools/real.py"):
        skeletonise.apply(root)
    assert untouched(root)


def test_hard_linked_target_is_not_written_through(tmp_path):
    root = make_repo(tmp_path, ["tools/real.py"], {"tools/real.py": "skeleton\n"})
    victim = tmp_path / "victim.txt"
    victim.write_text("victim\n")
    (root / "tools" / "real.py").unlink()
    os.link(victim, root / "tools" / "real.py")
    skeletonise.apply(root)
    assert victim.read_text() == "victim\n"
    assert (root / "tools" / "real.py").read_text() == "skeleton\n"
