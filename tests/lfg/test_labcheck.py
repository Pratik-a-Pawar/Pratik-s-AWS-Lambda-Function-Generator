from pathlib import Path

import pytest
from lfg.cli import main
from lfg.labcheck import ManifestError, load_manifest, run


def make_repo(tmp_path: Path, manifest: str, files: dict[str, str] | None = None) -> Path:
    (tmp_path / "labs").mkdir()
    (tmp_path / "labs" / "manifest.yaml").write_text(manifest, encoding="utf-8")
    for name, content in (files or {}).items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return tmp_path


def manifest_for(checks: str) -> str:
    return f'labs:\n  "01":\n    title: One\n    dir: labs/01\n    owned: []\n    checks: {checks}\n'


def test_passing_check_returns_0(tmp_path):
    root = make_repo(tmp_path, manifest_for("[checks/test_ok.py]"),
                     {"checks/test_ok.py": "def test_ok():\n    assert True\n"})
    assert run("01", root) == 0


def test_failing_check_returns_1(tmp_path):
    root = make_repo(tmp_path, manifest_for("[checks/test_bad.py]"),
                     {"checks/test_bad.py": "def test_bad():\n    assert False\n"})
    assert run("01", root) == 1


def test_unknown_lab_returns_2(tmp_path, capsys):
    root = make_repo(tmp_path, manifest_for("[]"))
    assert run("99", root) == 2
    assert "unknown lab" in capsys.readouterr().err


def test_empty_checks_says_so_and_returns_0(tmp_path, capsys):
    root = make_repo(tmp_path, manifest_for("[]"))
    assert run("01", root) == 0
    assert capsys.readouterr().out.strip() == "Lab 01 has no checks yet"


@pytest.mark.parametrize("check", ["checks/missing.py", "../outside.py", "/etc/passwd"])
def test_bad_check_path_returns_2(tmp_path, capsys, check):
    root = make_repo(tmp_path, manifest_for(f"[{check}]"))
    assert run("01", root) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and err.count("\n") == 1


@pytest.mark.parametrize("manifest", [
    None,
    "labs: [unclosed",
    "- just\n- a list\n",
    "labs: not-a-mapping\n",
    'labs:\n  "01":\n    title: One\n    dir: labs/01\n',
    'labs:\n  "01":\n    title: One\n    checks: [a.py]\n    checks: [b.py]\n',
    'labs:\n  "01":\n    dir: labs/01\n    checks: []\n',
])
def test_bad_manifest_returns_2_with_one_line(tmp_path, capsys, manifest):
    if manifest is not None:
        make_repo(tmp_path, manifest)
    assert run("01", tmp_path) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and err.count("\n") == 1


def test_load_manifest_raises_manifest_error(tmp_path):
    with pytest.raises(ManifestError):
        load_manifest(tmp_path)


def test_list_prints_titles_from_real_manifest(capsys):
    assert main(["labcheck", "--list"]) == 0
    out = capsys.readouterr().out
    assert "02  Function spec and policy checker" in out
    assert "00  Workstation and account guardrails" in out


def test_cli_labcheck_without_lab_is_usage_error(capsys):
    assert main(["labcheck"]) == 2
    assert capsys.readouterr().err.startswith("error:")


def test_cli_labcheck_empty_lab(capsys):
    assert main(["labcheck", "02"]) == 0
    assert "Lab 02 has no checks yet" in capsys.readouterr().out


def test_check_collecting_no_tests_returns_1_with_message(tmp_path, capsys):
    root = make_repo(tmp_path, manifest_for("[checks/test_none.py]"),
                     {"checks/test_none.py": "VALUE = 1\n"})
    assert run("01", root) == 1
    err = capsys.readouterr().err
    assert err == "error: no tests were collected\n"


def test_other_pytest_exit_codes_return_2_with_message(tmp_path, capsys):
    root = make_repo(tmp_path, manifest_for("[checks/test_broken.py]"),
                     {"checks/test_broken.py": "import os\nos._exit(4)\n"
                      "def test_x():\n    pass\n"})
    assert run("01", root) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and err.count("\n") == 1


def test_check_named_like_an_option_is_refused(tmp_path, capsys):
    root = make_repo(tmp_path, manifest_for('["-x.py"]'),
                     {"-x.py": "def test_ok():\n    assert True\n"})
    assert run("01", root) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and err.count("\n") == 1


def test_check_symlinked_outside_root_is_refused(tmp_path, capsys):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "test_out.py").write_text("def test_ok():\n    assert True\n")
    (tmp_path / "repo").mkdir()
    root = make_repo(tmp_path / "repo", manifest_for("[checks/test_out.py]"))
    (root / "checks").mkdir()
    (root / "checks" / "test_out.py").symlink_to(outside / "test_out.py")
    assert run("01", root) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and err.count("\n") == 1


def test_pytest_environment_options_are_not_inherited(tmp_path, monkeypatch):
    root = make_repo(tmp_path, manifest_for("[checks/test_ok.py]"),
                     {"checks/test_ok.py": "def test_ok():\n    assert True\n"})
    monkeypatch.setenv("PYTEST_ADDOPTS", "-k nothing_matches")
    monkeypatch.setenv("PYTEST_PLUGINS", "no_such_plugin_module")
    assert run("01", root) == 0


@pytest.mark.parametrize("fields", [
    "dir: ''\n    owned: []",
    "dir: /abs\n    owned: []",
    "dir: ../x\n    owned: []",
    "dir: 5\n    owned: []",
    "dir: labs/01\n    owned: tools/a.py",
    "dir: labs/01\n    owned: ['']",
    "dir: labs/01\n    owned: [../a.py]",
    "dir: labs/01\n    owned: [/etc/a.py]",
    "dir: labs/01",
])
def test_manifest_dir_and_owned_are_validated(tmp_path, fields):
    root = make_repo(tmp_path, f'labs:\n  "01":\n    title: One\n    {fields}\n    checks: []\n')
    with pytest.raises(ManifestError):
        load_manifest(root)


@pytest.mark.parametrize("fields", [
    'dir: labs/01\n    owned: []\n    checks: ["a\\0b.py"]',
    'dir: labs/01\n    owned: ["a\\0b.py"]\n    checks: []',
    'dir: "labs/\\x0001"\n    owned: []\n    checks: []',
    'dir: labs/01\n    owned: []\n    checks: ["a\\nb.py"]',
    'dir: labs/01\n    owned: []\n    checks: ["a\\x7fb.py"]',
])
def test_control_characters_in_manifest_paths_are_refused(tmp_path, capsys, fields):
    root = make_repo(tmp_path, f'labs:\n  "01":\n    title: One\n    {fields}\n')
    with pytest.raises(ManifestError, match="lab '01'"):
        load_manifest(root)
    assert run("01", root) == 2
    err = capsys.readouterr().err
    assert err.startswith("error:") and err.count("\n") == 1
