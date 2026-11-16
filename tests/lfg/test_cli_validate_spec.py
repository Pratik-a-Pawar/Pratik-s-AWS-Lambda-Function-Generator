from lfg.cli import main


def test_version(capsys):
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip() == "lfg 0.1.0"


def test_validate_good(good_dir, capsys):
    assert main(["validate-spec", str(good_dir)]) == 0
    assert capsys.readouterr().out.strip() == "OK: iam-key-age-audit"


def test_validate_bad(good_dir, capsys):
    spec_file = good_dir / "function.spec.yaml"
    text = spec_file.read_text().replace("timeout: 30", "timeout: 901")
    spec_file.write_text(text)
    assert main(["validate-spec", str(good_dir)]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert any(line.startswith("timeout: ") for line in lines)


def test_missing_spec(tmp_path, capsys):
    assert main(["validate-spec", str(tmp_path / "missing")]) == 2
    err = capsys.readouterr().err
    assert "function.spec.yaml" in err
    assert "Traceback" not in err


def test_unknown_command():
    assert main(["frobnicate"]) == 2


def test_invalid_yaml_exits_2(good_dir, capsys):
    (good_dir / "function.spec.yaml").write_text(": :\n- [")
    assert main(["validate-spec", str(good_dir)]) == 2
    assert "Traceback" not in capsys.readouterr().err


def test_binary_spec_exits_2(good_dir, capsys):
    (good_dir / "function.spec.yaml").write_bytes(b"\xff\xfe\x00\x80\x81")
    assert main(["validate-spec", str(good_dir)]) == 2
    assert "Traceback" not in capsys.readouterr().err
