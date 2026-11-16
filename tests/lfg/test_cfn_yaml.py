import pytest
import yaml
from lfg.cfn_yaml import TemplateLoadError, load_template


def test_good_template_intrinsics_become_long_form(good_dir):
    template = load_template(good_dir / "template.yaml")
    props = template["Resources"]["Function"]["Properties"]
    assert props["FunctionName"] == {"Fn::Sub": "lfg-${Stage}-iam-key-age-audit"}
    assert props["LoggingConfig"]["LogGroup"] == {"Ref": "LogGroup"}
    assert props["DeadLetterQueue"]["TargetArn"] == {"Fn::GetAtt": ["FailureQueue", "Arn"]}


def test_join_sequence_form(tmp_path):
    path = tmp_path / "t.yaml"
    path.write_text('X: !Join ["-", [a, b]]\n', encoding="utf-8")
    assert load_template(path) == {"X": {"Fn::Join": ["-", ["a", "b"]]}}


def test_mapping_form(tmp_path):
    path = tmp_path / "t.yaml"
    path.write_text("X: !If {A: 1}\n", encoding="utf-8")
    assert load_template(path) == {"X": {"Fn::If": {"A": 1}}}


def test_safe_loader_is_unaffected(tmp_path):
    with pytest.raises(yaml.YAMLError):
        yaml.safe_load("X: !Ref Y")


@pytest.mark.parametrize("content", [": :\n- [", "- a\n- b\n"])
def test_bad_content_raises(tmp_path, content):
    path = tmp_path / "t.yaml"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(TemplateLoadError):
        load_template(path)


def test_missing_file_raises(tmp_path):
    with pytest.raises(TemplateLoadError):
        load_template(tmp_path / "absent.yaml")
