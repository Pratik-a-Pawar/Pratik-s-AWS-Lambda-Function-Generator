"""Load CloudFormation/SAM YAML, expanding short-form intrinsic tags to long form."""

from pathlib import Path

import yaml

from lfg.yaml_util import UniqueKeyLoader


class TemplateLoadError(Exception):
    """The template file is missing, is not valid YAML, or is not a mapping."""


class _CfnLoader(UniqueKeyLoader):
    pass


def _intrinsic(loader: _CfnLoader, suffix: str, node: yaml.Node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)
    if suffix == "Ref":
        return {"Ref": value}
    if suffix == "GetAtt" and isinstance(value, str):
        value = value.split(".", 1)
    return {f"Fn::{suffix}": value}


_CfnLoader.add_multi_constructor("!", _intrinsic)


def load_template(path: Path) -> dict:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise TemplateLoadError(
            f"cannot read {path}: {getattr(exc, 'strerror', None) or exc}"
        ) from exc
    try:
        data = yaml.load(text, Loader=_CfnLoader)
    except (yaml.YAMLError, ValueError) as exc:
        raise TemplateLoadError(f"{path} is not valid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise TemplateLoadError(f"{path}: top level must be a mapping")
    return data
