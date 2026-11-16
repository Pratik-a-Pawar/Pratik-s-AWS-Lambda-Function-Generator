"""Load the rule catalogue from standards/rules.yaml."""

from dataclasses import dataclass
from pathlib import Path

import yaml

CATALOGUE_PATH = Path(__file__).resolve().parents[2] / "standards" / "rules.yaml"


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    klass: str
    severity: str
    cwe: str | None
    enforced_by: str
    summary: str


@dataclass(frozen=True)
class Catalogue:
    rules: dict[str, Rule]
    enabled_triggers: frozenset[str]
    allowed_resource_types: frozenset[str]
    allowed_function_attributes: frozenset[str]
    allowed_function_properties: frozenset[str]
    allowed_event_properties: dict[str, frozenset[str]]
    wildcard_only_actions: tuple[str, ...]
    sensitive_actions: tuple[str, ...]
    secret_name_pattern: str
    secret_name_safe_suffixes: tuple[str, ...]


def _rule(entry: dict) -> Rule:
    return Rule(
        id=entry["id"],
        title=entry["title"],
        klass=entry["class"],
        severity=entry["severity"],
        cwe=entry.get("cwe"),
        enforced_by=entry["enforced_by"],
        summary=entry["summary"],
    )


def load_catalogue(path: Path | None = None) -> Catalogue:
    data = yaml.safe_load(Path(path or CATALOGUE_PATH).read_text(encoding="utf-8"))
    rules: dict[str, Rule] = {}
    for entry in data["rules"]:
        rule = _rule(entry)
        if rule.id in rules:
            raise ValueError(f"duplicate rule ID: {rule.id}")
        rules[rule.id] = rule
    return Catalogue(
        rules=rules,
        enabled_triggers=frozenset(data["enabled_triggers"]),
        allowed_resource_types=frozenset(data["allowed_resource_types"]),
        allowed_function_attributes=frozenset(data["allowed_function_attributes"]),
        allowed_function_properties=frozenset(data["allowed_function_properties"]),
        allowed_event_properties={
            etype: frozenset(props) for etype, props in data["allowed_event_properties"].items()
        },
        wildcard_only_actions=tuple(data["wildcard_only_actions"]),
        sensitive_actions=tuple(data["sensitive_actions"]),
        secret_name_pattern=data["secret_name_pattern"],
        secret_name_safe_suffixes=tuple(data["secret_name_safe_suffixes"]),
    )
