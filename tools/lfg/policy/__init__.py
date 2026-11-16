"""Policy engine: run every rule module, then apply risk acceptances."""

import datetime
from dataclasses import dataclass
from pathlib import Path

from lfg.rules import Catalogue, load_catalogue


@dataclass(frozen=True)
class Violation:
    rule_id: str
    message: str
    location: str
    accepted: bool = False
    accepted_until: str | None = None


# Rule modules import Violation from this package, so they load after it is defined.
from lfg.policy import acceptance, config_rules, iam_rules, template_rules

# Rule modules that run whatever the template holds.
TEMPLATE_MODULES = (template_rules.check_template,)
# Rule modules that need the single function; skipped when there is not exactly one.
FUNCTION_MODULES = (iam_rules.check_iam,)
# Function-level modules that also read the function's source directory.
SOURCE_MODULES = (config_rules.check_config,)


def check(
    spec: dict,
    template: dict,
    source_dir: Path,
    today: datetime.date,
    catalogue: Catalogue | None = None,
) -> list[Violation]:
    catalogue = catalogue or load_catalogue()
    has_function = template_rules.get_function(template) is not None
    modules = TEMPLATE_MODULES + (FUNCTION_MODULES if has_function else ())
    raw: list[Violation] = []
    for module_check in modules:
        raw += module_check(spec, template, catalogue)
    if has_function:
        for module_check in SOURCE_MODULES:
            raw += module_check(spec, template, source_dir, catalogue)
    return sorted(
        acceptance.apply(raw, spec, catalogue, today),
        key=lambda v: (v.rule_id, v.location),
    )


def blocking(violations: list[Violation]) -> list[Violation]:
    return [v for v in violations if not v.accepted]
