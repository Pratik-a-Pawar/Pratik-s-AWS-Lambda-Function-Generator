"""Policy engine: run every rule module, then apply risk acceptances.

Lab 02, part B. The brief is labs/02-spec-and-policy/README.md; the checks for this file are
tests/lfg/test_policy_engine.py, and every other policy test runs through check().

Each rule module exposes one check function, registered in one of the three tuples below.
check() runs what the tuples hold and never calls a rule module by name, so adding a rule
module means writing its check function and adding it to the right tuple.

Location strings. Every Violation.location says where the problem is, as the file name, a
colon, then mapping keys joined with dots and list indexes in brackets:
    template.yaml:Resources.Function.Properties.Timeout
    template.yaml:Resources.Function.Properties.Policies[0].Statement[1]
    function.spec.yaml:risk_acceptances[0]
    requirements.txt
Each rule module's docstrings say which location each violation uses.
"""

import datetime
from dataclasses import dataclass
from pathlib import Path

from lfg.rules import Catalogue


@dataclass(frozen=True)
class Violation:
    rule_id: str
    message: str
    location: str
    accepted: bool = False
    accepted_until: str | None = None


# Rule modules import Violation from this package, so they load after it is defined.
# check() also needs this package's acceptance module: import it on the same line.
from lfg.policy import config_rules, iam_rules, template_rules

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
    """Run every registered rule module and return all violations, acceptances applied.

    - catalogue None means the real catalogue, from lfg.rules.load_catalogue().
    - Each function in TEMPLATE_MODULES always runs, called as f(spec, template, catalogue).
    - Each function in FUNCTION_MODULES runs, called the same way, only when the template
      holds exactly one AWS::Serverless::Function (template_rules.get_function decides).
      Without one, template_rules has already reported LFG-TPL-001.
    - Each function in SOURCE_MODULES runs under the same condition, called as
      f(spec, template, source_dir, catalogue).
    - All the raw violations then go through acceptance.apply(raw, spec, catalogue, today).
    - The result is sorted by (rule_id, location).

    The CLI only calls this for a spec that passed validate_spec, but the tests call it
    directly with specs and templates of every shape. Whatever a value turns out to be (a
    list where a mapping was expected, a number, null, a missing key), the answer is a
    violation, never an exception and never silence. The one exception allowed to escape is
    RecursionError from a template nested too deeply, which the CLI reports as exit code 2.
    """
    raise NotImplementedError("Lab 02, part B: run the rule modules and apply acceptances")


def blocking(violations: list[Violation]) -> list[Violation]:
    """Return the violations that are not accepted, in their original order."""
    raise NotImplementedError("Lab 02, part B: keep only the violations that still block")
