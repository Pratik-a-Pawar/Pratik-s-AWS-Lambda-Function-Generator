"""Apply the spec's risk acceptances to raw violations.

Lab 02, part B. Rule served: LFG-RA-001. The brief is labs/02-spec-and-policy/README.md; the
checks are in tests/lfg/test_policy_engine.py. Build violations with
`from lfg.policy import Violation`, as the other rule modules do.
"""

import datetime

from lfg.rules import Catalogue


def apply(violations, spec: dict, catalogue: Catalogue, today: datetime.date) -> list:
    """Mark the violations that a valid risk acceptance covers, and report bad acceptances.

    An entry of spec["risk_acceptances"] is valid only when all of these hold:
    - it is a mapping;
    - its rule_id is a string naming a rule in catalogue.rules whose class (Rule.klass) is
      "accept";
    - its expires is a string written YYYY-MM-DD that is a real calendar date;
    - that date is today or later: an acceptance holds through its expiry day.

    Return a new list. First every input violation, in its original order; each one whose
    rule_id has at least one valid acceptance becomes a copy with accepted=True and
    accepted_until set to the latest expires among that rule's valid acceptances. Then one
    LFG-RA-001 violation for each invalid entry, in entry order, located at
    "function.spec.yaml:risk_acceptances[<index>]", with a message saying what is wrong.

    A missing or null risk_acceptances means there are no acceptances. Any other value that
    is not a list is one LFG-RA-001 located at "function.spec.yaml:risk_acceptances".

    An LFG-RA-001 violation is never marked accepted, whatever the entries say. The input
    violations are not modified.
    """
    raise NotImplementedError("Lab 02, part B: apply the risk acceptances")
