"""Apply the spec's risk acceptances to raw violations."""

import dataclasses
import datetime
import re

from lfg.policy import Violation
from lfg.rules import Catalogue

_DATE_SHAPE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def _expiry(value) -> datetime.date | None:
    if not isinstance(value, str) or not _DATE_SHAPE.match(value):
        return None
    try:
        return datetime.date.fromisoformat(value)
    except ValueError:
        return None


def _problem(entry, catalogue: Catalogue, today: datetime.date) -> str | None:
    if not isinstance(entry, dict):
        return "risk acceptance is not a mapping"
    rule_id = entry.get("rule_id")
    rule = catalogue.rules.get(rule_id) if isinstance(rule_id, str) else None
    if rule is None:
        return f"risk acceptance names unknown rule {rule_id!r}"
    if rule.klass != "accept":
        return f"{rule_id} is class {rule.klass!r} and cannot be accepted"
    expires = _expiry(entry.get("expires"))
    if expires is None:
        return f"risk acceptance for {rule_id} has an invalid expiry {entry.get('expires')!r}"
    if expires < today:
        return f"risk acceptance for {rule_id} expired on {expires.isoformat()}"
    return None


def apply(violations, spec: dict, catalogue: Catalogue, today: datetime.date) -> list:
    entries = spec.get("risk_acceptances") or []
    valid_until: dict[str, str] = {}
    extra = []
    for index, entry in enumerate(entries):
        problem = _problem(entry, catalogue, today)
        if problem:
            extra.append(
                Violation("LFG-RA-001", problem, f"function.spec.yaml:risk_acceptances[{index}]")
            )
        else:
            current = valid_until.get(entry["rule_id"], "")
            valid_until[entry["rule_id"]] = max(current, entry["expires"])
    result = []
    for violation in violations:
        until = valid_until.get(violation.rule_id)
        if until and violation.rule_id != "LFG-RA-001":
            violation = dataclasses.replace(violation, accepted=True, accepted_until=until)
        result.append(violation)
    return result + extra
