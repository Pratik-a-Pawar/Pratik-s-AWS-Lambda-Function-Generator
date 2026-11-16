"""IAM rules: inline statements only, boundary present, no wildcards or unscoped access."""

import json
from fnmatch import fnmatchcase

from lfg.policy import Violation
from lfg.policy.template_rules import get_function
from lfg.rules import Catalogue

BOUNDARY_POLICY = "policy/lfg-function-boundary"
SCHEDULE_EVENT_TYPE = "ScheduleV2"


def _is_str_list(value) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(v, str) for v in value)


def _statement_problem(statement: dict) -> tuple[str, str] | None:
    """The rule ID and message if the statement is not a plain Allow with Action and Resource."""
    if "NotAction" in statement or "NotResource" in statement:
        return "LFG-IAM-002", "NotAction and NotResource are not allowed"
    effect = statement.get("Effect")
    if not isinstance(effect, str) or effect != "Allow":
        return "LFG-IAM-007", f"Effect must be 'Allow', not {effect!r}"
    action = statement.get("Action")
    if not isinstance(action, str) and not _is_str_list(action):
        return "LFG-IAM-007", "Action must be a string or a non-empty list of strings"
    resource = statement.get("Resource")
    if isinstance(resource, list):
        valid = bool(resource) and all(isinstance(r, (str, dict)) for r in resource)
    else:
        valid = isinstance(resource, (str, dict))
    if not valid:
        return "LFG-IAM-007", "Resource must be present, as a string, mapping or list of them"
    return None


def _actions(statement: dict) -> list[str]:
    action = statement["Action"]
    return [(action if isinstance(action, str) else a).lower() for a in _as_list(action)]


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _has_star_resource(statement: dict) -> bool:
    return "*" in [r for r in _as_list(statement["Resource"]) if isinstance(r, str)]


def _literal_prefix(pattern: str) -> str:
    return pattern.split("*", 1)[0]


def _is_sensitive(action: str, patterns: tuple[str, ...]) -> bool:
    prefix = _literal_prefix(action)
    for pattern in patterns:
        pattern = pattern.lower()
        if fnmatchcase(action, pattern):
            return True
        if "*" in action:
            other = _literal_prefix(pattern)
            if other.startswith(prefix) or prefix.startswith(other):
                return True
    return False


def _declared_actions(spec: dict) -> set[str]:
    permissions = spec.get("permissions") if isinstance(spec, dict) else None
    declared: set[str] = set()
    if not isinstance(permissions, list):
        return declared
    for entry in permissions:
        actions = entry.get("actions") if isinstance(entry, dict) else None
        if isinstance(actions, list):
            declared.update(a.lower() for a in actions if isinstance(a, str))
    return declared


def _statements(policies: list, base: str):
    """Yield (location, statement) for each statement, and violations for malformed policies."""
    for i, policy in enumerate(policies):
        loc = f"{base}.Policies[{i}]"
        if not isinstance(policy, dict) or "Statement" not in policy:
            yield loc, Violation(
                "LFG-IAM-003", "Policies must be inline statements, not managed policies or "
                "SAM policy templates", loc,
            )
            continue
        statements = policy["Statement"]
        if isinstance(statements, dict):
            yield f"{loc}.Statement", statements
        elif isinstance(statements, list):
            for j, statement in enumerate(statements):
                yield f"{loc}.Statement[{j}]", statement
        else:
            yield f"{loc}.Statement", None


def _check_statement(
    statement, loc: str, declared: set[str], catalogue: Catalogue,
) -> list[Violation]:
    problem = _statement_problem(statement) if isinstance(statement, dict) else (
        "LFG-IAM-007", "A statement must be a mapping",
    )
    if problem:
        return [Violation(problem[0], problem[1], loc)]
    out = []
    actions = _actions(statement)
    named = [a for a in actions if a != "*"]
    if "*" in actions:
        out.append(Violation("LFG-IAM-001", "A statement allows the action '*'", loc))
    wildcard_only = tuple(p.lower() for p in catalogue.wildcard_only_actions)
    if _has_star_resource(statement):
        scopable = [a for a in named if not any(fnmatchcase(a, p) for p in wildcard_only)]
        if scopable:
            out.append(Violation(
                "LFG-IAM-005", f"Resource '*' is used with scopable actions: {', '.join(scopable)}", loc,
            ))
    sensitive = [a for a in named if _is_sensitive(a, catalogue.sensitive_actions)]
    if sensitive:
        out.append(Violation(
            "LFG-IAM-006", f"Security-changing actions need an acceptance: {', '.join(sensitive)}", loc,
        ))
    wildcards = [a for a in named if "*" in a and a not in wildcard_only]
    if wildcards:
        out.append(Violation(
            "LFG-IAM-008", f"Wildcards inside action names need an acceptance: {', '.join(wildcards)}", loc,
        ))
    undeclared = [a for a in named if a not in declared]
    if undeclared:
        out.append(Violation(
            "LFG-SPEC-001", f"Actions not declared in the spec: {', '.join(undeclared)}", loc,
        ))
    return out


def _has_boundary(value) -> bool:
    return BOUNDARY_POLICY in json.dumps(value, default=str)


def _check_boundary(name: str, props: dict) -> list[Violation]:
    base = f"template.yaml:Resources.{name}.Properties"
    out = []
    if "Role" in props:
        out.append(Violation("LFG-IAM-004", "An external Role must not be supplied", f"{base}.Role"))
    if not _has_boundary(props.get("PermissionsBoundary")):
        out.append(Violation(
            "LFG-IAM-004", "PermissionsBoundary must be the lfg-function-boundary policy",
            f"{base}.PermissionsBoundary",
        ))
    events = props.get("Events")
    for event_name, event in (events.items() if isinstance(events, dict) else ()):
        if not isinstance(event, dict) or event.get("Type") != SCHEDULE_EVENT_TYPE:
            continue
        eprops = event.get("Properties")
        boundary = eprops.get("PermissionsBoundary") if isinstance(eprops, dict) else None
        if not _has_boundary(boundary):
            out.append(Violation(
                "LFG-IAM-004", "The schedule's role needs the lfg-function-boundary policy",
                f"{base}.Events.{event_name}.Properties.PermissionsBoundary",
            ))
    return out


def check_iam(spec: dict, template: dict, catalogue: Catalogue) -> list[Violation]:
    function = get_function(template)
    if function is None:
        return []
    name, props = function
    out = _check_boundary(name, props)
    base = f"template.yaml:Resources.{name}.Properties"
    if "Policies" not in props:
        return out
    policies = props["Policies"]
    if not isinstance(policies, list):
        return out + [Violation(
            "LFG-IAM-003", "Policies must be a list of inline statements", f"{base}.Policies",
        )]
    declared = _declared_actions(spec)
    for loc, statement in _statements(policies, base):
        if isinstance(statement, Violation):
            out.append(statement)
        else:
            out += _check_statement(statement, loc, declared, catalogue)
    return out
