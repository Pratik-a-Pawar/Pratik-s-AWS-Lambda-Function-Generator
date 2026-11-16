"""IAM rules: inline statements only, boundary present, no wildcards or unscoped access."""

import re
from fnmatch import fnmatchcase

from lfg.policy import Violation
from lfg.policy.template_rules import get_function
from lfg.rules import Catalogue

BOUNDARY = {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:policy/lfg-function-boundary"}
SCHEDULE_EVENT_TYPE = "ScheduleV2"
STATEMENT_KEYS = ("Sid", "Effect", "Action", "Resource", "Condition")

_ACTION_FORM = re.compile(r"[A-Za-z0-9-]+:[A-Za-z0-9*?]+")
_SUBSTITUTION = re.compile(r"\$\{([^}]*)\}")
_WHITESPACE = re.compile(r"\s")
PSEUDO_PARAMETERS = ("AWS::Partition", "AWS::Region", "AWS::AccountId")
_WILDCARDS = "*?"


def _is_str_list(value) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(v, str) for v in value)


def _as_list(value) -> list:
    return value if isinstance(value, list) else [value]


def _has_wildcard(text: str) -> bool:
    return any(c in text for c in _WILDCARDS)


def _literal_prefix(pattern: str) -> str:
    return re.split(r"[*?]", pattern, maxsplit=1)[0]


def _action_class(action: str) -> str:
    """'any' for an action that means everything, 'bad' for a malformed one, else 'named'."""
    if all(c in _WILDCARDS for c in action) and action:
        return "any"
    if _ACTION_FORM.fullmatch(action):
        return "named"
    service, colon, _ = action.partition(":")
    return "any" if colon and _has_wildcard(service) else "bad"


def _is_id(value, ids: frozenset[str]) -> bool:
    return isinstance(value, str) and value in ids


def _sub_variable_ok(variable: str, ids: frozenset[str]) -> bool:
    if variable in PSEUDO_PARAMETERS or variable == "Stage":
        return True
    name, dot, attribute = variable.partition(".")
    return name in ids and (not dot or bool(attribute))


def _resource_form(entry, ids: frozenset[str]) -> bool:
    """Whether a Resource entry is one of the closed list of permitted forms."""
    if isinstance(entry, str):
        return not _WHITESPACE.search(entry)
    if not isinstance(entry, dict) or len(entry) != 1:
        return False
    (key, value), = entry.items()
    if key == "Ref":
        return _is_id(value, ids)
    if key == "Fn::GetAtt":
        if isinstance(value, str):
            name, dot, attribute = value.partition(".")
            return name in ids and bool(dot) and bool(attribute)
        return (
            isinstance(value, list) and len(value) == 2 and _is_id(value[0], ids)
            and isinstance(value[1], str) and bool(value[1])
        )
    if key == "Fn::Sub":
        return (
            isinstance(value, str) and not _WHITESPACE.search(value)
            and all(_sub_variable_ok(v, ids) for v in _SUBSTITUTION.findall(value))
        )
    return False


def _resource_text(entry) -> str | None:
    """The text a string or Fn::Sub resource reads as, or None for Ref and Fn::GetAtt."""
    if isinstance(entry, str):
        return entry
    return entry.get("Fn::Sub")


def _is_unscoped(entry) -> bool:
    text = _resource_text(entry)
    if text is None:
        return False
    text = _SUBSTITUTION.sub("X", text)
    if all(c in "*?/" for c in text):
        return True
    if not text.lower().startswith("arn:"):
        return False
    parts = text.split(":", 5)
    if len(parts) < 6:
        return _has_wildcard(text)
    return all(c in "*?/:" for c in parts[5])


def _statement_problem(statement: dict, ids: frozenset[str]) -> tuple[str, str] | None:
    """The rule ID and message if the statement is not a plain Allow with Action and Resource."""
    if "NotAction" in statement or "NotResource" in statement:
        return "LFG-IAM-002", "NotAction and NotResource are not allowed"
    extra = [k for k in statement if k not in STATEMENT_KEYS]
    if extra:
        return "LFG-IAM-007", f"Statement keys {extra!r} are not allowed"
    effect = statement.get("Effect")
    if not isinstance(effect, str) or effect != "Allow":
        return "LFG-IAM-007", f"Effect must be 'Allow', not {effect!r}"
    action = statement.get("Action")
    if not isinstance(action, str) and not _is_str_list(action):
        return "LFG-IAM-007", "Action must be a string or a non-empty list of strings"
    if any(_action_class(a) == "bad" for a in _as_list(action)):
        return "LFG-IAM-007", "Every action must be written as <service>:<name>"
    resource = statement.get("Resource")
    entries = resource if isinstance(resource, list) else [resource]
    if not entries or not all(_resource_form(r, ids) for r in entries):
        return "LFG-IAM-007", "Resource must be present, as a string, a permitted intrinsic or a list"
    return None


def _is_sensitive(action: str, patterns: tuple[str, ...]) -> bool:
    prefix = _literal_prefix(action)
    for pattern in patterns:
        pattern = pattern.lower()
        if fnmatchcase(action, pattern):
            return True
        if _has_wildcard(action):
            other = _literal_prefix(pattern)
            if fnmatchcase(pattern, action) or other.startswith(prefix) or prefix.startswith(other):
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
    statement, loc: str, declared: set[str], ids: frozenset[str], catalogue: Catalogue,
) -> list[Violation]:
    problem = _statement_problem(statement, ids) if isinstance(statement, dict) else (
        "LFG-IAM-007", "A statement must be a mapping",
    )
    if problem:
        return [Violation(problem[0], problem[1], loc)]
    out = []
    actions = [a.lower() for a in _as_list(statement["Action"])]
    named = [a for a in actions if _action_class(a) == "named"]
    if len(named) < len(actions):
        out.append(Violation("LFG-IAM-001", "A statement allows every action ('*' or a wildcard service)", loc))
    wildcard_only = tuple(p.lower() for p in catalogue.wildcard_only_actions)
    resources = _as_list(statement["Resource"])
    if any(_is_unscoped(r) for r in resources):
        scopable = [a for a in named if not any(fnmatchcase(a, p) for p in wildcard_only)]
        if scopable:
            out.append(Violation(
                "LFG-IAM-005", f"A resource names everything for scopable actions: {', '.join(scopable)}", loc,
            ))
    sensitive = [a for a in named if _is_sensitive(a, catalogue.sensitive_actions)]
    if sensitive:
        out.append(Violation(
            "LFG-IAM-006", f"Security-changing actions need an acceptance: {', '.join(sensitive)}", loc,
        ))
    wildcards = [a for a in named if _has_wildcard(a) and a not in wildcard_only]
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


def _check_boundary(name: str, props: dict) -> list[Violation]:
    base = f"template.yaml:Resources.{name}.Properties"
    out = []
    if "Role" in props:
        out.append(Violation("LFG-IAM-004", "An external Role must not be supplied", f"{base}.Role"))
    if props.get("PermissionsBoundary") != BOUNDARY:
        out.append(Violation(
            "LFG-IAM-004", "PermissionsBoundary must be exactly the lfg-function-boundary Fn::Sub",
            f"{base}.PermissionsBoundary",
        ))
    events = props.get("Events")
    for event_name, event in (events.items() if isinstance(events, dict) else ()):
        if not isinstance(event, dict) or event.get("Type") != SCHEDULE_EVENT_TYPE:
            continue
        eloc = f"{base}.Events.{event_name}.Properties"
        eprops = event.get("Properties") if isinstance(event.get("Properties"), dict) else {}
        if "RoleArn" in eprops:
            out.append(Violation(
                "LFG-IAM-004", "An external RoleArn on the schedule bypasses the boundary",
                f"{eloc}.RoleArn",
            ))
        if eprops.get("PermissionsBoundary") != BOUNDARY:
            out.append(Violation(
                "LFG-IAM-004", "The schedule's PermissionsBoundary must be exactly the "
                "lfg-function-boundary Fn::Sub", f"{eloc}.PermissionsBoundary",
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
    resources = template.get("Resources")
    ids = frozenset(k for k in resources if isinstance(k, str)) if isinstance(resources, dict) else frozenset()
    for loc, statement in _statements(policies, base):
        if isinstance(statement, Violation):
            out.append(statement)
        else:
            out += _check_statement(statement, loc, declared, ids, catalogue)
    return out
