"""Configuration rules: secrets in environment, logging, failure destinations, URLs, dependencies."""

import re
from pathlib import Path

from lfg.policy import Violation
from lfg.policy.template_rules import get_function, is_resource_reference
from lfg.rules import Catalogue

ASYNC_TRIGGERS = ("schedule", "eventbridge")
DESTINATION_TYPES = ("SQS", "SNS")
SPEC_DESTINATIONS = ("sqs", "sns")
LOG_GROUP_TYPE = "AWS::Logs::LogGroup"
FUNCTION_URL_AUTH = "AWS_IAM"

_HASH = re.compile(r"--hash=sha256:[0-9a-fA-F]{64}")
_COMMENT = re.compile(r"(?:^|\s)#.*")
_REQUIREMENTS = "requirements.txt"


def _is_secret_name(name: str, catalogue: Catalogue) -> bool:
    return bool(re.search(catalogue.secret_name_pattern, name)) and not name.endswith(
        catalogue.secret_name_safe_suffixes
    )


def _check_variables(variables, loc: str, catalogue: Catalogue) -> list[Violation]:
    """LFG-SEC-001 for one mapping of variable names to values; anything else cannot be read."""
    if not isinstance(variables, dict):
        return [Violation("LFG-SEC-001", "Environment variables must be a mapping", loc)]
    out = []
    for name in variables:
        if not isinstance(name, str):
            out.append(Violation(
                "LFG-SEC-001", f"Environment variable name {name!r} is not a string", f"{loc}.{name}",
            ))
        elif _is_secret_name(name, catalogue):
            out.append(Violation(
                "LFG-SEC-001", f"Environment variable {name!r} looks like a secret; pass a reference "
                "(a name ending in _ARN, _NAME, _PARAM or _ID) instead", f"{loc}.{name}",
            ))
    return out


def _check_environment(spec: dict, name: str, props: dict, catalogue: Catalogue) -> list[Violation]:
    base = f"template.yaml:Resources.{name}.Properties.Environment"
    out = []
    if "Environment" in props:
        environment = props["Environment"]
        if not isinstance(environment, dict) or "Variables" not in environment:
            if not (isinstance(environment, dict) and not environment):
                out.append(Violation(
                    "LFG-SEC-001", "Environment must be a mapping holding Variables", base,
                ))
        else:
            out += _check_variables(environment["Variables"], base + ".Variables", catalogue)
    if "environment" in spec:
        out += _check_variables(spec["environment"], "function.spec.yaml:environment", catalogue)
    return out


def _check_logging(spec: dict, template: dict, name: str, props: dict) -> list[Violation]:
    base = f"template.yaml:Resources.{name}.Properties.LoggingConfig"
    config = props.get("LoggingConfig")
    if not isinstance(config, dict):
        return [Violation("LFG-LOG-001", "LoggingConfig must be a mapping naming the log group", base)]
    ids = _resource_ids(template)
    reference = config.get("LogGroup")
    loc = base + ".LogGroup"
    if not (is_resource_reference(reference, ids) and "Ref" in reference):
        return [Violation(
            "LFG-LOG-001", "LoggingConfig.LogGroup must be a Ref to a log group declared in the template",
            loc,
        )]
    target = template["Resources"][reference["Ref"]]
    if not isinstance(target, dict) or target.get("Type") != LOG_GROUP_TYPE:
        return [Violation("LFG-LOG-001", f"LoggingConfig.LogGroup must refer to a {LOG_GROUP_TYPE}", loc)]
    target_loc = f"template.yaml:Resources.{reference['Ref']}.Properties.RetentionInDays"
    properties = target.get("Properties")
    retention = properties.get("RetentionInDays") if isinstance(properties, dict) else None
    expected = spec.get("log_retention_days")
    if type(retention) is not int or type(expected) is not int or retention != expected:
        return [Violation(
            "LFG-LOG-001", f"RetentionInDays is {retention!r} but the spec says {expected!r}", target_loc,
        )]
    return []


def _resource_ids(template: dict) -> frozenset[str]:
    resources = template.get("Resources")
    return frozenset(k for k in resources if isinstance(k, str)) if isinstance(resources, dict) else frozenset()


def _destination_problem(value, target_key: str, ids: frozenset[str]) -> str | None:
    """None if value is a mapping with Type SQS or SNS and a Ref or Fn::GetAtt ... Arn to a resource in
    the template; else the location suffix of what is wrong ('' for the mapping itself)."""
    if not isinstance(value, dict):
        return ""
    kind = value.get("Type")
    if not isinstance(kind, str) or kind not in DESTINATION_TYPES:
        return ""
    target = value.get(target_key)
    if not is_resource_reference(target, ids):
        return "." + target_key
    if "Fn::GetAtt" in target:
        attribute = target["Fn::GetAtt"]
        if (attribute[1] if isinstance(attribute, list) else attribute.partition(".")[2]) != "Arn":
            return "." + target_key
    return None


def _check_failure_destination(spec: dict, template: dict, name: str, props: dict) -> list[Violation]:
    base = f"template.yaml:Resources.{name}.Properties"
    ids = _resource_ids(template)
    out = []
    has_destination = False

    def refuse(message: str, loc: str):
        out.append(Violation("LFG-REL-001", message, loc))

    if "DeadLetterQueue" in props:
        problem = _destination_problem(props["DeadLetterQueue"], "TargetArn", ids)
        if problem is None:
            has_destination = True
        else:
            refuse(
                "DeadLetterQueue must have Type SQS or SNS and a TargetArn that is a Ref or "
                "Fn::GetAtt ... Arn to a resource in the template", f"{base}.DeadLetterQueue{problem}",
            )
    if "EventInvokeConfig" in props:
        config = props["EventInvokeConfig"]
        loc = f"{base}.EventInvokeConfig"
        if not isinstance(config, dict):
            refuse("EventInvokeConfig must be a mapping", loc)
        elif "DestinationConfig" in config:
            destinations = config["DestinationConfig"]
            loc += ".DestinationConfig"
            if not isinstance(destinations, dict):
                refuse("DestinationConfig must be a mapping", loc)
            else:
                for key in destinations:
                    if key != "OnFailure":
                        refuse(f"DestinationConfig.{key} is not allowed; only OnFailure is", f"{loc}.{key}")
                if "OnFailure" in destinations:
                    problem = _destination_problem(destinations["OnFailure"], "Destination", ids)
                    if problem is None:
                        has_destination = True
                    else:
                        refuse(
                            "OnFailure must have Type SQS or SNS and a Destination that is a Ref or "
                            "Fn::GetAtt ... Arn to a resource in the template",
                            f"{loc}.OnFailure{problem}",
                        )
    trigger = spec.get("trigger")
    ttype = trigger.get("type") if isinstance(trigger, dict) else None
    if isinstance(ttype, str) and ttype in ASYNC_TRIGGERS:
        if not has_destination and not out:
            refuse(
                "An asynchronous trigger needs a DeadLetterQueue or an OnFailure destination", base,
            )
        if spec.get("failure_destination") not in SPEC_DESTINATIONS:
            refuse(
                f"The spec's failure_destination is {spec.get('failure_destination')!r}; "
                "an asynchronous trigger needs sqs or sns", "function.spec.yaml:failure_destination",
            )
    return out


def _check_function_url(name: str, props: dict) -> list[Violation]:
    if "FunctionUrlConfig" not in props:
        return []
    base = f"template.yaml:Resources.{name}.Properties.FunctionUrlConfig"
    config = props["FunctionUrlConfig"]
    if not isinstance(config, dict):
        return [Violation("LFG-NET-001", "FunctionUrlConfig must be a mapping", base)]
    auth = config.get("AuthType")
    if not isinstance(auth, str) or auth != FUNCTION_URL_AUTH:
        return [Violation(
            "LFG-NET-001", f"FunctionUrlConfig.AuthType is {auth!r}, not {FUNCTION_URL_AUTH!r}",
            base + ".AuthType",
        )]
    return []


def _requirements(text: str) -> list[str]:
    """Each requirement: continuation lines joined, comments and blank lines dropped."""
    joined, pending = [], ""
    for line in text.splitlines():
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        joined.append(pending + line)
        pending = ""
    if pending:
        joined.append(pending)
    cleaned = (_COMMENT.sub("", entry).strip() for entry in joined)
    return [entry for entry in cleaned if entry]


def _requirement_ok(requirement: str) -> bool:
    name_part = requirement.partition("--hash")[0]
    return (
        not requirement.startswith("-")
        and "://" not in requirement
        and "==" in name_part
        and bool(_HASH.search(requirement))
    )


def _check_dependencies(source_dir: Path) -> list[Violation]:
    path = Path(source_dir) / _REQUIREMENTS
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        return [Violation(
            "LFG-DEP-001", f"{_REQUIREMENTS} cannot be read ({type(exc).__name__})", _REQUIREMENTS,
        )]
    return [
        Violation(
            "LFG-DEP-001", f"{requirement!r} must be pinned with == and carry a --hash=sha256: value",
            _REQUIREMENTS,
        )
        for requirement in _requirements(text)
        if not _requirement_ok(requirement)
    ]


def check_config(
    spec: dict, template: dict, source_dir: Path, catalogue: Catalogue,
) -> list[Violation]:
    function = get_function(template)
    if function is None:
        return []
    name, props = function
    return (
        _check_environment(spec, name, props, catalogue)
        + _check_logging(spec, template, name, props)
        + _check_failure_destination(spec, template, name, props)
        + _check_function_url(name, props)
        + _check_dependencies(source_dir)
    )
