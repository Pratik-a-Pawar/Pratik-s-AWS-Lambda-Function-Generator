"""Template-level rules: resource set, naming, spec match, trigger, runtime and timeout."""

from lfg.policy import Violation
from lfg.rules import Catalogue

FUNCTION_TYPE = "AWS::Serverless::Function"
ALLOWED_RUNTIMES = ("python3.13", "python3.14")
LONG_TIMEOUT_SECONDS = 60
TRIGGER_EVENT_TYPES = {"schedule": "ScheduleV2", "eventbridge": "EventBridgeRule"}

_TPL = "template.yaml:"
_SPEC = "function.spec.yaml:"


def _resources(template: dict) -> dict:
    resources = template.get("Resources")
    return resources if isinstance(resources, dict) else {}


def get_function(template: dict) -> tuple[str, dict] | None:
    functions = [
        (name, res)
        for name, res in _resources(template).items()
        if isinstance(res, dict) and res.get("Type") == FUNCTION_TYPE
    ]
    if len(functions) != 1:
        return None
    name, resource = functions[0]
    props = resource.get("Properties")
    return name, props if isinstance(props, dict) else {}


def is_resource_reference(entry, ids: frozenset[str]) -> bool:
    """Whether entry is a Ref or Fn::GetAtt naming a logical ID in the template's Resources."""
    if not isinstance(entry, dict) or len(entry) != 1:
        return False
    (key, value), = entry.items()
    if key == "Ref":
        return isinstance(value, str) and value in ids
    if key == "Fn::GetAtt":
        if isinstance(value, str):
            name, dot, attribute = value.partition(".")
            return name in ids and bool(dot) and bool(attribute)
        return (
            isinstance(value, list) and len(value) == 2
            and isinstance(value[0], str) and value[0] in ids
            and isinstance(value[1], str) and bool(value[1])
        )
    return False


def _same(left, right) -> bool:
    return type(left) is type(right) and left == right


SERVERLESS_TRANSFORM = "AWS::Serverless-2016-10-31"
MACRO_KEY = "Fn::Transform"


def _macros(node, path: str, seen: tuple = ()) -> list[Violation]:
    """One violation per Fn::Transform key anywhere under node."""
    if id(node) in seen:
        return []
    seen += (id(node),)
    out = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if key == MACRO_KEY:
                out.append(Violation(
                    "LFG-TPL-004", "Fn::Transform (a macro) is not allowed", _TPL + here,
                ))
            out += _macros(value, here, seen)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            out += _macros(value, f"{path}[{index}]", seen)
    return out


STAGE_PARAMETERS = {"Stage": {"Type": "String", "AllowedValues": ["dev", "prod"]}}


def _check_parameters(template: dict) -> list[Violation]:
    """Parameters must be exactly the pinned Stage, so ${Stage} in an ARN cannot become '*'."""
    params = template.get("Parameters")
    if not isinstance(params, dict):
        return [Violation(
            "LFG-TPL-004", "Parameters must declare exactly the Stage parameter", _TPL + "Parameters",
        )]
    out = []
    if params.get("Stage") != STAGE_PARAMETERS["Stage"]:
        out.append(Violation(
            "LFG-TPL-004",
            "Stage must be exactly a String parameter with AllowedValues [dev, prod] and no Default",
            _TPL + "Parameters.Stage",
        ))
    out += [
        Violation("LFG-TPL-004", f"Parameter {name!r} is not allowed", f"{_TPL}Parameters.{name}")
        for name in params
        if name != "Stage"
    ]
    return out


def _check_sections(template: dict, catalogue: Catalogue) -> list[Violation]:
    out = [
        Violation(
            "LFG-TPL-004", f"Top-level section {key!r} is not on the allow-list", f"{_TPL}{key}",
        )
        for key in template
        if key not in catalogue.allowed_template_sections
    ]
    transform = template.get("Transform")
    if not isinstance(transform, str) or transform != SERVERLESS_TRANSFORM:
        out.append(Violation(
            "LFG-TPL-004", f"Transform must be exactly {SERVERLESS_TRANSFORM!r}", _TPL + "Transform",
        ))
    return out + _check_parameters(template) + _macros(template, "")


def _check_resources(template: dict, catalogue: Catalogue) -> list[Violation]:
    out = []
    if "Globals" in template:
        out.append(Violation("LFG-TPL-002", "A Globals section is not allowed", _TPL + "Globals"))
    for name, res in _resources(template).items():
        rtype = res.get("Type") if isinstance(res, dict) else None
        if not isinstance(rtype, str) or rtype not in catalogue.allowed_resource_types:
            out.append(Violation(
                "LFG-TPL-001", f"Resource type {rtype!r} is not on the allow-list",
                f"{_TPL}Resources.{name}.Type",
            ))
    if get_function(template) is None:
        out.append(Violation(
            "LFG-TPL-001", f"Exactly one {FUNCTION_TYPE} is required", _TPL + "Resources",
        ))
    return out


def _check_settings(spec: dict, name: str, props: dict) -> list[Violation]:
    base = f"{_TPL}Resources.{name}.Properties."
    out = []

    def mismatch(prop: str, expected, actual):
        out.append(Violation(
            "LFG-SPEC-002", f"{prop} is {actual!r} in the template but {expected!r} in the spec",
            base + prop,
        ))

    expected_name = {"Fn::Sub": "lfg-${Stage}-" + str(spec.get("name"))}
    if props.get("FunctionName") != expected_name:
        out.append(Violation(
            "LFG-NAME-001", f"FunctionName must be {expected_name!r}", base + "FunctionName",
        ))

    runtime = props.get("Runtime")
    if runtime not in ALLOWED_RUNTIMES:
        out.append(Violation("LFG-RUN-001", f"Runtime {runtime!r} is not allowed", base + "Runtime"))
    if runtime != spec.get("runtime"):
        mismatch("Runtime", spec.get("runtime"), runtime)
    if props.get("Architectures") != [spec.get("architecture")]:
        mismatch("Architectures", [spec.get("architecture")], props.get("Architectures"))
    for prop, key in (("Timeout", "timeout"), ("MemorySize", "memory")):
        if not _same(props.get(prop), spec.get(key)):
            mismatch(prop, spec.get(key), props.get(prop))
    timeout = props.get("Timeout")
    if isinstance(timeout, int) and not isinstance(timeout, bool) and timeout > LONG_TIMEOUT_SECONDS:
        out.append(Violation(
            "LFG-RUN-002", f"Timeout {timeout} exceeds {LONG_TIMEOUT_SECONDS} seconds",
            base + "Timeout",
        ))
    return out


def _check_trigger(spec: dict, name: str, props: dict, catalogue: Catalogue) -> list[Violation]:
    trigger = spec.get("trigger") if isinstance(spec.get("trigger"), dict) else {}
    ttype = trigger.get("type")
    if not isinstance(ttype, str) or ttype not in catalogue.enabled_triggers:
        return [Violation(
            "LFG-TRG-001", f"Trigger type {ttype!r} is not enabled", _SPEC + "trigger.type",
        )]
    events_loc = f"{_TPL}Resources.{name}.Properties.Events"
    events = props.get("Events")
    if not isinstance(events, dict) or len(events) != 1:
        return [Violation("LFG-SPEC-002", "Exactly one event is required", events_loc)]
    (event_name, event), = events.items()
    loc = f"{events_loc}.{event_name}"
    event = event if isinstance(event, dict) else {}
    eprops = event.get("Properties") if isinstance(event.get("Properties"), dict) else {}
    expected_type = TRIGGER_EVENT_TYPES.get(ttype)
    if expected_type is None or event.get("Type") != expected_type:
        return [Violation(
            "LFG-SPEC-002", f"Event type must be {expected_type!r} for trigger {ttype!r}",
            loc + ".Type",
        )]
    if ttype == "schedule":
        wanted = {
            "ScheduleExpression": trigger.get("expression"),
            "ScheduleExpressionTimezone": trigger.get("timezone", "UTC"),
        }
    else:
        wanted = {"Pattern": trigger.get("pattern")}
    return [
        Violation(
            "LFG-SPEC-002", f"{prop} is {eprops.get(prop)!r} in the template but {value!r} in the spec",
            f"{loc}.Properties.{prop}",
        )
        for prop, value in wanted.items()
        if eprops.get(prop) != value
    ]


def _unlisted(keys, allowed, base: str, what: str) -> list[Violation]:
    return [
        Violation("LFG-TPL-003", f"{what} {key!r} is not on the allow-list", f"{base}.{key}")
        for key in keys
        if key not in allowed
    ]


def _check_allow_lists(
    spec: dict, name: str, resource: dict, props: dict, catalogue: Catalogue,
) -> list[Violation]:
    base = f"{_TPL}Resources.{name}"
    out = _unlisted(resource, catalogue.allowed_function_attributes, base, "Function attribute")
    out += _unlisted(
        props, catalogue.allowed_function_properties, base + ".Properties", "Function property",
    )
    trigger = spec.get("trigger") if isinstance(spec.get("trigger"), dict) else {}
    ttype = trigger.get("type")
    expected_type = TRIGGER_EVENT_TYPES.get(ttype) if isinstance(ttype, str) else None
    events = props.get("Events")
    if expected_type is None or not isinstance(events, dict) or len(events) != 1:
        return out
    (event_name, event), = events.items()
    if not isinstance(event, dict) or event.get("Type") != expected_type:
        return out
    loc = f"{base}.Properties.Events.{event_name}"
    out += _unlisted(event, ("Type", "Properties"), loc, "Event key")
    eprops = event.get("Properties")
    if isinstance(eprops, dict):
        out += _unlisted(
            eprops, catalogue.allowed_event_properties.get(expected_type, frozenset()),
            loc + ".Properties", f"{expected_type} property",
        )
    return out


def check_template(spec: dict, template: dict, catalogue: Catalogue) -> list[Violation]:
    out = _check_sections(template, catalogue) + _check_resources(template, catalogue)
    function = get_function(template)
    if function is not None:
        name, props = function
        out += _check_settings(spec, name, props)
        out += _check_trigger(spec, name, props, catalogue)
        out += _check_allow_lists(spec, name, _resources(template)[name], props, catalogue)
    return out
