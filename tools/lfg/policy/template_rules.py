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


def _same(left, right) -> bool:
    return type(left) is type(right) and left == right


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


def check_template(spec: dict, template: dict, catalogue: Catalogue) -> list[Violation]:
    out = _check_resources(template, catalogue)
    function = get_function(template)
    if function is not None:
        name, props = function
        out += _check_settings(spec, name, props)
        out += _check_trigger(spec, name, props, catalogue)
    return out
