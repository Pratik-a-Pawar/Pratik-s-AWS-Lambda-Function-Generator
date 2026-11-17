"""Template-level rules: resource set, naming, spec match, trigger, runtime and timeout.

Lab 02, part B. Rules served: LFG-TPL-001, LFG-TPL-002, LFG-TPL-003, LFG-TPL-004,
LFG-NAME-001, LFG-SPEC-002, LFG-TRG-001, LFG-RUN-001 and LFG-RUN-002. The brief is
labs/02-spec-and-policy/README.md; the checks are in tests/lfg/test_policy_template.py.

get_function and is_resource_reference are also used by iam_rules and config_rules, so write
them first. Locations below are
written relative to "template.yaml:" unless they start with "function.spec.yaml:"; <id> is
the function's logical ID and <event> the name of its event.
"""

from lfg.policy import Violation
from lfg.rules import Catalogue

FUNCTION_TYPE = "AWS::Serverless::Function"
ALLOWED_RUNTIMES = ("python3.13", "python3.14")
LONG_TIMEOUT_SECONDS = 60
TRIGGER_EVENT_TYPES = {"schedule": "ScheduleV2", "eventbridge": "EventBridgeRule"}
SERVERLESS_TRANSFORM = "AWS::Serverless-2016-10-31"
MACRO_KEY = "Fn::Transform"
STAGE_PARAMETERS = {"Stage": {"Type": "String", "AllowedValues": ["dev", "prod"]}}


def get_function(template: dict) -> tuple[str, dict] | None:
    """Return (logical ID, Properties) of the template's one function, or None.

    None unless template["Resources"] is a mapping holding exactly one resource that is a
    mapping whose Type is FUNCTION_TYPE. If that resource's Properties is missing or not a
    mapping, return {} for it: the function still exists, and the rules that read its
    properties then report what is missing.
    """
    raise NotImplementedError("Lab 02, part B: find the template's single function")


def is_resource_reference(entry, ids: frozenset[str]) -> bool:
    """Whether entry is a Ref or Fn::GetAtt naming a logical ID in the template's Resources.

    True only for a mapping with exactly one key, which is one of:
    - {"Ref": <id>}, with <id> a string in ids;
    - {"Fn::GetAtt": "<id>.<attribute>"} or {"Fn::GetAtt": [<id>, <attribute>]}, with <id> a
      string in ids and <attribute> a non-empty string.
    False for every other value, of any type. The template loader turns the short forms !Ref
    and !GetAtt into these long forms, and turns !GetAtt A.B into the list form.
    """
    raise NotImplementedError("Lab 02, part B: recognise a reference to a declared resource")


def check_template(spec: dict, template: dict, catalogue: Catalogue) -> list[Violation]:
    """Check the template's shape and its agreement with the spec.

    LFG-TPL-004, sections, transform, parameters and macros:
    - each top-level key not in catalogue.allowed_template_sections, at <key>;
    - Transform anything but exactly the string SERVERLESS_TRANSFORM, at Transform;
    - Parameters missing or not a mapping: one violation at Parameters. Otherwise a Stage
      parameter not exactly equal to STAGE_PARAMETERS["Stage"], at Parameters.Stage, and each
      other parameter, at Parameters.<name>;
    - every MACRO_KEY key anywhere in the template, inside mappings and lists, at the path to
      that key, for example Resources.LogGroup.Properties.Tags[0].Fn::Transform.

    LFG-TPL-002: a Globals section, at Globals. (Globals is on the section allow-list so that
    this rule, not LFG-TPL-004, reports it.)

    LFG-TPL-001: each resource whose Type is not on catalogue.allowed_resource_types, at
    Resources.<name>.Type; and, when get_function finds no function, one violation at
    Resources.

    When get_function finds the function, also:

    LFG-NAME-001: FunctionName not exactly {"Fn::Sub": "lfg-${Stage}-<spec name>"}, at
    Resources.<id>.Properties.FunctionName.

    LFG-RUN-001: Runtime not in ALLOWED_RUNTIMES, at Resources.<id>.Properties.Runtime.

    LFG-RUN-002: Timeout above LONG_TIMEOUT_SECONDS, at Resources.<id>.Properties.Timeout.

    LFG-SPEC-002, settings, each at Resources.<id>.Properties.<Property>:
    - Runtime differs from the spec's runtime;
    - Architectures is not a one-item list holding the spec's architecture;
    - Timeout or MemorySize differs from the spec's timeout or memory.

    LFG-TRG-001: the spec's trigger.type is not one of catalogue.enabled_triggers, at
    function.spec.yaml:trigger.type. The trigger checks below then do not run.

    LFG-SPEC-002, trigger, each a single violation that ends the trigger checks:
    - Events is not a mapping holding exactly one event: at Resources.<id>.Properties.Events;
    - the event's Type is not TRIGGER_EVENT_TYPES[trigger type]: at
      Resources.<id>.Properties.Events.<event>.Type.
    Then, at Resources.<id>.Properties.Events.<event>.Properties.<Property>, one violation for
    each event property that differs from the spec. A schedule compares ScheduleExpression with
    trigger.expression and ScheduleExpressionTimezone with trigger.timezone ("UTC" when the
    spec leaves it out); an eventbridge trigger compares Pattern with trigger.pattern.

    LFG-TPL-003, allow-lists:
    - each key of the function resource not in catalogue.allowed_function_attributes, at
      Resources.<id>.<key>;
    - each key of its Properties not in catalogue.allowed_function_properties, at
      Resources.<id>.Properties.<key>;
    - only when there is exactly one event and its Type is the one the trigger needs: each key
      of the event other than Type and Properties, at
      Resources.<id>.Properties.Events.<event>.<key>, and each key of the event's Properties
      not in catalogue.allowed_event_properties for that event type, at
      Resources.<id>.Properties.Events.<event>.Properties.<key>.

    Fail closed. Every section, resource, property and spec field read here can be any YAML
    value, or missing. None may raise an exception, and none may pass unless it is a shape the
    standard allows. The rows of tests/lfg/test_policy_template.py are the exact cases.
    """
    raise NotImplementedError("Lab 02, part B: check the template rules")
