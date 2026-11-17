"""Load and validate function specs against the JSON Schema.

Lab 02, part A. The brief is labs/02-spec-and-policy/README.md; the checks are
tests/lfg/test_spec.py and tests/lfg/test_cli_validate_spec.py.

`lfg validate-spec` and `lfg policy-check` (tools/lfg/cli.py, already written) call the two
functions below. Read cli.py to see what each command does with what you return or raise.
"""

from dataclasses import dataclass
from pathlib import Path

SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schemas" / "function-spec.schema.json"


class SpecLoadError(Exception):
    """The spec file is missing, is not valid YAML, or is not a mapping."""


@dataclass(frozen=True)
class SpecError:
    path: str
    message: str


def load_spec(path: Path) -> dict:
    """Read a function.spec.yaml and return its top-level mapping as a plain dict.

    Every value YAML reads as a date or a date and time, at any depth (for example an unquoted
    `expires: 2027-01-31`), is returned as its ISO 8601 string ("2027-01-31"). Later code then
    only ever sees strings, whether or not the author quoted the date.

    Raise SpecLoadError, with a one-line message that names the file, when:
    - the file cannot be read: it is missing, is a directory, or is not valid UTF-8;
    - the text is not valid YAML, including a date that cannot exist, such as 2027-02-30;
    - a mapping repeats a key, at any depth. Load with the loader in tools/lfg/yaml_util.py,
      and keep its error text in your message: it names the repeated key;
    - the document is nested too deeply for Python to read or convert;
    - the top level is not a mapping.

    These are the only outcomes for a bad file. The CLI turns SpecLoadError into exit code 2
    with a one-line message; any other exception would reach the user as a traceback.
    """
    raise NotImplementedError("Lab 02, part A: load the spec file, or raise SpecLoadError")


def validate_spec(spec: dict) -> list[SpecError]:
    """Validate spec against the JSON Schema at SCHEMA_PATH, which declares draft 2020-12.

    Return one SpecError per schema error, sorted by path. An empty list means the spec is
    valid; an invalid spec is never an exception.

    `path` says where the error is: mapping keys joined with dots and list indexes in
    brackets, for example "name", "trigger", "permissions[0].actions[0]" or
    "risk_acceptances[0].expires". An error about the top-level mapping itself (an unknown or
    a missing key) has the path "(root)". `message` is the validator's own message.
    """
    raise NotImplementedError("Lab 02, part A: validate the spec against the schema")
