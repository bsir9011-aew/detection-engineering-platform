import json
from pathlib import Path


EXCEPTIONS_DIR = Path("exceptions")


def load_exceptions() -> list[dict]:
    exceptions = []

    for exception_file in sorted(EXCEPTIONS_DIR.glob("*.json")):
        exception = json.loads(
            exception_file.read_text(encoding="utf-8")
        )

        exceptions.append(exception)

    return exceptions


def contains_ignore_case(value: str | None, expected: str) -> bool:
    if value is None:
        return False

    return expected.lower() in value.lower()


def exception_matches(
    event: dict,
    rule: dict,
    exception: dict
) -> bool:

    if exception.get("rule_id") != rule.get("rule_id"):
        return False

    conditions = exception.get("conditions", {})

    host_expected = conditions.get("host_contains")
    if host_expected and not contains_ignore_case(
        event.get("host"),
        host_expected
    ):
        return False

    user_expected = conditions.get("user_contains")
    if user_expected and not contains_ignore_case(
        event.get("user"),
        user_expected
    ):
        return False

    parent_expected = conditions.get("parent_process_contains")
    if parent_expected and not contains_ignore_case(
        event.get("parent_process_path"),
        parent_expected
    ):
        return False

    command_expected = conditions.get("command_line_contains")
    if command_expected and not contains_ignore_case(
        event.get("command_line"),
        command_expected
    ):
        return False

    return True

def find_matching_exception(
    event: dict,
    rule: dict,
    exceptions: list[dict]
) -> dict | None:

    for exception in exceptions:
        if exception_matches(event, rule, exception):
            return exception

    return None