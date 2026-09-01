import json
from pathlib import Path


RULES_DIR = Path("rules")


def load_rule(rule_path: str) -> dict:
    path = Path(rule_path)

    return json.loads(
        path.read_text(encoding="utf-8")
    )


def load_rules() -> list[dict]:
    rules = []

    for rule_file in sorted(RULES_DIR.glob("*.json")):
        rule = json.loads(
            rule_file.read_text(encoding="utf-8")
        )

        rules.append(rule)

    return rules


def contains_ignore_case(value: str | None, expected: str) -> bool:
    if value is None:
        return False

    return expected.lower() in value.lower()

def contains_any_ignore_case(
    value: str | None,
    expected_values: list[str]
) -> bool:

    if value is None:
        return False

    return any(
        expected.lower() in value.lower()
        for expected in expected_values
    )

def evaluate_rule(event: dict, rule: dict) -> bool:
    if event.get("event_type") != rule.get("event_type"):
        return False

    conditions = rule.get("conditions", {})

    parent_expected = conditions.get("parent_process_contains")
    if parent_expected and not contains_ignore_case(
        event.get("parent_process_path"),
        parent_expected
    ):
        return False

    process_expected = conditions.get("process_contains")
    if process_expected and not contains_ignore_case(
        event.get("process_path"),
        process_expected
    ):
        return False

    command_expected = conditions.get("command_line_contains")
    if command_expected and not contains_ignore_case(
        event.get("command_line"),
        command_expected
    ):
        return False

    command_expected_any = conditions.get("command_line_contains_any")
    if command_expected_any and not contains_any_ignore_case(
        event.get("command_line"),
        command_expected_any
    ):
        return False


    return True

def evaluate_rules(event: dict, rules: list[dict]) -> list[dict]:
    matched_rules = []

    for rule in rules:
        if evaluate_rule(event, rule):
            matched_rules.append(rule)

    return matched_rules