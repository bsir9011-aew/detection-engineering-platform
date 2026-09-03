import json
import pytest
from pathlib import Path

from rule_validator import validate_rule, RuleValidationError


RULES_DIR = Path("rules")


def test_all_rules_are_valid():
    for rule_file in RULES_DIR.glob("*.json"):
        rule = json.loads(
            rule_file.read_text(encoding="utf-8")
        )

        validate_rule(rule)


def test_rule_ids_are_unique():
    seen_rule_ids = {}

    for rule_file in sorted(RULES_DIR.glob("*.json")):
        rule = json.loads(
            rule_file.read_text(encoding="utf-8")
        )

        rule_id = rule["rule_id"]

        assert rule_id not in seen_rule_ids, (
            f"Duplicate rule_id {rule_id}: "
            f"{seen_rule_ids[rule_id]} and {rule_file.name}"
        )

        seen_rule_ids[rule_id] = rule_file.name

def make_valid_rule():
    return {
        "rule_id": "DET-003",
        "name": "Test rule",
        "description": "Test",
        "severity": "high",
        "event_type": "process_creation",
        "conditions": {
            "process_contains": "powershell.exe"
        }
    }

def test_invalid_severity_is_rejected():
    rule = make_valid_rule()
    rule["severity"] = "banan"

    with pytest.raises(RuleValidationError):
        validate_rule(rule)


def test_invalid_event_type_is_rejected():
    rule = make_valid_rule()
    rule["event_type"] = "banana_event"

    with pytest.raises(RuleValidationError):
        validate_rule(rule)


def test_empty_conditions_are_rejected():
    rule = make_valid_rule()
    rule["conditions"] = {}

    with pytest.raises(RuleValidationError):
        validate_rule(rule)


def test_empty_name_is_rejected():
    rule = make_valid_rule()
    rule["name"] = "   "

    with pytest.raises(RuleValidationError):
        validate_rule(rule)


def test_invalid_rule_id_is_rejected():
    rule = make_valid_rule()
    rule["rule_id"] = "BANAN-003"

    with pytest.raises(RuleValidationError):
        validate_rule(rule)


def test_unknown_condition_is_rejected():
    rule = make_valid_rule()
    rule["conditions"] = {
        "banana_contains": "powershell.exe"
    }

    with pytest.raises(RuleValidationError):
        validate_rule(rule)