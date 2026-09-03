import json
from pathlib import Path

from rule_validator import validate_rule


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