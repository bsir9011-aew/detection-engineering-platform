import re 

class RuleValidationError(Exception):
    pass

REQUIRED_FIELDS = {
    "rule_id": str,
    "name": str,
    "description": str,
    "severity": str,
    "event_type": str,
    "conditions": dict,
}

ALLOWED_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}

ALLOWED_EVENT_TYPES = {
    "process_creation",
}

ALLOWED_CONDITION_KEYS = {
    "parent_process_contains",
    "process_contains",
    "command_line_contains",
    "command_line_contains_any"
}

def validate_rule(rule: dict) -> bool:
    for field, expected_type in REQUIRED_FIELDS.items():

        if field not in rule:
            raise RuleValidationError(
                f"Missing required fields: {field}"
            )
        if not isinstance(rule[field], expected_type):
            raise RuleValidationError(
                f"Field '{field}' must be {expected_type.__name__}"
            )

        if rule["severity"] not in ALLOWED_SEVERITIES:
            raise RuleValidationError(
                f"Invalid severity: {rule['severity']}"
        )

        if rule["event_type"] not in ALLOWED_EVENT_TYPES:
            raise RuleValidationError(
                f"Invalid event_type: {rule['event_type']}"
            )

        if not rule["conditions"]:
            raise RuleValidationError(
                "Conditions cannot be empty"
            )

        if not rule["name"].strip():
            raise RuleValidationError(
                "Name cannot be empty"
            )

        if not re.fullmatch(r"DET-\d{3}", rule["rule_id"]):
            raise RuleValidationError(
                f"Invalid rule_id format: {rule['rule_id']}"
            )


        unknown_conditions = (
            set(rule["conditions"]) - ALLOWED_CONDITION_KEYS
        )

        if unknown_conditions:
            raise RuleValidationError(
                f"Unknown conditions: {sorted(unknown_conditions)}"
            )

    return True