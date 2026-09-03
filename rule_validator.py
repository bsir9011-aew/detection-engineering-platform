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
    return True