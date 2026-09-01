def create_alert(
    event_id: int,
    enriched_event: dict,
    rule: dict
) -> dict:

    return {
        "event_id": event_id,
        "rule_id": rule.get("rule_id"),
        "rule_name": rule.get("name"),
        "severity": rule.get("severity"),
        "host": enriched_event.get("host"),
        "user": enriched_event.get("user"),
        "process_path": enriched_event.get("process_path"),
        "command_line": enriched_event.get("command_line")
    }

