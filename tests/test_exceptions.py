from detector import load_rules
from exception_engine import (
    load_exceptions,
    find_matching_exception,
)


def test_legit_admin_task_matches_exc_001():
    rules = load_rules()
    exceptions = load_exceptions()

    rule = next(
        r for r in rules
        if r["rule_id"] == "DET-002"
    )

    event = {
        "host": "ADMIN-WS01",
        "user": r"DOMAIN\svc_automation",
        "parent_process_path": r"C:\Windows\System32\cmd.exe",
        "command_line": "powershell.exe -EncodedCommand LEGIT_ADMIN_TASK",
    }

    exception = find_matching_exception(
        event,
        rule,
        exceptions,
    )

    assert exception is not None
    assert exception["exception_id"] == "EXC-001"


def test_same_activity_on_user_workstation_does_not_match_exc_001():
    rules = load_rules()
    exceptions = load_exceptions()

    rule = next(
        r for r in rules
        if r["rule_id"] == "DET-002"
    )

    event = {
        "host": "USER-WS01",
        "user": r"DOMAIN\svc_automation",
        "parent_process_path": r"C:\Windows\System32\cmd.exe",
        "command_line": "powershell.exe -EncodedCommand LEGIT_ADMIN_TASK",
    }

    exception = find_matching_exception(
        event,
        rule,
        exceptions,
    )

    assert exception is None

def test_legit_admin_task_is_suppressed_by_exc_001():
    rules = load_rules()
    exceptions = load_exceptions()

    rule = next(
        r for r in rules
        if r["rule_id"] == "DET-002"
    )

    event = {
        "host": "ADMIN-WS01",
        "user": r"DOMAIN\svc_automation",
        "parent_process_path": r"C:\Windows\System32\cmd.exe",
        "command_line": "powershell.exe -EncodedCommand LEGIT_ADMIN_TASK",
    }

    exception = find_matching_exception(
        event,
        rule,
        exceptions,
    )

    assert exception is not None
    assert exception["exception_id"] == "EXC-001"

def test_malicious_task_on_admin_host_is_not_suppressed():
    rules = load_rules()
    exceptions = load_exceptions()

    rule = next(
        r for r in rules
        if r["rule_id"] == "DET-002"
    )

    event = {
        "host": "ADMIN-WS01",
        "user": r"DOMAIN\svc_automation",
        "parent_process_path": r"C:\Windows\System32\cmd.exe",
        "command_line": "powershell.exe -EncodedCommand MALICIOUS_PAYLOAD",
    }

    exception = find_matching_exception(
        event,
        rule,
        exceptions,
    )

    assert exception is None