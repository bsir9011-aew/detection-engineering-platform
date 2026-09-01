from detector import load_rules, evaluate_rule
from exception_engine import (
    load_exceptions,
    find_matching_exception,
)


rules = load_rules()
exceptions = load_exceptions()

det_002 = next(
    rule for rule in rules
    if rule["rule_id"] == "DET-002"
)


test_cases = [
    {
        "name": "attack_encodedcommand",
        "attack": True,
        "event": {
            "event_type": "process_creation",
            "host": "USER-WS01",
            "user": r"DOMAIN\pawel",
            "parent_process_path": r"C:\Windows\explorer.exe",
            "process_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -EncodedCommand ABC123",
        },
    },
    {
        "name": "attack_enc_alias",
        "attack": True,
        "event": {
            "event_type": "process_creation",
            "host": "USER-WS01",
            "user": r"DOMAIN\pawel",
            "parent_process_path": r"C:\Windows\explorer.exe",
            "process_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -enc ABC123",
        },
    },
    {
        "name": "benign_notepad",
        "attack": False,
        "event": {
            "event_type": "process_creation",
            "host": "USER-WS01",
            "user": r"DOMAIN\pawel",
            "parent_process_path": r"C:\Windows\explorer.exe",
            "process_path": r"C:\Windows\System32\notepad.exe",
            "command_line": "notepad.exe test.txt",
        },
    },
    {
        "name": "benign_admin_encoded_powershell",
        "attack": False,
        "event": {
            "event_type": "process_creation",
            "host": "ADMIN-WS01",
            "user": r"DOMAIN\svc_automation",
            "parent_process_path": r"C:\Windows\System32\cmd.exe",
            "process_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -EncodedCommand LEGIT_ADMIN_TASK",
        },
    },

    {
        "name": "attack_on_admin_host_not_approved_task",
        "attack": True,
        "event": {
            "event_type": "process_creation",
            "host": "ADMIN-WS01",
            "user": r"DOMAIN\svc_automation",
            "parent_process_path": r"C:\Windows\System32\cmd.exe",
            "process_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "command_line": "powershell.exe -EncodedCommand MALICIOUS_PAYLOAD",
         },
    },
]


def classify(attack: bool, detected: bool) -> str:
    if attack and detected:
        return "TP"

    if not attack and detected:
        return "FP"

    if attack and not detected:
        return "FN"

    return "TN"


rule_results = {
    "TP": 0,
    "FP": 0,
    "FN": 0,
    "TN": 0,
}

alert_results = {
    "TP": 0,
    "FP": 0,
    "FN": 0,
    "TN": 0,
}


for case in test_cases:
    event = case["event"]

    # 1. Czy sama reguła DET-002 matchuje?
    matched = evaluate_rule(
        event,
        det_002,
    )

    rule_result = classify(
        case["attack"],
        matched,
    )

    rule_results[rule_result] += 1

    # 2. Czy match został objęty wyjątkiem?
    matching_exception = None

    if matched:
        matching_exception = find_matching_exception(
            event,
            det_002,
            exceptions,
        )

    # Alert powstaje tylko:
    # MATCH + brak exception
    alert_generated = (
        matched
        and matching_exception is None
    )

    alert_result = classify(
        case["attack"],
        alert_generated,
    )

    alert_results[alert_result] += 1

    exception_id = (
        matching_exception["exception_id"]
        if matching_exception
        else None
    )

    print(
        case["name"],
        "-> rule:",
        rule_result,
        "| exception:",
        exception_id,
        "| alert:",
        alert_result,
    )


def print_metrics(title: str, results: dict):
    tp = results["TP"]
    fp = results["FP"]
    fn = results["FN"]
    tn = results["TN"]

    precision = (
        tp / (tp + fp)
        if (tp + fp)
        else 0
    )

    recall = (
        tp / (tp + fn)
        if (tp + fn)
        else 0
    )

    print()
    print(title)
    print("TP:", tp)
    print("FP:", fp)
    print("FN:", fn)
    print("TN:", tn)
    print("Precision:", round(precision, 3))
    print("Recall:", round(recall, 3))


print_metrics(
    "RULE QUALITY - before exceptions",
    rule_results,
)

print_metrics(
    "ALERT QUALITY - after exceptions",
    alert_results,
)