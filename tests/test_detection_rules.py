from detector import load_rules, evaluate_rules


def test_suspicious_event_matches_det_001_and_det_002():
    rules = load_rules()

    event = {
        "event_type": "process_creation",
        "parent_process_path": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
        "process_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell.exe -EncodedCommand ABC123",
    }

    matched_rules = evaluate_rules(event, rules)

    matched_rule_ids = {
        rule["rule_id"]
        for rule in matched_rules
    }

    assert "DET-001" in matched_rule_ids
    assert "DET-002" in matched_rule_ids


def test_benign_notepad_event_matches_nothing():
    rules = load_rules()

    event = {
        "event_type": "process_creation",
        "parent_process_path": r"C:\Windows\explorer.exe",
        "process_path": r"C:\Windows\System32\notepad.exe",
        "command_line": "notepad.exe test.txt",
    }

    matched_rules = evaluate_rules(event, rules)

    assert matched_rules == []


def test_encoded_powershell_without_winword_matches_only_det_002():
    rules = load_rules()

    event = {
        "event_type": "process_creation",
        "parent_process_path": r"C:\Windows\explorer.exe",
        "process_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell.exe -EncodedCommand ABC123",
    }

    matched_rules = evaluate_rules(event, rules)

    matched_rule_ids = {
        rule["rule_id"]
        for rule in matched_rules
    }

    assert "DET-002" in matched_rule_ids
    assert "DET-001" not in matched_rule_ids

def test_encoded_powershell_short_alias_should_match_det_002():
    rules = load_rules()

    event = {
        "event_type": "process_creation",
        "parent_process_path": r"C:\Windows\explorer.exe",
        "process_path": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell.exe -enc ABC123",
    }

    matched_rules = evaluate_rules(event, rules)

    matched_rule_ids = {
        rule["rule_id"]
        for rule in matched_rules
    }

    assert "DET-002" in matched_rule_ids