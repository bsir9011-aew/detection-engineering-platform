def normalize_event(parsed_event: dict, source: str) -> dict:
    source_event_id = parsed_event.get("EventID")
    
    event_type = None

    if source == "sysmon" and source_event_id == "1":
        event_type = "process_creation" 
    
    return {
        "source": source,
        "source_event_id": parsed_event.get("EventID"),
        "event_type": event_type,
        "host": parsed_event.get("Computer"),
        "process_path": parsed_event.get("Image"),
        "command_line": parsed_event.get("CommandLine"),
        "parent_process_path": parsed_event.get("ParentImage"),
        "user": parsed_event.get("User"),
        "process_guid": parsed_event.get("ProcessGuid")
    }