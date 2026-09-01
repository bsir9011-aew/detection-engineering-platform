from pathlib import Path
import json

RAW_DIR = Path("data/raw")
RAW_DIR.mkdir(parents=True, exist_ok=True)
META_DIR = Path("data/meta")
META_DIR.mkdir(parents=True, exist_ok=True)
PARSED_DIR = Path("data/parsed")
PARSED_DIR.mkdir(parents=True, exist_ok=True)
NORMALIZED_DIR = Path("data/normalized")
NORMALIZED_DIR.mkdir(parents=True, exist_ok=True)
ENRICHED_DIR = Path("data/enriched")
ENRICHED_DIR.mkdir(parents=True, exist_ok=True)
ALERTS_DIR = Path("data/alerts")
ALERTS_DIR.mkdir(parents=True, exist_ok=True)


def get_next_event_id():
    event_files = RAW_DIR.glob("event_*.json")

    ids = [
        int(file.stem.split("_")[1])
        for file in event_files
    ]

    return max(ids, default=0) + 1


def save_raw_event(event_data: dict):
    event_id = get_next_event_id()

    stored_event = {
        "event_id": event_id,
        **event_data
    }

    file_path = RAW_DIR / f"event_{event_id:06d}.json"

    file_path.write_text(
        json.dumps(stored_event, indent=2),
        encoding="utf-8"
    )

    return event_id

def save_processing_status(
    event_id: int,
    parsing_status: str,
    normalization_status: str,
    enrichment_status: str,
    detection_status: str
):
    metadata = {
        "event_id": event_id,
        "parsing_status": parsing_status,
        "normalization_status": normalization_status,
        "enrichment_status": enrichment_status,
        "detection_status": detection_status
    }

    file_path = META_DIR / f"event_{event_id:06d}.json"

    file_path.write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8"
    )

def save_parsed_event(event_id: int, parsed_data: dict):
    stored_event = {
        "event_id": event_id,
        **parsed_data
    }

    file_path = PARSED_DIR / f"event_{event_id:06d}.json"

    file_path.write_text(
        json.dumps(stored_event, indent=2),
        encoding="utf-8"
    )

def save_normalized_event(event_id: int, normalized_data: dict):
    stored_event = {
        "event_id": event_id,
        **normalized_data
    }

    file_path = NORMALIZED_DIR / f"event_{event_id:06d}.json"

    file_path.write_text(
        json.dumps(stored_event, indent=2),
        encoding="utf-8"
    )

def save_enriched_event(event_id: int, enriched_data: dict):
    stored_event = {
        "event_id": event_id,
        **enriched_data
    }

    file_path = ENRICHED_DIR / f"event_{event_id:06d}.json"

    file_path.write_text(
        json.dumps(stored_event, indent=2),
        encoding="utf-8"
    )
def get_next_alert_id():
    alert_files = ALERTS_DIR.glob("alert_*.json")

    ids = [
        int(file.stem.split("_")[1])
        for file in alert_files
    ]

    return max(ids, default=0) + 1


def save_alert(alert_data: dict):
    alert_id = get_next_alert_id()

    stored_alert = {
        "alert_id": alert_id,
        **alert_data
    }

    file_path = ALERTS_DIR / f"alert_{alert_id:06d}.json"

    file_path.write_text(
        json.dumps(stored_alert, indent=2),
        encoding="utf-8"
    )

    return alert_id