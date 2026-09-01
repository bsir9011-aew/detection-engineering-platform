from fastapi import FastAPI
from pydantic import BaseModel

from storage import (
    save_raw_event,
    save_processing_status,
    save_parsed_event,
    save_normalized_event,
    save_enriched_event,
    save_alert,
)

from parser import parse_raw_event, EventParseError
from normalizer import normalize_event
from enricher import enrich_event
from detector import load_rules, evaluate_rules
from alert_engine import create_alert
from exception_engine import (
    load_exceptions,
    find_matching_exception,
)


app = FastAPI()


class EventIn(BaseModel):
    source: str
    host: str
    raw_event: str


@app.post("/events", status_code=201)
def create_event(event: EventIn):

    # 1. RAW - source of truth
    event_id = save_raw_event(event.model_dump())

    parsing_status = "pending"
    normalization_status = "not_started"
    enrichment_status = "not_started"
    detection_status = "not_started"

    alert_ids = []
    exception_ids = []

    save_processing_status(
        event_id,
        parsing_status,
        normalization_status,
        enrichment_status,
        detection_status,
    )

    # 2. PARSING
    try:
        parsed_event = parse_raw_event(event.raw_event)

        save_parsed_event(
            event_id,
            parsed_event,
        )

        parsing_status = "parsed"
        normalization_status = "pending"

    except EventParseError:
        parsing_status = "failed"

        save_processing_status(
            event_id,
            parsing_status,
            normalization_status,
            enrichment_status,
            detection_status,
        )

        return {
            "event_id": event_id,
            "status": "stored",
            "parsing_status": parsing_status,
            "normalization_status": normalization_status,
            "enrichment_status": enrichment_status,
            "detection_status": detection_status,
            "alert_ids": alert_ids,
        }

    save_processing_status(
        event_id,
        parsing_status,
        normalization_status,
        enrichment_status,
        detection_status,
    )

    # 3. NORMALIZATION
    try:
        normalized_event = normalize_event(
            parsed_event,
            event.source,
        )

        save_normalized_event(
            event_id,
            normalized_event,
        )

        normalization_status = "normalized"
        enrichment_status = "pending"

    except Exception:
        normalization_status = "failed"

        save_processing_status(
            event_id,
            parsing_status,
            normalization_status,
            enrichment_status,
            detection_status,
        )

        return {
            "event_id": event_id,
            "status": "stored",
            "parsing_status": parsing_status,
            "normalization_status": normalization_status,
            "enrichment_status": enrichment_status,
            "detection_status": detection_status,
            "alert_ids": alert_ids,
        }

    save_processing_status(
        event_id,
        parsing_status,
        normalization_status,
        enrichment_status,
        detection_status,
    )

    # 4. ENRICHMENT
    try:
        enriched_event = enrich_event(normalized_event)

        save_enriched_event(
            event_id,
            enriched_event,
        )

        enrichment_status = "enriched"
        detection_status = "pending"

    except Exception:
        enrichment_status = "failed"

        save_processing_status(
            event_id,
            parsing_status,
            normalization_status,
            enrichment_status,
            detection_status,
        )

        return {
            "event_id": event_id,
            "status": "stored",
            "parsing_status": parsing_status,
            "normalization_status": normalization_status,
            "enrichment_status": enrichment_status,
            "detection_status": detection_status,
            "alert_ids": alert_ids,
        }

    save_processing_status(
        event_id,
        parsing_status,
        normalization_status,
        enrichment_status,
        detection_status,
    )

    # 5. DETECTION - wszystkie reguły + exceptions
    try:
        rules = load_rules()
        exceptions = load_exceptions()

        matched_rules = evaluate_rules(
            enriched_event,
            rules,
        )

        if matched_rules:
            detection_status = "matched"

            for rule in matched_rules:

                matching_exception = find_matching_exception(
                    enriched_event,
                    rule,
                    exceptions,
                )

                if matching_exception:
                    exception_ids.append(
                        matching_exception["exception_id"]
                    )

                    continue

                alert = create_alert(
                    event_id,
                    enriched_event,
                    rule,
                )

                alert_id = save_alert(alert)
                alert_ids.append(alert_id)

        else:
            detection_status = "no_match"

    except Exception:
        detection_status = "failed"

    # 6. Końcowy stan pipeline'u
    save_processing_status(
        event_id,
        parsing_status,
        normalization_status,
        enrichment_status,
        detection_status,
    )

    return {
        "event_id": event_id,
        "status": "stored",
        "parsing_status": parsing_status,
        "normalization_status": normalization_status,
        "enrichment_status": enrichment_status,
        "detection_status": detection_status,
        "alert_ids": alert_ids,
        "exception_ids": exception_ids,
    }