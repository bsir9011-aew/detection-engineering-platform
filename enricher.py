ASSET_CONTEXT = {
    "LAB-WIN01": {
        "asset_role": "laboratory",
        "asset_criticality": "low"
    }
}


def enrich_event(normalized_event: dict) -> dict:
    host = normalized_event.get("host")

    asset_data = ASSET_CONTEXT.get(host, {})

    return {
        **normalized_event,
        **asset_data
    }