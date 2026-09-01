import xml.etree.ElementTree as ET


class EventParseError(Exception):
    pass


def parse_raw_event(raw_event: str) -> dict:
    try:
        root = ET.fromstring(raw_event)
    except ET.ParseError as error:
        raise EventParseError(str(error)) from error

    event_id = root.findtext("./System/EventID")
    computer = root.findtext("./System/Computer")

    event_data = {}

    for data in root.findall("./EventData/Data"):
        name = data.attrib.get("Name")

        if name:
            event_data[name] = data.text

    return {
       "EventID": event_id,
       "Computer": computer,
       **event_data
}