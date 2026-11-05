import xml.etree.ElementTree as ET


class EventParseError(Exception):
    pass


def parse_raw_event(raw_event: str) -> dict:
    try:
        root = ET.fromstring(raw_event)
    except ET.ParseError as error:
        raise EventParseError(str(error)) from error

    ns = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}

    event_id = root.findtext("./w:System/w:EventID", namespaces=ns)
    computer = root.findtext("./w:System/w:Computer", namespaces=ns)

    event_data = {}

    for data in root.findall("./w:EventData/w:Data", namespaces=ns):
        name = data.attrib.get("Name")

        if name:
            event_data[name] = data.text

    return {
       "EventID": event_id,
       "Computer": computer,
       **event_data
}