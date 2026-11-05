from parser import parse_raw_event


def test_parser_windows_namespace():
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <EventID>1</EventID>
            <Computer>WIN-LAB</Computer>
        </System>
        <EventData>
            <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
        </EventData>
    </Event>
    """

    result = parse_raw_event(xml)

    assert result["EventID"] == "1"
    assert result["Computer"] == "WIN-LAB"
    assert result["Image"] == r"C:\Windows\System32\cmd.exe"