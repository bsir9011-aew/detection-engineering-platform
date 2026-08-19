# Detection Engineering Platform

A hands-on project focused on building a detection engineering platform from first principles.

The goal is not to build another SIEM from day one, but to understand and implement the complete path from endpoint activity to a validated security detection.

## Current architecture

User Activity
↓
Windows Endpoint
↓
Telemetry Sensor
↓
Sysmon Event
↓
Event Forwarder
↓
Detection Engineering Platform

## First milestone

Generate a process creation event on a Windows laboratory endpoint and successfully deliver it to the platform.

Example:

notepad.exe starts
↓
Sysmon Event ID 1
↓
Event Forwarder
↓
Platform receives the event

Expected fields:

- Timestamp
- Host
- User
- Image
- CommandLine
- ParentImage
- ProcessId
- ProcessGuid

## Project principles

- Understand the data before writing detections.
- Separate telemetry collection from detection logic.
- Treat detections as testable engineering artifacts.
- Validate the complete telemetry pipeline end-to-end.
- Measure false positives and false negatives.
- Build incrementally.

## Status

Architecture and laboratory design.
