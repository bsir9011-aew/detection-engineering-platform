# Detection Engineering Platform

A hands-on project focused on building a detection engineering platform from first principles.

The goal is not to build another SIEM from day one, but to understand and implement the complete path from endpoint activity to a validated security detection.

## Current architecture

```text
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
