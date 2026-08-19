# Architecture

## Version 0.0.1

The first objective of the platform is intentionally small:

> Move one process creation event from a Windows laboratory endpoint into our own platform.

At this stage the system contains only three logical components:

```
LAB-WIN01
    ↓
  Sysmon
    ↓
Event Forwarder
    ↓
Our Platform
```

## 1. LAB-WIN01 and Sysmon

`LAB-WIN01` is the Windows laboratory endpoint where activity occurs.

Example:

```
user starts notepad.exe
        ↓
Windows creates a process
        ↓
Sysmon observes the activity
        ↓
Sysmon Event ID 1 is generated
```

### Responsibility

Sysmon is responsible for **observing endpoint activity and generating telemetry**.

For a process creation event we expect information such as:

* Timestamp
* Host
* User
* Image
* CommandLine
* ParentImage
* ProcessId
* ProcessGuid

### Not responsible for

Sysmon does not decide whether the activity is malicious.

Its job is to **observe and record**, not to detect.

---

## 2. Event Forwarder

The event currently exists on `LAB-WIN01`.

Our platform cannot analyze data that it has never received.

The Event Forwarder solves this problem.

```
Sysmon Event
    ↓
Event Forwarder
    ↓
Our Platform
```

### Responsibility

The Event Forwarder should:

1. Read selected events from the Windows endpoint.
2. Preserve the required event data.
3. Transport the events to the platform.

### Not responsible for

The Event Forwarder should not:

* decide whether PowerShell is malicious,
* generate security alerts,
* execute detection rules.

Those responsibilities belong to later layers.

This separation is intentional:

> Collection transports evidence. Detection interprets evidence.

---

## 3. Our Platform

At version `0.0.1`, the internal architecture of the platform is intentionally undefined.

The only requirement is:

> The platform must successfully receive an event sent by the Event Forwarder.

Storage, parsing, normalization, detection logic and alerting will be introduced only when they become necessary.

---

## First end-to-end milestone

The first successful test will be:

```
Start notepad.exe on LAB-WIN01
            ↓
Sysmon generates Event ID 1
            ↓
Event Forwarder reads the event
            ↓
Event Forwarder sends the event
            ↓
Our Platform receives the event
```

Success means that the platform can display the received event and identify at least:

* Host
* User
* Image
* ParentImage
* ProcessId
* ProcessGuid

## Design principle

Each component should have one clear responsibility.

The platform will be expanded incrementally only after the previous part of the pipeline is understood and working.

