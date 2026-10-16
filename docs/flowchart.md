# Command → backend flow

Every slash command and alert button passes through the same guard pipeline before any backend call is made.

## Request pipeline

```mermaid
flowchart TD
    A[Analyst types slash command or presses an alert button] --> B{Guild + channel allowed?}
    B -- no --> X[Ephemeral 'Access denied'<br/>audit: denied]
    B -- yes --> C{Role tier >= required tier?<br/>READ / TRIAGE / RESPONSE}
    C -- no --> X
    C -- yes --> D{Input validation<br/>incident number, IP, hostname, hunt target}
    D -- invalid --> Y[Ephemeral validation error]
    D -- valid --> E{Destructive action?<br/>close / isolate / unisolate}
    E -- no --> F[Call backend]
    E -- yes --> G{Host on deny-list?}
    G -- yes --> Z[Blocked<br/>audit: blocked]
    G -- no --> H[Confirm / Cancel buttons<br/>requester only, 60s]
    H -- cancel / timeout --> W[Cancelled<br/>audit: cancelled]
    H -- confirm --> F
    F --> I[Render embed in channel]
    I --> J[Audit: JSONL file + audit channel + Splunk HEC]
```

## Command → backend map

```mermaid
flowchart LR
    subgraph Discord["Discord"]
        L["/incident list"]
        S["/incident show"]
        C["/incident comment"]
        CL["/incident close"]
        EN["/enrich"]
        HU["/hunt"]
        IS["/isolate"]
        UN["/unisolate"]
        BTN["Alert buttons<br/>Acknowledge / Enrich / Isolate"]
    end

    subgraph DB["SQLite incident store"]
        D1["incidents"]
        D2["comments"]
    end

    subgraph SPL["Splunk"]
        P1["REST :8089<br/>POST /services/search/jobs/export"]
        P2["HEC :8088<br/>index soc_audit"]
        P3["Alert webhook"]
    end

    subgraph VIC["soc-victim (SSH as responder)"]
        V1["sudo soc-isolate"]
        V2["sudo soc-unisolate"]
    end

    subgraph TI["Threat intel (public IPs only)"]
        T1["AbuseIPDB /api/v2/check"]
        T2["VirusTotal /api/v3/ip_addresses/{ip}"]
    end

    P3 -- "POST /webhook/splunk" --> D1
    L --> D1
    S --> D1 & D2
    C --> D2
    CL --> D1 & D2
    EN --> T1 & T2
    EN -. "linked incident" .-> D2
    HU --> P1
    IS --> D1 --> V1
    UN --> D1 --> V2
    IS & UN -. "comment" .-> D2
    BTN --> D1
    BTN --> EN
    BTN --> IS
    Discord -. "every action" .-> P2
```

## `/isolate` sequence

```mermaid
sequenceDiagram
    actor Analyst
    participant Bot as SOC Bot
    participant DB as SQLite store
    participant VM as soc-victim
    participant HEC as Splunk HEC
    participant Audit as Audit log/channel

    Analyst->>Bot: /isolate host:soc-victim reason:... incident:12
    Bot->>Bot: RBAC (RESPONSE tier), validate hostname, deny-list
    Bot->>DB: get incident 12
    Bot->>Bot: resolve host in RESPONDER_HOSTS allow-list
    Bot-->>Analyst: Host card + [Confirm] [Cancel]
    Analyst->>Bot: Confirm
    Bot->>VM: SSH responder: sudo -n /usr/local/sbin/soc-isolate
    VM-->>Bot: exit 0 "isolated"
    Bot->>DB: add comment to incident 12
    Bot-->>Analyst: Isolation completed
    Bot->>Audit: device.isolate success
    Bot->>HEC: forward audit entry
```

## Alert intake sequence

```mermaid
sequenceDiagram
    participant SP as Splunk alert
    participant W as Webhook receiver
    participant DB as SQLite store
    participant D as Discord alerts channel

    SP->>W: POST /webhook/splunk (secret, JSON)
    W->>W: constant-time secret check, size limit, validate fields
    W->>DB: insert incident
    W->>D: embed + Acknowledge / Enrich / Isolate buttons
    W-->>SP: 201 {"id": 12}
```
