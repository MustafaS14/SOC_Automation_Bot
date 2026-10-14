# Command → Azure REST API flow

Every slash command passes through the same guard pipeline before any API call is made.

## Request pipeline

```mermaid
flowchart TD
    A[Analyst types slash command in Discord] --> B{Guild + channel allowed?}
    B -- no --> X[Ephemeral 'Access denied'<br/>audit: denied]
    B -- yes --> C{Role tier >= required tier?<br/>READ / TRIAGE / RESPONSE}
    C -- no --> X
    C -- yes --> D{Input validation<br/>incident ref, IP, hostname}
    D -- invalid --> Y[Ephemeral validation error]
    D -- valid --> E{Destructive action?<br/>close / isolate / unisolate}
    E -- no --> F[Call Azure API]
    E -- yes --> G{Host on deny-list?}
    G -- yes --> Z[Blocked<br/>audit: blocked]
    G -- no --> H[Confirm / Cancel buttons<br/>requester only, 60s]
    H -- cancel / timeout --> W[Cancelled<br/>audit: cancelled]
    H -- confirm --> F
    F --> I[Render embed in channel]
    I --> J[Audit: JSONL file + audit channel]
```

## Command → endpoint map

```mermaid
flowchart LR
    subgraph Discord["Discord slash commands"]
        L["/incident list"]
        S["/incident show"]
        C["/incident comment"]
        CL["/incident close"]
        EN["/enrich"]
        IS["/isolate"]
        UN["/unisolate"]
    end

    subgraph AAD["Microsoft Entra ID (DefaultAzureCredential)"]
        T1["token: management.azure.com/.default"]
        T2["token: api.securitycenter.microsoft.com/.default"]
    end

    subgraph ARM["Microsoft Sentinel REST API<br/>management.azure.com/.../workspaces/{ws}/providers/Microsoft.SecurityInsights"]
        A1["GET /incidents?$filter&$orderby&$top"]
        A2["GET /incidents/{id}"]
        A3["POST /incidents/{id}/entities"]
        A4["PUT /incidents/{id}/comments/{commentId}"]
        A5["PUT /incidents/{id}<br/>status=Closed + classification + etag"]
    end

    subgraph MDE["Defender for Endpoint API<br/>api.securitycenter.microsoft.com"]
        M1["GET /api/machines?$filter=startswith(computerDnsName,...)"]
        M2["POST /api/machines/{id}/isolate"]
        M3["POST /api/machines/{id}/unisolate"]
    end

    subgraph TI["Threat intel (public IPs only)"]
        V1["AbuseIPDB GET /api/v2/check"]
        V2["VirusTotal GET /api/v3/ip_addresses/{ip}"]
    end

    L --> A1
    S --> A1 & A2 --> A3
    C --> A1 --> A4
    CL --> A1 --> A5
    EN --> V1 & V2
    IS --> M1 --> M2
    UN --> M1 --> M3
    IS --> A1
    UN --> A1
    IS --> A4
    UN --> A4

    A1 & A2 & A3 & A4 & A5 -.-> T1
    M1 & M2 & M3 -.-> T2
```

> Incident numbers (e.g. `1042`) are resolved to incident GUIDs with
> `GET /incidents?$filter=properties/incidentNumber eq 1042`; GUIDs go straight to `GET /incidents/{id}`.

## `/isolate` sequence

```mermaid
sequenceDiagram
    actor Analyst
    participant Bot as SOC Bot
    participant Entra as Entra ID
    participant Sentinel as Sentinel API
    participant MDE as Defender API
    participant Audit as Audit log/channel

    Analyst->>Bot: /isolate host:ws-fin-017 reason:... incident:1042
    Bot->>Bot: RBAC (RESPONSE tier), validate hostname, deny-list
    Bot->>Entra: get_token(ARM), get_token(MDE)
    Bot->>Sentinel: GET /incidents?$filter=incidentNumber eq 1042
    Bot->>MDE: GET /api/machines?$filter=startswith(computerDnsName,'ws-fin-017')
    Bot-->>Analyst: Device card + [Confirm] [Cancel]
    Analyst->>Bot: Confirm
    Bot->>MDE: POST /api/machines/{id}/isolate {Comment, IsolationType}
    MDE-->>Bot: MachineAction (Pending)
    Bot->>Sentinel: PUT /incidents/{id}/comments/{guid}
    Bot-->>Analyst: Action submitted (action ID)
    Bot->>Audit: device.isolate success
```
