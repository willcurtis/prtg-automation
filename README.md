# PRTG Creation Tool v4 — Nested Groups

This PowerShell script automates creation of **nested groups**, devices, and a default **Ping** sensor in Paessler PRTG.
It builds on v3 (robust logging + v2/classic fallbacks) and adds **GroupPath** support such as `Region/City/Role`.

---

## What’s New in v4

- **Nested group paths** via `GroupPath` (e.g., `EMEA/London/Switches`).
- Auto-reuse of existing groups at every level to avoid duplicates.
- Auto-correction when a `ParentGroupId` accidentally targets a **device** (it will use the device’s **parent group**).
- Same resilient behavior as v3: API v2 first, then classic fallback for creation **and** verification.
- Auto-logging to `logs/prtg_creation_tool_v4_YYYYMMDD_HHMMSS.log` (timestamped per run).

---

## Requirements

- **PowerShell 7+**.
- Access to the PRTG Application Server (API v2) and Core Server (classic API).
- Credentials:
  - API v2: **Bearer API key** with *Write/Full* rights.
  - Classic fallback: either the same API token or `-ClassicUser` + `-ClassicPasshash`.
- CSV with columns (any extra columns are ignored):
  - `DeviceName` (required)
  - `IP` (required)
  - **One** of the following targeting methods per row:
    - `GroupId` **OR**
    - `ParentGroupId` + `GroupPath` **OR**
    - `ParentGroupId` + `GroupName`

---

## CSV Examples

### A) Nested path under a known parent (recommended)
```csv
DeviceName,IP,GroupId,GroupName,ParentGroupId,GroupPath
edge-fw-01,10.194.10.100,,,,EMEA/London/Firewalls
branch-ap-17,10.194.10.101,,,,EMEA/London/Branch-APs
core-sw-01,10.194.10.102,,,,EMEA/London/Switches
```

### B) Device into an existing group ID
```csv
DeviceName,IP,GroupId,GroupName,ParentGroupId,GroupPath
core-sw-02,10.194.10.105,2375,,,
```

### C) Single-level group under a parent
```csv
DeviceName,IP,GroupId,GroupName,ParentGroupId,GroupPath
edge-fw-02,10.194.10.103,,Firewalls,2372,
```

---

## Usage

Run from the folder containing the script and your CSV:

```powershell
.\prtg_creation_tool_v4.ps1 `
  -BaseUrl "https://<prtg-host>:1616" `
  -ApiKey "<YOUR_API_KEY>" `
  -CsvPath ".\prtg-import.csv" `
  -ClassicBaseUrl "https://<prtg-host>:8443/" `
  [-ClassicUser "<USERNAME>"] `
  [-ClassicPasshash "<PASSHASH>"] `
  -SkipCertCheck `
  -Verbose
```

---

## Logging

Each run starts a transcript and logs to:

```
<ScriptFolder>\logs\prtg_creation_tool_v4_YYYYMMDD_HHMMSS.log
```

Example snippet:

```text
PowerShell transcript start
Logging to: C:\PRTG\logs\prtg_creation_tool_v4_20250822_101504.log
VERBOSE: Normalized BaseUrl => https://prtg-host:1616/api/v2
VERBOSE: Path segment 'EMEA' => group id 2401
VERBOSE: Path segment 'London' => group id 2402
Group resolved: 2403
Created device 'core-sw-01' (ID 2410)
✅ Ping sensor ensured for 'core-sw-01'.
```

---

## Notes

- **GroupPath** creates/reuses each segment in order.
- If a parent points to a **device**, the script adjusts to its **parent group**.
- v2 is attempted first; if not possible, the script falls back to classic API for creation and verification.
- Logs are timestamped and stored under a `logs` folder.
