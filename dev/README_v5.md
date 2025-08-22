# PRTG Creation Tool v5 — Config File Support

This PowerShell script automates creation of **groups** (including nested paths), **devices**, and a default **Ping sensor** in Paessler PRTG.  
It extends v4 by introducing **config file support** (YAML or JSON), optional **JSON run summaries**, and the ability to override settings via CLI.

---

## What’s New in v5
- Supports **YAML or JSON config files** with `-ConfigPath`.
- CLI arguments override config file values.
- If `prtg.apiKey` is empty in the config, the script checks `$env:PRTG_API_KEY`.
- Optional **machine-readable JSON summary** of the run.
- Keeps all v4 features (nested groups, classic API fallback, auto-logging).

---

## Requirements
- PowerShell 7+
- PRTG API v2 (Application Server, port 1616) + classic API (Core Server, usually port 443/8443).
- A user with **write rights** on the target PRTG groups.
- **If using YAML config:** `powershell-yaml` module (`Install-Module powershell-yaml`).

---

## Config File Options

### YAML (`config_v5.yaml`)
```yaml
prtg:
  baseUrl: "https://prtg.example.com:1616"
  apiKey: ""                     # leave blank to use $env:PRTG_API_KEY
  classicBaseUrl: "https://prtg.example.com:8443/"
  classicUser: ""
  classicPasshash: ""
  skipCertCheck: true

logging:
  logPath: "C:\PRTG\logs"
  verbose: true
  jsonSummaryPath: "C:\PRTG\logs\run-summary.json"

defaults:
  parentGroupId: "2372"
  sensorType: "ping"
  scanAfterCreate: true

csv:
  path: ".\prtg-import.csv"

behavior:
  whatIf: false
  parallel: false
  maxConcurrency: 6
  retry:
    attempts: 2
    backoffSeconds: 2
```

### JSON (`config_v5.json`)
```json
{
  "prtg": {
    "baseUrl": "https://prtg.example.com:1616",
    "apiKey": "",
    "classicBaseUrl": "https://prtg.example.com:8443/",
    "classicUser": "",
    "classicPasshash": "",
    "skipCertCheck": true
  },
  "logging": {
    "logPath": "C:\PRTG\logs",
    "verbose": true,
    "jsonSummaryPath": "C:\PRTG\logs\run-summary.json"
  },
  "defaults": {
    "parentGroupId": "2372",
    "sensorType": "ping",
    "scanAfterCreate": true
  },
  "csv": {
    "path": ".\prtg-import.csv"
  },
  "behavior": {
    "whatIf": false,
    "parallel": false,
    "maxConcurrency": 6,
    "retry": { "attempts": 2, "backoffSeconds": 2 }
  }
}
```

---

## Usage

### Using YAML config
```powershell
# Requires powershell-yaml module
Install-Module powershell-yaml -Scope CurrentUser

.\prtg_creation_tool_v5.ps1 -ConfigPath .\config_v5.yaml
```

### Using JSON config
```powershell
.\prtg_creation_tool_v5.ps1 -ConfigPath .\config_v5.json
```

### CLI overrides
CLI flags override config values:
```powershell
.\prtg_creation_tool_v5.ps1 -ConfigPath .\config_v5.json -Verbose -CsvPath .\custom.csv
```

---

## Logs & Summary
- Logs always written to `<script>\logs\prtg_creation_tool_v5_YYYYMMDD_HHMMSS.log`
- If `logging.jsonSummaryPath` is set, script also writes run results to that JSON file:
```json
[
  {
    "DeviceName": "edge-fw-01",
    "IP": "10.194.10.100",
    "GroupId": "2403",
    "DeviceId": "2410",
    "PingAdded": true
  }
]
```

---

## CSV Format
CSV must contain:
- `DeviceName`
- `IP`
- One of:
  - `GroupId`
  - `ParentGroupId` + `GroupPath`
  - `ParentGroupId` + `GroupName`

Example:
```csv
DeviceName,IP,GroupId,GroupName,ParentGroupId,GroupPath
edge-fw-01,10.194.10.100,,,,EMEA/London/Firewalls
```

---

## Security
- Don’t commit API keys or passhashes to Git.  
- Use `$env:PRTG_API_KEY` if possible.  
- YAML/JSON configs are for convenience; ensure access permissions are restricted.
