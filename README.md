# PRTG Creation Tool v3

This PowerShell script automates creation of groups, devices, and Ping sensors in **Paessler PRTG** using the API.  
Version **v3** introduces **automatic logging** — each run creates a timestamped transcript log in a `logs/` folder next to the script.

---

## Features

- Creates groups under a probe or group (auto-detects type).
- Avoids duplicate groups by reusing existing ones.
- Creates devices in groups.
- Ensures each device has a Ping sensor (uses API v2 first, falls back to classic API).
- Logs all verbose output to a timestamped log file (`logs/prtg_creation_tool_v3_YYYYMMDD_HHMMSS.log`).

---

## Requirements

- **PowerShell 7+** (cross-platform compatible).
- Network connectivity to your PRTG server (both Application Server for API v2 and Core Server for classic API).
- A PRTG API key with **Write** (or Full) access, **or** a username + passhash for classic API fallback.
- CSV input file with required columns:
  - `DeviceName`
  - `IP`
  - `GroupId` *(optional)*
  - `GroupName` *(optional)*
  - `ParentGroupId` *(required if `GroupId` is not provided)*

Example `prtg-import.csv`:

```csv
DeviceName,IP,GroupId,GroupName,ParentGroupId
edge-fw-01,10.194.10.100,,Firewalls,2372
branch-ap-17,10.194.10.101,,Branch-APs,2372
core-sw-01,10.194.10.102,,Switches,2372
```

---

## Usage

Run the script from PowerShell:

```powershell
.\prtg_creation_tool_v3.ps1 `
  -BaseUrl "https://<prtg-host>:1616" `
  -ApiKey "<YOUR_API_KEY>" `
  -CsvPath ".\prtg-import.csv" `
  -ClassicBaseUrl "https://<prtg-host>:8443/" `
  [-ClassicUser "<USERNAME>"] `
  [-ClassicPasshash "<PASSHASH>"] `
  -SkipCertCheck `
  -Verbose
```

### Parameters

- **`-BaseUrl`**  
  The PRTG v2 API endpoint.  
  Accepts both forms: `https://host:1616` or `https://host:1616/api/v2`.

- **`-ApiKey`**  
  PRTG API key with sufficient rights.

- **`-CsvPath`**  
  Path to the CSV file describing groups/devices.

- **`-ClassicBaseUrl`**  
  URL for the classic Core Server API (usually HTTPS port 443 or 8443).

- **`-ClassicUser`, `-ClassicPasshash`** *(optional)*  
  Use instead of `-ApiKey` for classic fallback, if your build does not support token auth in the classic API.

- **`-SkipCertCheck`**  
  Bypass SSL validation (useful with self-signed certs).

- **`-Verbose`**  
  Prints detailed URLs and operations to console (already logged by default).

---

## Logs

Every run writes a transcript log to:

```
<ScriptFolder>\logs\prtg_creation_tool_v3_YYYYMMDD_HHMMSS.log
```

This includes verbose output and any warnings or errors.  

### Sample Log Snippet

```text
**********************
PowerShell transcript start
Start time: 20250222 15:43:00
Script path: C:\PRTG-Automation\prtg_creation_tool_v3.ps1
Logging to: C:\PRTG-Automation\logs\prtg_creation_tool_v3_20250222_154300.log
**********************

VERBOSE: Normalized BaseUrl => https://prtg-server:1616/api/v2
VERBOSE: ClassicBaseUrl => https://prtg-server:8443/
VERBOSE: Invoke-Prtg POST https://prtg-server:1616/api/v2/experimental/groups/2372/group
Group resolved: 2375
Created device 'edge-fw-01' (ID 2390)
✅ Ping sensor ensured for 'edge-fw-01'.

**********************
PowerShell transcript end
**********************
```

---

## Example Run

```powershell
PS C:\PRTG-Automation> .\prtg_creation_tool_v3.ps1 `
    -BaseUrl "https://prtg-server:1616" `
    -ApiKey "********" `
    -CsvPath ".\prtg-import.csv" `
    -ClassicBaseUrl "https://prtg-server:8443/" `
    -SkipCertCheck -Verbose
```

---

## Notes

- If API v2 calls fail (401/403/404), the script automatically falls back to the **classic API**.
- Ensure your API key or user account has **write rights** on the target probe/group.
- The log files provide a complete transcript of each run for auditing.
