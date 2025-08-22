<#
.SYNOPSIS
 Create (or reuse) groups, add devices, and ensure a Ping sensor per device in PRTG.

.CSV COLUMNS
 DeviceName, IP, GroupId, GroupName, ParentGroupId
 - Use GroupId when known.
 - Otherwise provide GroupName + ParentGroupId (script will reuse existing child group by name or create it).

.PARAMETERS
 -BaseUrl         e.g. https://prtg.example.com:1616 or https://prtg.example.com:1616/api/v2
 -ApiKey          PRTG API key with write rights
 -CsvPath         Path to CSV
 -ClassicBaseUrl  e.g. https://prtg.example.com:443/   (Core UI/API). Optional; auto-inferred.
 -ClassicUser     (optional) classic API username (for username+passhash auth)
 -ClassicPasshash (optional) classic API passhash (see PRTG user account page)
 -SkipCertCheck   Ignore TLS validation (self-signed/lab)
 -Verbose         Show URLs and fallbacks being used

.NOTES
 PowerShell 7+. Uses API v2 experimental endpoints for groups/devices; Ping sensor via v2 if available, else classic.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [string]$BaseUrl,

  [Parameter(Mandatory)]
  [string]$ApiKey,

  [Parameter(Mandatory)]
  [string]$CsvPath,

  [string]$ClassicBaseUrl,
  [string]$ClassicUser,
  [string]$ClassicPasshash,

  [switch]$SkipCertCheck
)

# -------------------- Logging (auto-enabled) --------------------
# Create timestamped log file and capture verbose output by default.
# Logs directory: <script folder>\logs\prtg_creation_tool_v3_YYYYMMDD_HHMMSS.log

# Determine script root (prefer $PSScriptRoot in script context)
try {
  if ($PSScriptRoot) {
    $ScriptRoot = $PSScriptRoot
  } elseif ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
  } else {
    $ScriptRoot = (Get-Location).Path
  }
} catch {
  $ScriptRoot = (Get-Location).Path
}

# Build/ensure logs directory
try {
  $LogDir = Join-Path $ScriptRoot 'logs'
  if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
  }
} catch {
  # Fallback to current directory if we can't create under script root
  $LogDir = Join-Path (Get-Location).Path 'logs'
  if (-not (Test-Path -LiteralPath $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
  }
}

$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$global:PrtgLogFile = Join-Path $LogDir ("prtg_creation_tool_v3_{0}.log" -f $ts)

# Ensure Verbose messages are emitted
$VerbosePreference = 'Continue'

$global:TranscriptStarted = $false
try {
  Start-Transcript -Path $global:PrtgLogFile -Append -ErrorAction Stop | Out-Null
  $global:TranscriptStarted = $true
  Write-Verbose ("Transcript started: {0}" -f $global:PrtgLogFile)
  Write-Host ("Logging to: {0}" -f $global:PrtgLogFile)
} catch {
  Write-Warning ("Failed to start transcript: {0}" -f $_.Exception.Message)
  # Try one fallback in the temp directory
  try {
    $tmp = [System.IO.Path]::GetTempPath()
    $global:PrtgLogFile = Join-Path $tmp ("prtg_creation_tool_v3_{0}.log" -f $ts)
    Start-Transcript -Path $global:PrtgLogFile -Append -ErrorAction Stop | Out-Null
    $global:TranscriptStarted = $true
    Write-Verbose ("Transcript started (temp): {0}" -f $global:PrtgLogFile)
    Write-Host ("Logging to (temp): {0}" -f $global:PrtgLogFile)
  } catch {
    Write-Warning ("Failed to start transcript in temp: {0}" -f $_.Exception.Message)
  }
}

# Make an attempt to stop transcript on engine exit, in case of unhandled termination.
if ($global:TranscriptStarted) {
  try {
    Register-EngineEvent PowerShell.Exiting -Action { try { Stop-Transcript | Out-Null } catch {} } | Out-Null
  } catch {}
}
# ---------------------------------------------------------------



# -------------------- Globals / Cache --------------------

# --- Normalize BaseUrl to ALWAYS include /api/v2 (and no trailing slash)
# Accepts either:
#   https://host:1616
#   https://host:1616/
#   https://host:1616/api/v2
#   https://host:1616/api/v2/
if ($BaseUrl.EndsWith('/')) { $BaseUrl = $BaseUrl.TrimEnd('/') }
if ($BaseUrl -notmatch '/api/v2$') {
  $BaseUrl = "$BaseUrl/api/v2"
}
Write-Verbose ("Normalized BaseUrl => {0}" -f $BaseUrl)

# Infer ClassicBaseUrl from the v2 BaseUrl if not provided
if (-not $ClassicBaseUrl) {
  try {
    $u = [System.Uri]$BaseUrl
    # v2 often https://host:1616/api/v2 -> assume classic is https://host/
    $ClassicBaseUrl = ("{0}://{1}/" -f $u.Scheme, $u.Host)
  } catch {
    $ClassicBaseUrl = ($BaseUrl -replace "/api/v2.*","/")
  }
}
if (-not $ClassicBaseUrl.EndsWith('/')) { $ClassicBaseUrl += '/' }
Write-Verbose ("ClassicBaseUrl => {0}" -f $ClassicBaseUrl)

# Expose classic auth for helpers
$script:ClassicUser     = $ClassicUser
$script:ClassicPasshash = $ClassicPasshash

# Cache to avoid duplicate lookups/creates during one run
$script:GroupCache = @{}   # key: "<ParentGroupId>|<GroupName>" -> value: GroupId

# -------------------- Helpers --------------------

function New-AuthHeader {
  param([string]$Key)
  @{ "Authorization" = "Bearer $Key" }
}

function Invoke-Prtg {
  param(
    [ValidateSet('GET','POST','PATCH','DELETE')]
    [string]$Method,
    [string]$Path,            # should start with "/" e.g. "/experimental/groups/123/group"
    [hashtable]$Headers,
    $Body = $null
  )

  # Ensure exactly one slash between base and path
  $uri = $BaseUrl + ($Path.StartsWith('/') ? '' : '/') + $Path
  Write-Verbose ("Invoke-Prtg {0} {1}" -f $Method, $uri)

  try {
    if ($Body -ne $null) {
      $json = $Body | ConvertTo-Json -Depth 12
      if ($SkipCertCheck) {
        Invoke-RestMethod -Method $Method -Uri $uri -Headers $Headers -ContentType 'application/json' -Body $json -SkipCertificateCheck
      } else {
        Invoke-RestMethod -Method $Method -Uri $uri -Headers $Headers -ContentType 'application/json' -Body $json
      }
    } else {
      if ($SkipCertCheck) {
        Invoke-RestMethod -Method $Method -Uri $uri -Headers $Headers -SkipCertificateCheck
      } else {
        Invoke-RestMethod -Method $Method -Uri $uri -Headers $Headers
      }
    }
  } catch {
    $msg = $_.Exception.Message
    throw ("PRTG API v2 call failed ({0} {1}): {2}" -f $Method, $uri, $msg)
  }
}

function Invoke-ClassicApi {
  <#
    Robust Classic Core API GET.
    - Tries multiple path variants to survive reverse proxies (/prtg/) and non-standard setups.
    - Auth with either &apitoken=... OR &username=...&passhash=...
  #>
  param(
    [string]$PathWithQuery,       # e.g. "api/addsensor5.htm?id=1234&sensortype=ping"
    [string]$PathAlt = $null      # optional alternative path to try first
  )

  $base = $ClassicBaseUrl.TrimEnd('/') + '/'
  $candidates = @()

  if ($PathAlt) { $candidates += ($base + $PathAlt) }
  $candidates += ($base + $PathWithQuery)

  if ($PathWithQuery -like 'api/*') {
    $candidates += ($base + 'prtg/' + $PathWithQuery)              # /prtg/api/...
    $candidates += ($base + ($PathWithQuery -replace '^api/',''))  # bare path fallback
  }

  function Add-Auth {
    param([string]$u)
    if ($script:ClassicUser -and $script:ClassicPasshash) {
      $u + (&{ if ($u.Contains('?')){'&'}else{'?'} }) + ('username={0}&passhash={1}' -f `
         [System.Uri]::EscapeDataString($script:ClassicUser), [System.Uri]::EscapeDataString($script:ClassicPasshash))
    } else {
      $u + (&{ if ($u.Contains('?')){'&'}else{'?'} }) + ('apitoken={0}' -f [System.Uri]::EscapeDataString($ApiKey))
    }
  }

  $lastErr = $null
  foreach ($u in $candidates) {
    $uri = Add-Auth $u
    Write-Verbose ("Invoke-ClassicApi GET {0}" -f $uri)
    try {
      if ($SkipCertCheck) {
        Invoke-RestMethod -Method GET -Uri $uri -SkipCertificateCheck | Out-Null
      } else {
        Invoke-RestMethod -Method GET -Uri $uri | Out-Null
      }
      return  # success
    } catch {
      $lastErr = $_.Exception.Message
    }
  }

  throw ("Classic API call failed. Tried: {0}`nLast error: {1}" -f ($candidates -join ', '), $lastErr)
}

function Test-GroupExists {
  param([string]$GroupId, [hashtable]$Headers)
  if ([string]::IsNullOrWhiteSpace($GroupId)) { return $false }
  try {
    Invoke-Prtg -Method GET -Path ("/groups/{0}" -f $GroupId) -Headers $Headers | Out-Null
    return $true
  } catch {
    return $false
  }
}

function Find-ChildGroupByName {
  <#
    Returns the ID of a child group named $GroupName under $ParentGroupId, or $null if not found.
  #>
  param(
    [Parameter(Mandatory)] [string]$ParentGroupId,
    [Parameter(Mandatory)] [string]$GroupName,
    [Parameter(Mandatory)] [hashtable]$Headers
  )

  $cacheKey = ("{0}|{1}" -f $ParentGroupId, $GroupName)
  if ($script:GroupCache.ContainsKey($cacheKey)) {
    return $script:GroupCache[$cacheKey]
  }

  $safeName = $GroupName.Replace('"','\"')
  $filter = ('type = group and name = "{0}" and parentid = "{1}"' -f $safeName, $ParentGroupId)
  $filterEnc = [System.Uri]::EscapeDataString($filter)

  try {
    $result = Invoke-Prtg -Method GET -Path ("/experimental/objects?limit=50&filter={0}" -f $filterEnc) -Headers $Headers
    if ($result -and $result.Count -gt 0 -and $result[0].id) {
      $script:GroupCache[$cacheKey] = $result[0].id
      return $result[0].id
    }
  } catch {
    # ignore lookup errors; return null
  }
  return $null
}

function Add-GroupClassic {
  param([string]$ParentId, [string]$GroupName)
  $safe = [System.Uri]::EscapeDataString($GroupName)
  # addgroup2.htm creates a subgroup under a *group or probe*
  $q = ("api/addgroup2.htm?id={0}&name_={1}" -f $ParentId, $safe)
  Invoke-ClassicApi -PathWithQuery $q
}

function Add-DeviceClassic {
  param([string]$GroupId, [string]$DeviceName, [string]$IP)
  $safeName = [System.Uri]::EscapeDataString($DeviceName)
  $safeIP   = [System.Uri]::EscapeDataString($IP)
  # adddevice2.htm creates a device under a group
  $q = ("api/adddevice2.htm?id={0}&name_={1}&host_={2}" -f $GroupId, $safeName, $safeIP)
  Invoke-ClassicApi -PathWithQuery $q
}

function Ensure-Group {
  <#
    Resolution order:
      1) If GroupId provided and exists -> return it
      2) If GroupName+ParentGroupId provided -> try to FIND existing child group by name
      3) If not found -> CREATE a new child group under ParentGroupId
         - If ParentGroupId is a GROUP -> POST /experimental/groups/{id}/group
         - If ParentGroupId is a PROBE -> POST /experimental/probes/{id}/group
         - On ANY v2 failure -> fallback to classic addgroup2.htm
  #>
  param(
    [string]$GroupId,
    [string]$GroupName,
    [string]$ParentGroupId,
    [hashtable]$Headers
  )

  # 1) Is GroupId valid already?
  if (-not [string]::IsNullOrWhiteSpace($GroupId)) {
    try {
      Invoke-Prtg -Method GET -Path ("/groups/{0}" -f $GroupId) -Headers $Headers | Out-Null
      return $GroupId
    } catch { }
  }

  if ([string]::IsNullOrWhiteSpace($GroupName) -or [string]::IsNullOrWhiteSpace($ParentGroupId)) {
    throw "Insufficient info to resolve group. Provide GroupId or (GroupName + ParentGroupId)."
  }

  # 2) Try to find existing child group (works for both group/probe parents)
  $existing = Find-ChildGroupByName -ParentGroupId $ParentGroupId -GroupName $GroupName -Headers $Headers
  if ($existing) { return $existing }

  # 3) Determine parent type: group or probe?
  $isParentGroup = $false
  $isParentProbe = $false

  try {
    Invoke-Prtg -Method GET -Path ("/groups/{0}" -f $ParentGroupId) -Headers $Headers | Out-Null
    $isParentGroup = $true
  } catch {
    try {
      Invoke-Prtg -Method GET -Path ("/probes/{0}" -f $ParentGroupId) -Headers $Headers | Out-Null
      $isParentProbe = $true
    } catch { }
  }

  if (-not ($isParentGroup -or $isParentProbe)) {
    throw ("Parent ID {0} is neither a group nor a probe (or not visible to this API key)." -f $ParentGroupId)
  }

  $createPath = if ($isParentGroup) { "/experimental/groups/$ParentGroupId/group" } else { "/experimental/probes/$ParentGroupId/group" }

  # Try v2 create
  try {
    $resp = Invoke-Prtg -Method POST -Path $createPath -Headers $Headers -Body @{ basic = @{ name = $GroupName } }
    $newId = if ($resp -is [System.Array] -and $resp.Count -gt 0) { $resp[0].id } else { $resp.id }
    if (-not $newId) { throw "CreateGroup response did not include an id." }
    $script:GroupCache["{0}|{1}" -f $ParentGroupId, $GroupName] = $newId
    return $newId
  } catch {
    $em = $_.Exception.Message
    Write-Verbose ("v2 group create failed for '{0}' under '{1}': {2} — falling back to classic" -f $GroupName, $ParentGroupId, $em)
    # Classic fallback (works for parent group or probe)
    try {
      Add-GroupClassic -ParentId $ParentGroupId -GroupName $GroupName
      # Re-resolve
      $existing2 = Find-ChildGroupByName -ParentGroupId $ParentGroupId -GroupName $GroupName -Headers $Headers
      if ($existing2) {
        $script:GroupCache["{0}|{1}" -f $ParentGroupId, $GroupName] = $existing2
        return $existing2
      }
      throw "Classic addgroup2.htm reported success but group not found by lookup."
    } catch {
      $em2 = $_.Exception.Message
      throw ("Failed to create group '{0}' under parent '{1}': v2 error [{2}] ; classic error [{3}]" -f $GroupName, $ParentGroupId, $em, $em2)
    }
  }
}

function New-Device {
  <#
    POST /experimental/groups/{id}/device
    Body: { "basic": { "name": "<Device>", "host": "<IP>" } }
    Fallback to classic adddevice2.htm on ANY v2 failure.
  #>
  param(
    [string]$GroupId,
    [string]$DeviceName,
    [string]$IP,
    [hashtable]$Headers
  )

  $path = "/experimental/groups/$GroupId/device"
  $body = @{ basic = @{ name = $DeviceName; host = $IP } }

  try {
    $resp = Invoke-Prtg -Method POST -Path $path -Headers $Headers -Body $body
    if ($resp -is [System.Array] -and $resp.Count -gt 0 -and $resp[0].id) { return $resp[0].id }
    elseif ($resp.id) { return $resp.id }
    else { throw "CreateDevice response did not include an id." }
  } catch {
    $em = $_.Exception.Message
    Write-Verbose ("v2 device create failed for '{0}' in group '{1}': {2} — falling back to classic" -f $DeviceName, $GroupId, $em)
    try {
      Add-DeviceClassic -GroupId $GroupId -DeviceName $DeviceName -IP $IP
      # Resolve by searching device by name under group
      $safeName  = $DeviceName.Replace('"','\"')
      $filter    = ('type = device and name = "{0}" and parentid = "{1}"' -f $safeName, $GroupId)
      $filterEnc = [System.Uri]::EscapeDataString($filter)
      $r = Invoke-Prtg -Method GET -Path ("/experimental/objects?limit=10&filter={0}" -f $filterEnc) -Headers $Headers
      if ($r -and $r.Count -gt 0 -and $r[0].id) { return $r[0].id }
      throw "Classic adddevice2.htm reported success but device not found by lookup."
    } catch {
      $em2 = $_.Exception.Message
      throw ("Failed to create device '{0}' in group '{1}': v2 error [{2}] ; classic error [{3}]" -f $DeviceName, $GroupId, $em, $em2)
    }
  }
}

function Add-PingSensorV2 {
  <#
    Try API v2 experimental endpoint to create a Ping sensor:
    POST /experimental/devices/{id}/sensor
    Body: { "type": "ping", "basic": { "name": "Ping" } }
  #>
  param([string]$DeviceId, [hashtable]$Headers)

  $path = "/experimental/devices/$DeviceId/sensor"
  $body = @{ type = "ping"; basic = @{ name = "Ping" } }

  try {
    Invoke-Prtg -Method POST -Path $path -Headers $Headers -Body $body | Out-Null
    return $true
  } catch {
    $msg = $_.Exception.Message
    throw ("API v2 ping creation failed for device {0}: {1}" -f $DeviceId, $msg)
  }
}

function Add-PingSensorClassic {
  <#
    Fallback classic API:
    GET /api/addsensor5.htm?id=<deviceId>&sensortype=ping&apitoken=...
    (Invoke-ClassicApi also tries /prtg/api/... and bare path variants)
  #>
  param([string]$DeviceId)

  $q = ("api/addsensor5.htm?id={0}&sensortype=ping" -f $DeviceId)
  Invoke-ClassicApi -PathWithQuery $q
}

function Ensure-PingSensor {
  <#
    Ensure a device has a Ping sensor:
      1) Try v2 creation; if that fails, fall back to classic addsensor5.htm
      2) Verify presence via /experimental/objects filter
  #>
  param(
    [string]$DeviceId,
    [hashtable]$Headers
  )

  $created = $false

  try {
    Add-PingSensorV2 -DeviceId $DeviceId -Headers $Headers
    $created = $true
  } catch {
    Add-PingSensorClassic -DeviceId $DeviceId
    $created = $true
  }

  # Verify via v2 objects filter
  try {
    $filter = ('type = sensor and (tags contains "ping" or type_raw = "ping") and parentid = "{0}"' -f $DeviceId)
    $filterEnc = [System.Uri]::EscapeDataString($filter)
    $result = Invoke-Prtg -Method GET -Path ("/experimental/objects?limit=50&filter={0}" -f $filterEnc) -Headers $Headers
    return ($result -and $result.Count -gt 0)
  } catch {
    return $created
  }
}

function Start-DeviceScan {
  param([string]$DeviceId, [hashtable]$Headers)
  try {
    Invoke-Prtg -Method POST -Path "/devices/$DeviceId/scan" -Headers $Headers | Out-Null
  } catch {
    $msg = $_.Exception.Message
    Write-Warning ("Scan after creation failed for device {0}: {1}" -f $DeviceId, $msg)
  }
}

# -------------------- Main --------------------

if (-not (Test-Path -LiteralPath $CsvPath)) {
  throw ("CSV file not found: {0}" -f $CsvPath)
}

$headers = New-AuthHeader -Key $ApiKey
$rows    = Import-Csv -LiteralPath $CsvPath
$summary = [System.Collections.Generic.List[Object]]::new()

foreach ($row in $rows) {
  $deviceName    = ($row.DeviceName  | ForEach-Object { $_.ToString().Trim() })
  $ip            = ($row.IP          | ForEach-Object { $_.ToString().Trim() })
  $groupIdCsv    = $row.GroupId
  $groupName     = $row.GroupName
  $parentGroupId = $row.ParentGroupId

  if ([string]::IsNullOrWhiteSpace($deviceName) -or [string]::IsNullOrWhiteSpace($ip)) {
    Write-Warning ("Skipping row with missing DeviceName or IP: {0}" -f ($row | ConvertTo-Json -Compress))
    continue
  }

  try {
    $resolvedGroupId = Ensure-Group -GroupId $groupIdCsv -GroupName $groupName -ParentGroupId $parentGroupId -Headers $headers
    Write-Host ("Group resolved: {0}" -f $resolvedGroupId)

    $deviceId = New-Device -GroupId $resolvedGroupId -DeviceName $deviceName -IP $ip -Headers $headers
    Write-Host ("Created device '{0}' (ID {1})" -f $deviceName, $deviceId)

    $hasPing = Ensure-PingSensor -DeviceId $deviceId -Headers $headers
    if ($hasPing) {
      Write-Host ("✅ Ping sensor ensured for '{0}'." -f $deviceName)
    } else {
      Write-Warning ("⚠️  Could not verify Ping sensor for '{0}'." -f $deviceName)
    }

    # Optional: scan to initialize further sensors
    Start-DeviceScan -DeviceId $deviceId -Headers $headers

    $summary.Add([pscustomobject]@{
      DeviceName = $deviceName
      IP         = $ip
      GroupId    = $resolvedGroupId
      DeviceId   = $deviceId
      PingAdded  = $hasPing
    })
  } catch {
    $msg = $_.Exception.Message
    Write-Error ("{0}" -f $msg)
    $summary.Add([pscustomobject]@{
      DeviceName = $deviceName
      IP         = $ip
      GroupId    = $groupIdCsv
      DeviceId   = $null
      PingAdded  = $false
      Error      = $msg
    })
  }
}

$summary | Format-Table -AutoSize


# -------------------- End Logging --------------------
if ($global:TranscriptStarted) {
  try { Stop-Transcript | Out-Null } catch {}
}
# -----------------------------------------------------
