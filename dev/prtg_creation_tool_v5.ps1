<#
.SYNOPSIS
 PRTG Creation Tool v5 — Config support (YAML/JSON), nested groups, JSON summary

.DESCRIPTION
 - Creates/reuses groups (including nested paths), adds devices, and ensures a Ping sensor per device.
 - Reads settings from a YAML or JSON config file via -ConfigPath (CLI params override config).
 - Supports API v2 with robust fallback to classic API (creation + verification).
 - Automatic transcript logging to a timestamped log file.
 - Optional JSON summary export of the run results.

.CSV COLUMNS (v5)
 DeviceName, IP, GroupId, GroupName, ParentGroupId, GroupPath

.CONFIG (YAML or JSON)
 See sample files included alongside this script.
#>

[CmdletBinding(SupportsShouldProcess=$true)]
param(
  [string]$BaseUrl,
  [string]$ApiKey,
  [string]$CsvPath,
  [string]$ClassicBaseUrl,
  [string]$ClassicUser,
  [string]$ClassicPasshash,
  [switch]$SkipCertCheck,
  [string]$ConfigPath,
  [string]$LogPath,
  [switch]$VerboseEnabled,
  [string]$JsonSummaryPath
)

# -------------------- Load Config (optional) --------------------
$cfg = $null
if ($ConfigPath) {
  if (-not (Test-Path -LiteralPath $ConfigPath)) {
    throw ("Config file not found: {0}" -f $ConfigPath)
  }
  $ext = [System.IO.Path]::GetExtension($ConfigPath).ToLowerInvariant()
  switch ($ext) {
    '.yaml' { 
      try {
        Import-Module powershell-yaml -ErrorAction Stop
      } catch {
        throw "YAML config requested but module 'powershell-yaml' is not installed. Install-Module powershell-yaml"
      }
      $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Yaml
    }
    '.yml'  { 
      try {
        Import-Module powershell-yaml -ErrorAction Stop
      } catch {
        throw "YAML config requested but module 'powershell-yaml' is not installed. Install-Module powershell-yaml"
      }
      $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Yaml
    }
    '.json' {
      $cfg = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
    }
    default { throw ("Unsupported config extension: {0}. Use .yaml, .yml or .json" -f $ext) }
  }
}

function Coalesce { param($a,$b) if ($null -ne $a -and $a -ne '') { $a } else { $b } }

# Merge precedence: CLI params > config > defaults
# prtg.*
$BaseUrl        = Coalesce $BaseUrl        $cfg.prtg.baseUrl
$ApiKey         = Coalesce $ApiKey         $cfg.prtg.apiKey
$ClassicBaseUrl = Coalesce $ClassicBaseUrl $cfg.prtg.classicBaseUrl
$ClassicUser    = Coalesce $ClassicUser    $cfg.prtg.classicUser
$ClassicPasshash= Coalesce $ClassicPasshash$cfg.prtg.classicPasshash
if (-not $SkipCertCheck) { if ($cfg.prtg.skipCertCheck) { $SkipCertCheck = $true } }

# logging.*
$LogPath        = Coalesce $LogPath        $cfg.logging.logPath
$VerboseEnabled = $VerboseEnabled -or [bool]$cfg.logging.verbose
$JsonSummaryPath= Coalesce $JsonSummaryPath$cfg.logging.jsonSummaryPath

# defaults.*
$DefaultParentId= $cfg.defaults.parentGroupId
$DefaultSensor  = if ($cfg.defaults.sensorType) { $cfg.defaults.sensorType } else { 'ping' }
$ScanAfterCreate= if ($cfg.defaults.scanAfterCreate) { $true } else { $false }

# csv.*
$CsvPath        = Coalesce $CsvPath        $cfg.csv.path

# behavior.* (currently advisory)
$WhatIfCfg      = [bool]$cfg.behavior.whatIf
$Parallel       = [bool]$cfg.behavior.parallel
$MaxConc        = if ($cfg.behavior.maxConcurrency) { [int]$cfg.behavior.maxConcurrency } else { 6 }
$RetryAttempts  = if ($cfg.behavior.retry.attempts) { [int]$cfg.behavior.retry.attempts } else { 1 }
$RetryBackoff   = if ($cfg.behavior.retry.backoffSeconds) { [int]$cfg.behavior.retry.backoffSeconds } else { 2 }

# API key from environment if still empty
if (-not $ApiKey -or $ApiKey -eq '') {
  if ($env:PRTG_API_KEY) { $ApiKey = $env:PRTG_API_KEY }
}

# -------------------- Logging (auto-enabled) --------------------
# Timestamped log file; allows override via -LogPath or config.logging.logPath

try {
  if ($PSScriptRoot)      { $ScriptRoot = $PSScriptRoot }
  elseif ($MyInvocation -and $MyInvocation.MyCommand -and $MyInvocation.MyCommand.Path) {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
  } else { $ScriptRoot = (Get-Location).Path }
} catch { $ScriptRoot = (Get-Location).Path }

try {
  if (-not $LogPath -or $LogPath -eq '') { $LogPath = Join-Path $ScriptRoot 'logs' }
  if (-not (Test-Path -LiteralPath $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
} catch {
  $LogPath = Join-Path ([System.IO.Path]::GetTempPath()) 'prtg-logs'
  if (-not (Test-Path -LiteralPath $LogPath)) { New-Item -ItemType Directory -Path $LogPath -Force | Out-Null }
}

$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$global:PrtgLogFile = Join-Path $LogPath ("prtg_creation_tool_v5_{0}.log" -f $ts)

# Ensure Verbose behavior
if ($VerboseEnabled -or $PSBoundParameters.ContainsKey('Verbose')) {
  $VerbosePreference = 'Continue'
} else {
  # still capture verbose in transcript, but don't spam console unless -Verbose was supplied
  $VerbosePreference = 'SilentlyContinue'
}

$global:TranscriptStarted = $false
try {
  Start-Transcript -Path $global:PrtgLogFile -Append -ErrorAction Stop | Out-Null
  $global:TranscriptStarted = $true
  Write-Verbose ("Transcript started: {0}" -f $global:PrtgLogFile)
  Write-Host ("Logging to: {0}" -f $global:PrtgLogFile)
} catch {
  Write-Warning ("Failed to start transcript: {0}" -f $_.Exception.Message)
  try {
    $tmp = [System.IO.Path]::GetTempPath()
    $global:PrtgLogFile = Join-Path $tmp ("prtg_creation_tool_v5_{0}.log" -f $ts)
    Start-Transcript -Path $global:PrtgLogFile -Append -ErrorAction Stop | Out-Null
    $global:TranscriptStarted = $true
    Write-Verbose ("Transcript started (temp): {0}" -f $global:PrtgLogFile)
    Write-Host ("Logging to (temp): {0}" -f $global:PrtgLogFile)
  } catch {
    Write-Warning ("Failed to start transcript in temp: {0}" -f $_.Exception.Message)
  }
}

if ($global:TranscriptStarted) {
  try { Register-EngineEvent PowerShell.Exiting -Action { try { Stop-Transcript | Out-Null } catch {} } | Out-Null } catch {}
}

# -------------------- Globals / Cache --------------------

# Basic param validation
if (-not $BaseUrl)   { throw "BaseUrl is required (or set prtg.baseUrl in config)." }
if (-not $ApiKey)    { throw "ApiKey is required (or set prtg.apiKey in config, or env:PRTG_API_KEY)." }
if (-not $CsvPath)   { throw "CsvPath is required (or set csv.path in config)." }

# Normalize BaseUrl to ALWAYS include /api/v2 (and no trailing slash)
if ($BaseUrl.EndsWith('/')) { $BaseUrl = $BaseUrl.TrimEnd('/') }
if ($BaseUrl -notmatch '/api/v2$') { $BaseUrl = "$BaseUrl/api/v2" }
Write-Verbose ("Normalized BaseUrl => {0}" -f $BaseUrl)

# Infer ClassicBaseUrl from the v2 BaseUrl if not provided
if (-not $ClassicBaseUrl) {
  try {
    $u = [System.Uri]$BaseUrl
    $ClassicBaseUrl = ("{0}://{1}/" -f $u.Scheme, $u.Host)
  } catch {
    $ClassicBaseUrl = ($BaseUrl -replace "/api/v2.*","/")
  }
}
if (-not $ClassicBaseUrl.EndsWith('/')) { $ClassicBaseUrl += '/' }
Write-Verbose ("ClassicBaseUrl => {0}" -f $ClassicBaseUrl)

$script:ClassicUser     = $ClassicUser
$script:ClassicPasshash = $ClassicPasshash

# Caches
$script:GroupCache = @{}   # key: "<ParentId>|<GroupName>" -> GroupId
$script:ObjectTypeCache = @{}  # id -> type (probe/group/device)

# -------------------- Helpers --------------------

function New-AuthHeader { param([string]$Key) @{ "Authorization" = "Bearer $Key" } }

function Invoke-Prtg {
  param(
    [ValidateSet('GET','POST','PATCH','DELETE')] [string]$Method,
    [string]$Path, [hashtable]$Headers, $Body = $null
  )
  $uri = $BaseUrl + ($Path.StartsWith('/') ? '' : '/') + $Path
  Write-Verbose ("Invoke-Prtg {0} {1}" -f $Method, $uri)
  if ($PSCmdlet.ShouldProcess($uri, $Method)) {
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
}

function Invoke-ClassicApi {
  param([string]$PathWithQuery, [string]$PathAlt = $null)
  $base = $ClassicBaseUrl.TrimEnd('/') + '/'
  $candidates = @()
  if ($PathAlt) { $candidates += ($base + $PathAlt) }
  $candidates += ($base + $PathWithQuery)
  if ($PathWithQuery -like 'api/*') {
    $candidates += ($base + 'prtg/' + $PathWithQuery)
    $candidates += ($base + ($PathWithQuery -replace '^api/',''))
  }
  function Add-Auth { param([string]$u)
    if ($script:ClassicUser -and $script:ClassicPasshash) {
      $u + (&{ if ($u.Contains('?')){'&'}else{'?'} }) + ('username={0}&passhash={1}' -f [System.Uri]::EscapeDataString($script:ClassicUser), [System.Uri]::EscapeDataString($script:ClassicPasshash))
    } else {
      $u + (&{ if ($u.Contains('?')){'&'}else{'?'} }) + ('apitoken={0}' -f [System.Uri]::EscapeDataString($ApiKey))
    }
  }
  $lastErr = $null
  foreach ($u in $candidates) {
    $uri = Add-Auth $u
    Write-Verbose ("Invoke-ClassicApi GET {0}" -f $uri)
    if ($PSCmdlet.ShouldProcess($uri, "GET")) {
      try {
        if ($SkipCertCheck) { Invoke-RestMethod -Method GET -Uri $uri -SkipCertificateCheck | Out-Null }
        else { Invoke-RestMethod -Method GET -Uri $uri | Out-Null }
        return
      } catch { $lastErr = $_.Exception.Message }
    }
  }
  throw ("Classic API call failed. Tried: {0}`nLast error: {1}" -f ($candidates -join ', '), $lastErr)
}

function Invoke-ClassicApiJson {
  param([string]$PathWithQuery, [string]$PathAlt = $null)
  $base = $ClassicBaseUrl.TrimEnd('/') + '/'
  $candidates = @()
  if ($PathAlt) { $candidates += ($base + $PathAlt) }
  $candidates += ($base + $PathWithQuery)
  if ($PathWithQuery -like 'api/*') {
    $candidates += ($base + 'prtg/' + $PathWithQuery)
    $candidates += ($base + ($PathWithQuery -replace '^api/',''))
  }
  function Add-Auth { param([string]$u)
    if ($script:ClassicUser -and $script:ClassicPasshash) {
      $u + (&{ if ($u.Contains('?')){'&'}else{'?'} }) + ('username={0}&passhash={1}' -f [System.Uri]::EscapeDataString($script:ClassicUser), [System.Uri]::EscapeDataString($script:ClassicPasshash))
    } else {
      $u + (&{ if ($u.Contains('?')){'&'}else{'?'} }) + ('apitoken={0}' -f [System.Uri]::EscapeDataString($ApiKey))
    }
  }
  $lastErr = $null
  foreach ($u in $candidates) {
    $uri = Add-Auth $u
    Write-Verbose ("Invoke-ClassicApiJson GET {0}" -f $uri)
    # JSON reads are safe even in WhatIf; they don't change state
    try {
      if ($SkipCertCheck) { return Invoke-RestMethod -Method GET -Uri $uri -SkipCertificateCheck }
      else { return Invoke-RestMethod -Method GET -Uri $uri }
    } catch { $lastErr = $_.Exception.Message }
  }
  throw ("Classic API JSON call failed. Tried: {0}`nLast error: {1}" -f ($candidates -join ', '), $lastErr)
}

function Get-ObjectTypeClassic {
  param([string]$ObjId)
  if ($script:ObjectTypeCache.ContainsKey($ObjId)) { return $script:ObjectTypeCache[$ObjId] }
  try {
    $r = Invoke-ClassicApiJson -PathWithQuery ("api/table.json?content=probes&columns=objid&filter_objid={0}" -f $ObjId)
    $rows = $r.rows ?? $r
    if ($rows -and $rows.Count -gt 0) { $script:ObjectTypeCache[$ObjId]="probe"; return "probe" }
  } catch {}
  try {
    $r = Invoke-ClassicApiJson -PathWithQuery ("api/table.json?content=groups&columns=objid&filter_objid={0}" -f $ObjId)
    $rows = $r.rows ?? $r
    if ($rows -and $rows.Count -gt 0) { $script:ObjectTypeCache[$ObjId]="group"; return "group" }
  } catch {}
  try {
    $r = Invoke-ClassicApiJson -PathWithQuery ("api/table.json?content=devices&columns=objid&filter_objid={0}" -f $ObjId)
    $rows = $r.rows ?? $r
    if ($rows -and $rows.Count -gt 0) { $script:ObjectTypeCache[$ObjId]="device"; return "device" }
  } catch {}
  return $null
}

function Get-ParentIdClassic {
  param([string]$ObjId)
  $r = Invoke-ClassicApiJson -PathWithQuery ("api/table.json?content=all&columns=objid,parentid&filter_objid={0}" -f $ObjId)
  $rows = $r.rows ?? $r
  if ($rows -and $rows.Count -gt 0) { return $rows[0].parentid }
  return $null
}

function Find-ChildGroupByName {
  param([string]$ParentGroupId, [string]$GroupName, [hashtable]$Headers)
  $cacheKey = ("{0}|{1}" -f $ParentGroupId, $GroupName)
  if ($script:GroupCache.ContainsKey($cacheKey)) { return $script:GroupCache[$cacheKey] }

  # v2 lookup
  try {
    $safeName = $GroupName.Replace('"','\"')
    $filter = ('type = group and name = "{0}" and parentid = "{1}"' -f $safeName, $ParentGroupId)
    $filterEnc = [System.Uri]::EscapeDataString($filter)
    $result = Invoke-Prtg -Method GET -Path ("/experimental/objects?limit=50&filter={0}" -f $filterEnc) -Headers $Headers
    if ($result -and $result.Count -gt 0 -and $result[0].id) {
      $script:GroupCache[$cacheKey] = $result[0].id
      return $result[0].id
    }
  } catch {
    Write-Verbose ("v2 lookup failed for group '{0}' under '{1}', trying classic: {2}" -f $GroupName, $ParentGroupId, $_.Exception.Message)
  }

  # classic lookup
  try {
    $q = ("api/table.json?content=groups&columns=objid,parentid,name&filter_parentid={0}" -f $ParentGroupId)
    $json = Invoke-ClassicApiJson -PathWithQuery $q
    $rows = $json.rows ?? $json
    if ($rows) {
      $match = $rows | Where-Object { $_.name -eq $GroupName -and ($_.parentid -as [string]) -eq ($ParentGroupId -as [string]) } | Select-Object -First 1
      if ($match -and $match.objid) {
        $script:GroupCache[$cacheKey] = $match.objid
        return $match.objid
      }
    }
  } catch {
    Write-Verbose ("classic lookup failed for group '{0}' under '{1}': {2}" -f $GroupName, $ParentGroupId, $_.Exception.Message)
  }
  return $null
}

function Add-GroupClassic { param([string]$ParentId, [string]$GroupName)
  $safe = [System.Uri]::EscapeDataString($GroupName)
  $q = ("api/addgroup2.htm?id={0}&name_={1}" -f $ParentId, $safe)
  Invoke-ClassicApi -PathWithQuery $q
}

function Ensure-GroupSingleLevel {
  param([string]$GroupName, [string]$ParentId, [hashtable]$Headers)

  # Normalize ParentId: if device id passed, use its parent group
  if (-not [string]::IsNullOrWhiteSpace($ParentId)) {
    $ptype = Get-ObjectTypeClassic -ObjId $ParentId
    if ($ptype -eq "device") {
      $orig = $ParentId
      $ParentId = Get-ParentIdClassic -ObjId $ParentId
      Write-Verbose ("ParentGroupId {0} is a device; using its parent group {1} instead" -f $orig, $ParentId)
    }
  }

  # Try reuse
  $existing = Find-ChildGroupByName -ParentGroupId $ParentId -GroupName $GroupName -Headers $Headers
  if ($existing) { return $existing }

  # Determine parent type
  $isParentGroup = $false; $isParentProbe = $false
  try { Invoke-Prtg -Method GET -Path ("/groups/{0}" -f $ParentId) -Headers $Headers | Out-Null; $isParentGroup = $true }
  catch {
    try { Invoke-Prtg -Method GET -Path ("/probes/{0}" -f $ParentId) -Headers $Headers | Out-Null; $isParentProbe = $true }
    catch {}
  }
  if (-not ($isParentGroup -or $isParentProbe)) {
    # still allow classic create (works for group or probe id)
    Write-Verbose ("Parent {0} not accessible via v2 as group/probe; attempting classic create." -f $ParentId)
  }

  # Try v2 create first if parent looked valid
  if ($isParentGroup -or $isParentProbe) {
    $createPath = if ($isParentGroup) { "/experimental/groups/$ParentId/group" } else { "/experimental/probes/$ParentId/group" }
    try {
      $resp = Invoke-Prtg -Method POST -Path $createPath -Headers $Headers -Body @{ basic = @{ name = $GroupName } }
      $newId = if ($resp -is [System.Array] -and $resp.Count -gt 0) { $resp[0].id } else { $resp.id }
      if ($newId) { $script:GroupCache["{0}|{1}" -f $ParentId, $GroupName] = $newId; return $newId }
    } catch {
      Write-Verbose ("v2 group create failed for '{0}' under '{1}': {2} — falling back to classic" -f $GroupName, $ParentId, $_.Exception.Message)
    }
  }

  # Classic fallback
  Add-GroupClassic -ParentId $ParentId -GroupName $GroupName
  $resolved = Find-ChildGroupByName -ParentGroupId $ParentId -GroupName $GroupName -Headers $Headers
  if ($resolved) { return $resolved }
  throw ("Failed to create or find group '{0}' under parent '{1}'." -f $GroupName, $ParentId)
}

function Ensure-GroupByPath {
  <#
    Creates/reuses nested groups given a starting parent and a GroupPath like "Region/City/Switches".
    Returns the final (deepest) group ID.
  #>
  param([string]$ParentId, [string]$GroupPath, [hashtable]$Headers)

  if ([string]::IsNullOrWhiteSpace($GroupPath)) {
    throw "GroupPath is empty."
  }

  $parts = $GroupPath -split '[\\/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() }
  if ($parts.Count -eq 0) { throw "GroupPath does not contain any valid segments." }

  $currentParent = $ParentId
  foreach ($segment in $parts) {
    $currentParent = Ensure-GroupSingleLevel -GroupName $segment -ParentId $currentParent -Headers $Headers
    Write-Verbose ("Path segment '{0}' => group id {1}" -f $segment, $currentParent)
  }
  return $currentParent
}

function Add-DeviceClassic { param([string]$GroupId, [string]$DeviceName, [string]$IP)
  $safeName = [System.Uri]::EscapeDataString($DeviceName)
  $safeIP   = [System.Uri]::EscapeDataString($IP)
  $q = ("api/adddevice2.htm?id={0}&name_={1}&host_={2}" -f $GroupId, $safeName, $safeIP)
  Invoke-ClassicApi -PathWithQuery $q
}

function New-Device {
  param([string]$GroupId, [string]$DeviceName, [string]$IP, [hashtable]$Headers)
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
      # Resolve by classic first
      $q = ("api/table.json?content=devices&columns=objid,parentid,name&filter_parentid={0}" -f $GroupId)
      $json = Invoke-ClassicApiJson -PathWithQuery $q
      $rows = $json.rows ?? $json
      $match = $rows | Where-Object { $_.name -eq $DeviceName } | Select-Object -First 1
      if ($match -and $match.objid) { return $match.objid }
      # Try v2 as last resort
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

function Add-PingSensorV2 { param([string]$DeviceId, [hashtable]$Headers)
  $path = "/experimental/devices/$DeviceId/sensor"
  $body = @{ type = "ping"; basic = @{ name = "Ping" } }
  try { Invoke-Prtg -Method POST -Path $path -Headers $Headers -Body $body | Out-Null; return $true }
  catch { $msg = $_.Exception.Message; throw ("API v2 ping creation failed for device {0}: {1}" -f $DeviceId, $msg) }
}

function Add-PingSensorClassic { param([string]$DeviceId)
  $q = ("api/addsensor5.htm?id={0}&sensortype=ping" -f $DeviceId)
  Invoke-ClassicApi -PathWithQuery $q
}

function Ensure-PingSensor {
  param([string]$DeviceId, [hashtable]$Headers)
  # Respect config: only ping supported right now
  if ($DefaultSensor -and $DefaultSensor.ToLower() -ne 'ping') {
    Write-Warning ("Configured defaults.sensorType='{0}' is not supported yet; proceeding with 'ping'." -f $DefaultSensor)
  }
  $created = $false
  try { Add-PingSensorV2 -DeviceId $DeviceId -Headers $Headers; $created = $true }
  catch { Add-PingSensorClassic -DeviceId $DeviceId; $created = $true }
  try {
    $filter = ('type = sensor and (tags contains "ping" or type_raw = "ping") and parentid = "{0}"' -f $DeviceId)
    $filterEnc = [System.Uri]::EscapeDataString($filter)
    $result = Invoke-Prtg -Method GET -Path ("/experimental/objects?limit=50&filter={0}" -f $filterEnc) -Headers $Headers
    return ($result -and $result.Count -gt 0)
  } catch { return $created }
}

function Start-DeviceScan {
  param([string]$DeviceId, [hashtable]$Headers)
  if (-not $ScanAfterCreate) { return }
  try { Invoke-Prtg -Method POST -Path "/devices/$DeviceId/scan" -Headers $Headers | Out-Null }
  catch { $msg = $_.Exception.Message; Write-Warning ("Scan after creation failed for device {0}: {1}" -f $DeviceId, $msg) }
}

# -------------------- Main --------------------

if (-not (Test-Path -LiteralPath $CsvPath)) { throw ("CSV file not found: {0}" -f $CsvPath) }

$headers = New-AuthHeader -Key $ApiKey
$rows    = Import-Csv -LiteralPath $CsvPath
$summary = [System.Collections.Generic.List[Object]]::new()

foreach ($row in $rows) {
  $deviceName    = ($row.DeviceName  | ForEach-Object { $_.ToString().Trim() })
  $ip            = ($row.IP          | ForEach-Object { $_.ToString().Trim() })
  $groupIdCsv    = $row.GroupId
  $groupName     = if ($row.GroupName) { $row.GroupName } else { $null }
  $parentGroupId = if ($row.ParentGroupId) { $row.ParentGroupId } else { $DefaultParentId }
  $groupPath     = if ($row.GroupPath) { $row.GroupPath } else { $null }

  if ([string]::IsNullOrWhiteSpace($deviceName) -or [string]::IsNullOrWhiteSpace($ip)) {
    Write-Warning ("Skipping row with missing DeviceName or IP: {0}" -f ($row | ConvertTo-Json -Compress))
    continue
  }

  try {
    # Resolve group target
    $resolvedGroupId = $null
    if (-not [string]::IsNullOrWhiteSpace($groupIdCsv)) {
      # Provided GroupId wins
      try { Invoke-Prtg -Method GET -Path ("/groups/{0}" -f $groupIdCsv) -Headers $headers | Out-Null; $resolvedGroupId = $groupIdCsv }
      catch {
        # try classic verification (in case v2 cannot read it)
        $r = Invoke-ClassicApiJson -PathWithQuery ("api/table.json?content=groups&columns=objid&filter_objid={0}" -f $groupIdCsv)
        $rowsG = $r.rows ?? $r
        if ($rowsG -and $rowsG.Count -gt 0) { $resolvedGroupId = $groupIdCsv }
        else { throw ("Provided GroupId {0} is not accessible." -f $groupIdCsv) }
      }
    }
    elseif (-not [string]::IsNullOrWhiteSpace($groupPath)) {
      if ([string]::IsNullOrWhiteSpace($parentGroupId)) {
        throw "ParentGroupId is required when using GroupPath (set defaults.parentGroupId to avoid specifying it per row)."
      }
      $resolvedGroupId = Ensure-GroupByPath -ParentId $parentGroupId -GroupPath $groupPath -Headers $headers
    }
    else {
      if ([string]::IsNullOrWhiteSpace($parentGroupId) -or [string]::IsNullOrWhiteSpace($groupName)) {
        throw "Provide either GroupId, or (ParentGroupId + GroupName), or (ParentGroupId + GroupPath)."
      }
      $resolvedGroupId = Ensure-GroupSingleLevel -GroupName $groupName -ParentId $parentGroupId -Headers $headers
    }

    Write-Host ("Group resolved: {0}" -f $resolvedGroupId)

    $deviceId = New-Device -GroupId $resolvedGroupId -DeviceName $deviceName -IP $ip -Headers $headers
    Write-Host ("Created device '{0}' (ID {1})" -f $deviceName, $deviceId)

    $hasPing = Ensure-PingSensor -DeviceId $deviceId -Headers $headers
    if ($hasPing) { Write-Host ("✅ Ping sensor ensured for '{0}'." -f $deviceName) }
    else { Write-Warning ("⚠️  Could not verify Ping sensor for '{0}'." -f $deviceName) }

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

# Output summary to console
$summary | Format-Table -AutoSize

# Optional JSON summary export
if ($JsonSummaryPath) {
  try {
    $dir = Split-Path -Parent $JsonSummaryPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $summary | ConvertTo-Json -Depth 6 | Out-File -FilePath $JsonSummaryPath -Encoding utf8
    Write-Host ("Summary JSON written to: {0}" -f $JsonSummaryPath)
  } catch {
    Write-Warning ("Failed to write JSON summary: {0}" -f $_.Exception.Message)
  }
}

# -------------------- End Logging --------------------
if ($global:TranscriptStarted) { try { Stop-Transcript | Out-Null } catch {} }
