<#
.SYNOPSIS
    HoneyShield collector for Active Directory decoy accounts. Install it on every domain controller.

.DESCRIPTION
    Every minute (a scheduled task running as SYSTEM) the collector fetches the project's decoy
    accounts from HoneyShield, reads new events about them from this domain controller's Security
    log and reports each one through HoneyShield's signed integration channel. Only events that name
    a decoy account leave the controller; nothing else in the log is read into a report or sent.

    Events reported:
      4624, 4625  logon with the account (success, failure)
      4768, 4771  Kerberos sign-in with the account (ticket granted or refused, wrong password)
      4769        Kerberos service ticket for the account's SPN (Kerberoasting)
      4776        NTLM validation of the account
      4662        read of the account object (only for decoys with read auditing)

    Requests are signed with an integration credential (HoneyShield console: Integrations). The
    secret is stored under C:\ProgramData\HoneyShield, encrypted with DPAPI and readable only by
    SYSTEM and Administrators. It is never sent: requests carry an HMAC signature.

    Needs Windows Server 2016 or later and Windows PowerShell 5.1 (or PowerShell 7).

.PARAMETER Install
    Store the credential, check that it works and register the scheduled task.

.PARAMETER IntegrationId
    The integration's id (hsi_...). The secret is asked for, not passed on the command line.

.PARAMETER BaseUrl
    The HoneyShield ingest host, e.g. https://ingest.example.com.

.PARAMETER Test
    Show the decoys this controller watches, the audit policy and the last run.

.PARAMETER Uninstall
    Remove the scheduled task and everything under the state folder.

.EXAMPLE
    .\HoneyShield-DCCollector.ps1 -Install -IntegrationId hsi_0123456789abcdef01234567

.EXAMPLE
    .\HoneyShield-DCCollector.ps1 -Test
#>
[CmdletBinding(DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)][switch]$Install,
    [Parameter(ParameterSetName = 'Install', Mandatory = $true)]
    [ValidatePattern('^hsi_[0-9a-f]{24}$')][string]$IntegrationId,
    [Parameter(ParameterSetName = 'Install')][string]$BaseUrl = '{{BASE_URL}}',
    [Parameter(ParameterSetName = 'Test', Mandatory = $true)][switch]$Test,
    [Parameter(ParameterSetName = 'Uninstall', Mandatory = $true)][switch]$Uninstall,
    [string]$StateDir = (Join-Path $env:ProgramData 'HoneyShield')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$TaskName = 'HoneyShield DC Collector'
$EventIds = @(4624, 4625, 4662, 4768, 4769, 4771, 4776)
$MaxEventsPerAccount = 500
$AuditSuccess = 0x0020000000000000
# Audit subcategories the events need (GUIDs: names are localized).
$AuditSubcategories = [ordered]@{
    'Logon'                             = '{0CCE9215-69AE-11D9-BED3-505054503030}'
    'Credential Validation'             = '{0CCE923F-69AE-11D9-BED3-505054503030}'
    'Kerberos Authentication Service'   = '{0CCE9242-69AE-11D9-BED3-505054503030}'
    'Kerberos Service Ticket Operations' = '{0CCE9240-69AE-11D9-BED3-505054503030}'
    'Directory Service Access'          = '{0CCE923B-69AE-11D9-BED3-505054503030}'
}

# ---------------------------------------------------------------- signing (docs/customer-integrations.md)

function ConvertTo-HsHex([byte[]]$Bytes) {
    $sb = New-Object System.Text.StringBuilder ($Bytes.Length * 2)
    foreach ($b in $Bytes) { [void]$sb.Append($b.ToString('x2')) }
    $sb.ToString()
}

function Get-HsSha256Hex([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { ConvertTo-HsHex $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
}

function New-HsSignature([string]$Secret, [string]$Method, [string]$Path, [string]$Timestamp, [byte[]]$Body) {
    $canonical = "v1`n$($Method.ToUpperInvariant())`n$Path`n$Timestamp`n$(Get-HsSha256Hex $Body)"
    $hmac = New-Object System.Security.Cryptography.HMACSHA256 (, [System.Text.Encoding]::UTF8.GetBytes($Secret))
    try { 'v1=' + (ConvertTo-HsHex $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonical))) }
    finally { $hmac.Dispose() }
}

function Invoke-HsRequest($Config, [string]$Secret, [string]$Method, [string]$Path, $BodyObject) {
    $body = New-Object byte[] 0
    if ($null -ne $BodyObject) {
        $body = [System.Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $BodyObject -Compress -Depth 4))
    }
    $timestamp = [string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    $headers = @{
        'X-HS-Integration' = $Config.integration_id
        'X-HS-Timestamp'   = $timestamp
        'X-HS-Signature'   = (New-HsSignature $Secret $Method $Path $timestamp $body)
    }
    $request = @{ Uri = $Config.base_url + $Path; Method = $Method; Headers = $headers
                  UseBasicParsing = $true; TimeoutSec = 30 }
    if ($Method -eq 'POST') { $request.Body = $body; $request.ContentType = 'application/json' }
    try {
        $response = Invoke-WebRequest @request
        return [pscustomobject]@{ Status = [int]$response.StatusCode; Content = [string]$response.Content }
    } catch {
        # WebException (Windows PowerShell) or HttpResponseException (PowerShell 7) carry the status.
        $property = $_.Exception.PSObject.Properties['Response']
        if ($null -eq $property -or $null -eq $property.Value) { throw }
        return [pscustomobject]@{ Status = [int]$property.Value.StatusCode; Content = '' }
    }
}

# ---------------------------------------------------------------- events -> reports

function Get-HsField([hashtable]$Data, [string]$Name) {
    if ($Data.ContainsKey($Name)) {
        $value = [string]$Data[$Name]
        if ($value -and $value -ne '-') { return $value.Trim() }
    }
    return $null
}

function ConvertTo-HsDirectoryReport {
    <# One Security log event about a decoy account -> the body of POST /integrations/v1/directory-events. #>
    param(
        [Parameter(Mandatory = $true)][string]$DecoyId,
        [Parameter(Mandatory = $true)][string]$AccountName,
        [Parameter(Mandatory = $true)][int]$EventId,
        [Parameter(Mandatory = $true)][long]$Keywords,
        [Parameter(Mandatory = $true)][long]$RecordId,
        [Parameter(Mandatory = $true)][string]$MachineName,
        [Parameter(Mandatory = $true)][datetime]$TimeCreated,
        [Parameter(Mandatory = $true)][hashtable]$Data
    )
    $target = switch ($EventId) {
        4769 { Get-HsField $Data 'ServiceName' }
        4662 { $AccountName }
        default { Get-HsField $Data 'TargetUserName' }
    }
    if (-not $target) { $target = $AccountName }
    $actor = $null
    if ($EventId -eq 4769) { $actor = Get-HsField $Data 'TargetUserName' }
    if ($EventId -eq 4662) {
        $user = Get-HsField $Data 'SubjectUserName'
        $domain = Get-HsField $Data 'SubjectDomainName'
        if ($user) { $actor = if ($domain) { "$domain\$user" } else { $user } }
    }
    $status = if ($EventId -eq 4625) { Get-HsField $Data 'SubStatus' } else { Get-HsField $Data 'Status' }
    if ($status -and $status -notmatch '^0x[0-9A-Fa-f]{1,8}$') { $status = $null }
    $encryption = Get-HsField $Data 'TicketEncryptionType'
    if ($encryption -and $encryption -notmatch '^0x[0-9A-Fa-f]{1,8}$') { $encryption = $null }
    $workstation = Get-HsField $Data 'WorkstationName'
    if (-not $workstation) { $workstation = Get-HsField $Data 'Workstation' }
    $logonType = Get-HsField $Data 'LogonType'
    $source = Get-HsField $Data 'IpAddress'

    $report = [ordered]@{
        decoy_id          = $DecoyId
        idempotency_key   = 'ad_' + (Get-HsSha256Hex ([System.Text.Encoding]::UTF8.GetBytes("$MachineName|$RecordId"))).Substring(0, 40)
        observed_at       = $TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", [System.Globalization.CultureInfo]::InvariantCulture)
        windows_event_id  = $EventId
        succeeded         = (($Keywords -band $AuditSuccess) -ne 0)
        domain_controller = $MachineName
        target_name       = $target
        record_id         = $RecordId
    }
    if ($source) { $report.source_ip = $source }
    if ($workstation) { $report.workstation = $workstation }
    if ($actor) { $report.actor = $actor }
    if ($status) { $report.status = $status }
    if ($logonType -match '^\d{1,2}$') { $report.logon_type = [int]$logonType }
    if ($encryption) { $report.ticket_encryption = $encryption }
    return $report
}

function Get-HsEventData($WinEvent) {
    $xml = [xml]$WinEvent.ToXml()
    $data = @{}
    foreach ($node in $xml.GetElementsByTagName('Data')) { $data[$node.GetAttribute('Name')] = $node.InnerText }
    return $data
}

function Get-HsNameVariants([string]$Name) {
    # The event log stores names as the client typed them, and XPath comparison is case-sensitive.
    @($Name, $Name.ToLowerInvariant(), $Name.ToUpperInvariant()) | Sort-Object -Unique -CaseSensitive
}

function Get-HsXPath([string]$AccountName, [string]$ObjectGuid, [long]$After, [long]$Through) {
    $ids = ($EventIds | ForEach-Object { "EventID=$_" }) -join ' or '
    $terms = foreach ($variant in (Get-HsNameVariants $AccountName)) {
        "Data[@Name='TargetUserName']='$variant'"
        "Data[@Name='ServiceName']='$variant'"
    }
    if ($ObjectGuid) { $terms = @($terms) + "Data[@Name='ObjectName']='%{$ObjectGuid}'" }
    "*[System[($ids) and EventRecordID > $After and EventRecordID <= $Through]] and *[EventData[$(@($terms) -join ' or ')]]"
}

# ---------------------------------------------------------------- state

function Write-HsLog([string]$Message) {
    $line = '{0} {1}' -f [DateTime]::UtcNow.ToString('u'), $Message
    Write-Host $line
    try {
        $log = Join-Path $StateDir 'collector.log'
        if ((Test-Path $log) -and (Get-Item $log).Length -gt 1MB) { Move-Item $log "$log.1" -Force }
        Add-Content -Path $log -Value $line -Encoding ASCII
    } catch { }
}

function Initialize-HsCrypto {
    try { Add-Type -AssemblyName System.Security } catch { }
}

function Protect-HsSecret([string]$Plain) {
    Initialize-HsCrypto
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Plain)
    [Convert]::ToBase64String([System.Security.Cryptography.ProtectedData]::Protect(
        $bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine))
}

function Unprotect-HsSecret([string]$Blob) {
    Initialize-HsCrypto
    [System.Text.Encoding]::UTF8.GetString([System.Security.Cryptography.ProtectedData]::Unprotect(
        [Convert]::FromBase64String($Blob), $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine))
}

function Get-HsConfigPath { Join-Path $StateDir 'collector.json' }

function Read-HsConfig {
    $path = Get-HsConfigPath
    if (-not (Test-Path $path)) { throw "Not installed: run this script with -Install first ($path is missing)." }
    $config = Get-Content -Path $path -Raw | ConvertFrom-Json
    if (-not $config.PSObject.Properties['object_guids']) {
        $config | Add-Member -NotePropertyName object_guids -NotePropertyValue ([pscustomobject]@{})
    }
    return $config
}

function Save-HsConfig($Config) {
    $path = Get-HsConfigPath
    $temp = "$path.tmp"
    ConvertTo-Json -InputObject $Config -Depth 4 | Set-Content -Path $temp -Encoding ASCII
    Move-Item -Path $temp -Destination $path -Force
}

function Set-HsPrivateAcl([string]$Path) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object System.Security.Principal.SecurityIdentifier $sid
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -Path $Path -AclObject $acl
}

function Get-HsNewestRecordId {
    $newest = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($newest) { return [long]$newest.RecordId }
    return [long]0
}

function Get-HsManifest($Config, [string]$Secret) {
    $response = Invoke-HsRequest $Config $Secret 'GET' '/integrations/v1/directory-manifest' $null
    if ($response.Status -eq 401) { throw 'HoneyShield refused the credential (revoked, wrong secret, or this clock is more than 5 minutes off).' }
    if ($response.Status -ne 200) { throw "HoneyShield answered $($response.Status) to the manifest request." }
    return ($response.Content | ConvertFrom-Json).decoys
}

function Get-HsObjectGuid($Config, [string]$AccountName) {
    # Looked up once and kept: every read of an audited object is itself a 4662 event.
    $known = $Config.object_guids.PSObject.Properties[$AccountName]
    if ($known) { return [string]$known.Value }
    try {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.Filter = "(&(objectCategory=person)(sAMAccountName=$AccountName))"
        [void]$searcher.PropertiesToLoad.Add('objectGUID')
        $found = $searcher.FindOne()
        if ($null -eq $found) { return $null }
        $guid = (New-Object System.Guid (, [byte[]]$found.Properties['objectguid'][0])).ToString()
        $Config.object_guids | Add-Member -NotePropertyName $AccountName -NotePropertyValue $guid -Force
        return $guid
    } catch {
        Write-HsLog "Could not look up $AccountName in the directory: $($_.Exception.Message)"
        return $null
    }
}

function Test-HsOwnRead([hashtable]$Data) {
    # This controller's own reads (the GUID lookup above runs as SYSTEM, i.e. the computer account).
    $sid = Get-HsField $Data 'SubjectUserSid'
    $user = Get-HsField $Data 'SubjectUserName'
    return ($sid -eq 'S-1-5-18') -or ($user -and $user -ieq "$env:COMPUTERNAME`$")
}

# ---------------------------------------------------------------- modes

function Invoke-HsCollector {
    $config = Read-HsConfig
    $secret = Unprotect-HsSecret $config.secret
    try { $decoys = @(Get-HsManifest $config $secret) }
    catch { Write-HsLog "Manifest: $($_.Exception.Message)"; return }

    $newest = Get-HsNewestRecordId
    $after = [long]$config.last_record_id
    if ($after -gt $newest) { $after = 0 }  # the log was cleared
    if ($after -eq $newest) {
        $config | Add-Member -NotePropertyName last_run -NotePropertyValue ([DateTime]::UtcNow.ToString('u')) -Force
        Save-HsConfig $config
        return
    }

    $found = New-Object System.Collections.Generic.List[object]
    foreach ($decoy in $decoys) {
        $guid = if ($decoy.audit_reads) { Get-HsObjectGuid $config $decoy.account_name } else { $null }
        try {
            $events = @(Get-WinEvent -LogName Security -Oldest -MaxEvents $MaxEventsPerAccount `
                        -FilterXPath (Get-HsXPath $decoy.account_name $guid $after $newest))
        } catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { continue }
            Write-HsLog "Reading the Security log for $($decoy.account_name): $($_.Exception.Message)"
            return
        }
        if ($events.Count -ge $MaxEventsPerAccount) {
            Write-HsLog "More than $MaxEventsPerAccount events for $($decoy.account_name) this minute; the rest are not reported."
        }
        foreach ($e in $events) { $found.Add([pscustomobject]@{ Event = $e; Decoy = $decoy }) }
    }

    $bookmark = $newest
    foreach ($item in ($found | Sort-Object { $_.Event.RecordId })) {
        $e = $item.Event
        $data = Get-HsEventData $e
        if ($e.Id -eq 4662 -and (Test-HsOwnRead $data)) { continue }
        $report = ConvertTo-HsDirectoryReport -DecoyId $item.Decoy.decoy_id -AccountName $item.Decoy.account_name `
            -EventId $e.Id -Keywords $e.Keywords -RecordId $e.RecordId -MachineName $e.MachineName `
            -TimeCreated $e.TimeCreated -Data $data
        $failure = $null
        try {
            $response = Invoke-HsRequest $config $secret 'POST' '/integrations/v1/directory-events' $report
            if ($response.Status -eq 422) {
                Write-HsLog "HoneyShield rejected event $($e.RecordId) ($($e.Id)); skipped."
            } elseif ($response.Status -ne 202) { $failure = "HTTP $($response.Status)" }
        } catch { $failure = $_.Exception.Message }
        if ($failure) {
            # Retried next minute; HoneyShield stores each event once (idempotency key).
            Write-HsLog "Reporting event $($e.RecordId) failed ($failure); will retry."
            $bookmark = [long]$e.RecordId - 1
            break
        }
        Write-HsLog "Reported event $($e.Id) record $($e.RecordId) for $($item.Decoy.account_name)."
    }
    $config.last_record_id = $bookmark
    $config | Add-Member -NotePropertyName last_run -NotePropertyValue ([DateTime]::UtcNow.ToString('u')) -Force
    Save-HsConfig $config
}

function Install-HsCollector {
    if ($BaseUrl -notmatch '^https://[A-Za-z0-9.-]+(:\d+)?/?$') {
        throw 'Pass -BaseUrl with the HoneyShield ingest host, e.g. https://ingest.example.com'
    }
    $secure = Read-Host -AsSecureString 'Integration secret (shown once when the integration was created)'
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if ($plain -notmatch '^[0-9a-f]{64}$') { throw 'That is not an integration secret (64 hexadecimal characters).' }

    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    Set-HsPrivateAcl $StateDir
    $config = [pscustomobject]@{
        integration_id = $IntegrationId
        base_url       = $BaseUrl.TrimEnd('/')
        secret         = (Protect-HsSecret $plain)
        last_record_id = (Get-HsNewestRecordId)
        object_guids   = [pscustomobject]@{}
    }
    $decoys = @(Get-HsManifest $config $plain)
    Save-HsConfig $config
    $installed = Join-Path $StateDir 'HoneyShield-DCCollector.ps1'
    Copy-Item -Path $PSCommandPath -Destination $installed -Force

    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$installed`""
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1)
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Force | Out-Null

    Write-Host "Installed. HoneyShield accepted the credential; $($decoys.Count) decoy account(s) to watch:"
    foreach ($d in $decoys) { Write-Host "  $($d.account_name)" }
    Write-Host "The task '$TaskName' runs every minute. Check it with: .\HoneyShield-DCCollector.ps1 -Test"
}

function Show-HsStatus {
    $config = Read-HsConfig
    $secret = Unprotect-HsSecret $config.secret
    Write-Host "HoneyShield: $($config.base_url) as $($config.integration_id)"
    $decoys = @(Get-HsManifest $config $secret)
    Write-Host "Decoy accounts watched by this controller: $($decoys.Count)"
    foreach ($d in $decoys) {
        $flags = @()
        if (-not $d.is_active) { $flags += 'retired in HoneyShield' }
        if ($d.audit_reads) { $flags += 'reads audited' }
        Write-Host ("  {0} {1}" -f $d.account_name, $(if ($flags) { '(' + ($flags -join ', ') + ')' } else { '' }))
    }
    # Looking the accounts up here would read them, which an account with read auditing reports.
    Write-Host ''
    Write-Host 'Audit policy on this controller (each needs Success and Failure; Directory Service Access only for read auditing):'
    foreach ($name in $AuditSubcategories.Keys) {
        $line = (& auditpol.exe /get "/subcategory:$($AuditSubcategories[$name])" 2>&1 | Select-Object -Last 1)
        Write-Host ("  {0,-36} {1}" -f $name, ([string]$line).Trim())
    }
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) {
        $info = Get-ScheduledTaskInfo -TaskName $TaskName
        Write-Host ''
        Write-Host "Task: $($task.State), last run $($info.LastRunTime), result $($info.LastTaskResult)"
    } else { Write-Host 'Task: not registered (run -Install).' }
    if ($config.PSObject.Properties['last_run']) { Write-Host "Last collection: $($config.last_run) UTC" }
    $log = Join-Path $StateDir 'collector.log'
    if (Test-Path $log) { Write-Host ''; Write-Host 'Recent log:'; Get-Content $log -Tail 10 | ForEach-Object { "  $_" } }
}

function Uninstall-HsCollector {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path $StateDir) { Remove-Item -Path $StateDir -Recurse -Force }
    Write-Host 'Removed the scheduled task and the stored credential. Revoke the integration in HoneyShield too.'
}

# Dot-sourcing (tests) loads the functions only.
if ($MyInvocation.InvocationName -ne '.') {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    switch ($PSCmdlet.ParameterSetName) {
        'Install'   { Install-HsCollector }
        'Test'      { Show-HsStatus }
        'Uninstall' { Uninstall-HsCollector }
        default     { Invoke-HsCollector }
    }
}
