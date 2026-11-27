<#
.SYNOPSIS
    Creates the HoneyShield decoy account {{ACCOUNT_NAME}} in Active Directory.

.DESCRIPTION
    HoneyShield decoy {{DECOY_ID}}.

    Run once, as a member of Domain Admins (or with the right to create users in the target OU), on
    a domain controller or any machine with the ActiveDirectory PowerShell module.

    The account gets a 68-character random password generated on this machine. It is not shown,
    saved or sent anywhere: nobody needs it, and any attempt to sign in with the account is the
    alert. The account is in no groups and can do nothing anywhere.

    Then install the collector (HoneyShield-DCCollector.ps1) on every domain controller, or nothing
    is reported. See docs/active-directory-decoys.md.

.PARAMETER Path
    Distinguished name of the OU for the account. Default: the domain's Users container. Put it
    where your real service accounts are: an account alone in an empty OU looks planted.

.PARAMETER Remove
    Delete the account. Do this after retiring the decoy in HoneyShield.

.EXAMPLE
    .\New-HoneyShieldDecoy-{{ACCOUNT_NAME}}.ps1 -Path 'OU=Service Accounts,DC=corp,DC=example,DC=com'

.EXAMPLE
    .\New-HoneyShieldDecoy-{{ACCOUNT_NAME}}.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$Path,
    [switch]$Remove
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$AccountName   = '{{ACCOUNT_NAME}}'
$DisplayName   = '{{DISPLAY_NAME}}'
$Description   = '{{DESCRIPTION}}'
$SpnTemplate   = '{{SPN}}'            # service/host[:port]; the domain's DNS name is added below
$AuditReads    = {{AUDIT_READS}}
$SetAdminCount = {{ADMIN_COUNT}}

$domain = Get-ADDomain
$existing = Get-ADUser -Filter "SamAccountName -eq '$AccountName'"

if ($Remove) {
    if (-not $existing) { Write-Host "There is no account named $AccountName."; return }
    # Remove-ADUser asks you to confirm.
    if ($PSCmdlet.ShouldProcess($existing.DistinguishedName, 'Delete the HoneyShield decoy account')) {
        Remove-ADUser -Identity $existing
        Write-Host "Deleted $AccountName."
    }
    return
}
if ($existing) {
    throw "An account named $AccountName already exists ($($existing.DistinguishedName)). Generate the decoy again in HoneyShield with another account name."
}

$spn = $null
if ($SpnTemplate) {
    $service, $rest = $SpnTemplate -split '/', 2
    $hostName, $port = $rest -split ':', 2
    $spn = "$service/$hostName.$($domain.DNSRoot)"
    if ($port) { $spn = "${spn}:$port" }
    if (Get-ADObject -LDAPFilter "(servicePrincipalName=$spn)") {
        throw "The SPN $spn is already registered in this forest. Generate the decoy again in HoneyShield with another SPN."
    }
}

$target = if ($Path) { $Path } else { $domain.UsersContainer }
if (-not $PSCmdlet.ShouldProcess("$AccountName in $target", 'Create the HoneyShield decoy account')) { return }

# 48 random bytes -> 64 Base64 characters, plus one character of each class so any complexity
# policy accepts it. Nobody ever learns it.
$bytes = New-Object byte[] 48
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
$password = ConvertTo-SecureString ([Convert]::ToBase64String($bytes) + 'aA1!') -AsPlainText -Force
[Array]::Clear($bytes, 0, $bytes.Length)

$userParams = @{
    Name                 = $DisplayName
    DisplayName          = $DisplayName
    SamAccountName       = $AccountName
    UserPrincipalName    = "$AccountName@$($domain.DNSRoot)"
    Description          = $Description
    Path                 = $target
    AccountPassword      = $password
    Enabled              = $true
    PasswordNeverExpires = $true
    CannotChangePassword = $true
}
New-ADUser @userParams
$user = Get-ADUser -Identity $AccountName

if ($spn) {
    # An SPN makes the account a Kerberoasting target: asking for its ticket is event 4769.
    Set-ADUser -Identity $user -ServicePrincipalNames @{ Add = $spn }
}
if ($SetAdminCount) {
    # Marks the account the way protected admin accounts are marked, which is what enumeration
    # tools highlight. It grants nothing.
    Set-ADUser -Identity $user -Replace @{ adminCount = 1 }
}
if ($AuditReads) {
    # Audit every read of the account object (event 4662), which catches directory enumeration.
    $adPath = "AD:\$($user.DistinguishedName)"
    $acl = Get-Acl -Path $adPath -Audit
    $everyone = New-Object System.Security.Principal.SecurityIdentifier 'S-1-1-0'
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
        $everyone,
        [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
        [System.Security.AccessControl.AuditFlags]::Success)
    $acl.AddAuditRule($rule)
    Set-Acl -Path $adPath -AclObject $acl
}

Write-Host ''
Write-Host "Created the HoneyShield decoy account $AccountName ($($user.DistinguishedName))."
if ($spn) { Write-Host "SPN: $spn" }
if ($AuditReads) { Write-Host 'Reads of the account are audited (needs the Directory Service Access audit policy).' }
Write-Host ''
Write-Host 'Next: install HoneyShield-DCCollector.ps1 on every domain controller, then run it with -Test.'
Write-Host 'The domain controllers need these audit policies (Success and Failure), normally set by GPO:'
Write-Host '  Account Logon: Credential Validation, Kerberos Authentication Service, Kerberos Service Ticket Operations'
Write-Host '  Logon/Logoff: Logon'
if ($AuditReads) { Write-Host '  DS Access: Directory Service Access (Success)' }
