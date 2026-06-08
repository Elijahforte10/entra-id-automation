#requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Get-MfaStatus.ps1 — report MFA / strong-auth registration across the tenant.

.DESCRIPTION
    READ-ONLY. Uses the authentication-method registration report to show who
    is registered for MFA, who is capable, and who is passwordless. Flags
    unregistered users as your remediation list.

    Required Graph scopes: AuditLog.Read.All, UserAuthenticationMethod.Read.All

.PARAMETER OutputPath
    CSV output path (default .\mfa_status.csv).

.EXAMPLE
    .\Get-MfaStatus.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\mfa_status.csv"
)

Connect-MgGraph -Scopes "AuditLog.Read.All", "UserAuthenticationMethod.Read.All" -NoWelcome

Write-Host "[*] Pulling authentication-method registration details..." -ForegroundColor Cyan

$uri = "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails"
$results = @()
do {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $uri
    $results += $resp.value
    $uri = $resp.'@odata.nextLink'
} while ($uri)

$report = foreach ($r in $results) {
    [pscustomobject]@{
        UserPrincipalName = $r.userPrincipalName
        MfaRegistered     = $r.isMfaRegistered
        MfaCapable        = $r.isMfaCapable
        Passwordless      = $r.isPasswordlessCapable
        SsprRegistered    = $r.isSsprRegistered
        Methods           = ($r.methodsRegistered -join "; ")
    }
}

$notRegistered = $report | Where-Object { -not $_.MfaRegistered }

Write-Host "`n[!] Users NOT registered for MFA:" -ForegroundColor Yellow
$notRegistered | Select-Object UserPrincipalName | Format-Table -AutoSize

$report | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "[*] Total users: $($report.Count) | No MFA: $($notRegistered.Count)" -ForegroundColor Green
Write-Host "[*] Full report exported to $OutputPath"

Disconnect-MgGraph | Out-Null
