#requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications
<#
.SYNOPSIS
    Get-ExpiringAppSecrets.ps1 — find app registration secrets/certs that are
    expired or expiring soon.

.DESCRIPTION
    READ-ONLY. Expired credentials cause outages; long-lived or forgotten
    secrets are a security risk. This reports every app registration's client
    secrets and certificates with their expiry, flagging anything within the
    warning window.

    Required Graph scopes: Application.Read.All

.PARAMETER WarnDays
    Flag credentials expiring within this many days (default 30).

.PARAMETER OutputPath
    CSV output path (default .\app_credentials.csv).

.EXAMPLE
    .\Get-ExpiringAppSecrets.ps1 -WarnDays 45
#>
[CmdletBinding()]
param(
    [int]$WarnDays = 30,
    [string]$OutputPath = ".\app_credentials.csv"
)

Connect-MgGraph -Scopes "Application.Read.All" -NoWelcome

$warnDate = (Get-Date).AddDays($WarnDays)
Write-Host "[*] Scanning app registrations for credentials expiring before $($warnDate.ToString('yyyy-MM-dd'))..." -ForegroundColor Cyan

$apps = Get-MgApplication -All -Property "Id,DisplayName,PasswordCredentials,KeyCredentials,AppId"

$creds = foreach ($app in $apps) {
    foreach ($pc in $app.PasswordCredentials) {
        [pscustomobject]@{
            App        = $app.DisplayName
            AppId      = $app.AppId
            Type       = "Secret"
            Expires    = $pc.EndDateTime
            Status     = if ($pc.EndDateTime -lt (Get-Date)) { "EXPIRED" }
                         elseif ($pc.EndDateTime -lt $warnDate) { "EXPIRING" }
                         else { "OK" }
        }
    }
    foreach ($kc in $app.KeyCredentials) {
        [pscustomobject]@{
            App        = $app.DisplayName
            AppId      = $app.AppId
            Type       = "Certificate"
            Expires    = $kc.EndDateTime
            Status     = if ($kc.EndDateTime -lt (Get-Date)) { "EXPIRED" }
                         elseif ($kc.EndDateTime -lt $warnDate) { "EXPIRING" }
                         else { "OK" }
        }
    }
}

$flagged = $creds | Where-Object { $_.Status -ne "OK" } | Sort-Object Expires
Write-Host "`n[!] Expired / expiring credentials:" -ForegroundColor Yellow
$flagged | Format-Table -AutoSize

$creds | Sort-Object Expires | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "[*] $($flagged.Count) credential(s) need attention. Full list -> $OutputPath" -ForegroundColor Green

Disconnect-MgGraph | Out-Null
