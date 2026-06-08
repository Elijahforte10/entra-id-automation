#requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users
<#
.SYNOPSIS
    Get-StaleAccounts.ps1 — find enabled Entra ID users who haven't signed in
    for N days. Stale accounts are a classic attack surface and an easy
    access-review win.

.DESCRIPTION
    READ-ONLY. Queries sign-in activity and reports enabled accounts whose
    last interactive sign-in is older than the threshold (or who have never
    signed in). Exports to CSV.

    Required Graph scopes: User.Read.All, AuditLog.Read.All

.PARAMETER Days
    Inactivity threshold in days (default 90).

.PARAMETER OutputPath
    CSV output path (default .\stale_accounts.csv).

.EXAMPLE
    .\Get-StaleAccounts.ps1 -Days 60
#>
[CmdletBinding()]
param(
    [int]$Days = 90,
    [string]$OutputPath = ".\stale_accounts.csv"
)

Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All" -NoWelcome

$cutoff = (Get-Date).AddDays(-$Days)
Write-Host "[*] Looking for enabled users inactive since $($cutoff.ToString('yyyy-MM-dd'))..." -ForegroundColor Cyan

$users = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,AccountEnabled,SignInActivity,CreatedDateTime" |
    Where-Object { $_.AccountEnabled -eq $true }

$stale = foreach ($u in $users) {
    $last = $u.SignInActivity.LastSignInDateTime
    $isStale = (-not $last) -or ($last -lt $cutoff)
    if ($isStale) {
        [pscustomobject]@{
            DisplayName       = $u.DisplayName
            UserPrincipalName = $u.UserPrincipalName
            LastSignIn        = if ($last) { $last } else { "NEVER" }
            Created           = $u.CreatedDateTime
            DaysInactive      = if ($last) { [math]::Round(((Get-Date) - $last).TotalDays) } else { "N/A" }
        }
    }
}

$stale = $stale | Sort-Object { if ($_.LastSignIn -eq "NEVER") { [datetime]::MinValue } else { $_.LastSignIn } }
$stale | Format-Table -AutoSize
$stale | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "[*] $($stale.Count) stale account(s). Exported to $OutputPath" -ForegroundColor Green

Disconnect-MgGraph | Out-Null
