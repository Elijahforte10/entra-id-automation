#requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users
<#
.SYNOPSIS
    Get-GuestAccountReview.ps1 — review external (guest) accounts in the tenant.

.DESCRIPTION
    READ-ONLY. Guest accounts accumulate and are often forgotten. This lists
    every guest, when they were invited, whether they ever accepted, and their
    last sign-in — your access-review starting point for external identities.

    Required Graph scopes: User.Read.All, AuditLog.Read.All

.PARAMETER OutputPath
    CSV output path (default .\guest_accounts.csv).

.EXAMPLE
    .\Get-GuestAccountReview.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\guest_accounts.csv"
)

Connect-MgGraph -Scopes "User.Read.All", "AuditLog.Read.All" -NoWelcome

Write-Host "[*] Retrieving guest accounts..." -ForegroundColor Cyan
$guests = Get-MgUser -All -Filter "userType eq 'Guest'" `
    -Property "DisplayName,UserPrincipalName,Mail,CreatedDateTime,ExternalUserState,SignInActivity,AccountEnabled"

$report = foreach ($g in $guests) {
    $last = $g.SignInActivity.LastSignInDateTime
    [pscustomobject]@{
        DisplayName   = $g.DisplayName
        Email         = $g.Mail
        InviteState   = $g.ExternalUserState      # PendingAcceptance / Accepted
        Created       = $g.CreatedDateTime
        LastSignIn    = if ($last) { $last } else { "NEVER" }
        Enabled       = $g.AccountEnabled
    }
}

$pending = $report | Where-Object { $_.InviteState -eq "PendingAcceptance" }
$neverIn = $report | Where-Object { $_.LastSignIn -eq "NEVER" }

Write-Host "`n[!] Pending (never accepted) invites: $($pending.Count)" -ForegroundColor Yellow
Write-Host "[!] Guests who never signed in:      $($neverIn.Count)" -ForegroundColor Yellow

$report | Sort-Object Created | Format-Table -AutoSize
$report | Export-Csv -Path $OutputPath -NoTypeInformation
Write-Host "[*] $($report.Count) guest(s) total. Exported to $OutputPath" -ForegroundColor Green

Disconnect-MgGraph | Out-Null
