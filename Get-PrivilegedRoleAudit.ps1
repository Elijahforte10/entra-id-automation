#requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Identity.DirectoryManagement
<#
.SYNOPSIS
    Get-PrivilegedRoleAudit.ps1 — enumerate members of privileged directory roles.

.DESCRIPTION
    READ-ONLY. Lists every active directory role and its members, with a
    spotlight on the highest-risk roles (Global Administrator, Privileged Role
    Administrator, etc.). Over-provisioned admin roles are a top finding in any
    identity assessment.

    Required Graph scopes: RoleManagement.Read.Directory, Directory.Read.All

.PARAMETER OutputPath
    CSV output path (default .\privileged_roles.csv).

.EXAMPLE
    .\Get-PrivilegedRoleAudit.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath = ".\privileged_roles.csv"
)

Connect-MgGraph -Scopes "RoleManagement.Read.Directory", "Directory.Read.All" -NoWelcome

$highRisk = @(
    "Global Administrator", "Privileged Role Administrator",
    "Privileged Authentication Administrator", "Security Administrator",
    "Application Administrator", "Cloud Application Administrator",
    "Exchange Administrator", "User Administrator"
)

Write-Host "[*] Enumerating active directory roles and members..." -ForegroundColor Cyan
$roles = Get-MgDirectoryRole -All

$audit = foreach ($role in $roles) {
    $members = Get-MgDirectoryRoleMember -DirectoryRoleId $role.Id -All
    foreach ($m in $members) {
        $props = $m.AdditionalProperties
        [pscustomobject]@{
            Role        = $role.DisplayName
            HighRisk    = if ($highRisk -contains $role.DisplayName) { "YES" } else { "" }
            MemberName  = $props.displayName
            MemberUPN   = $props.userPrincipalName
            MemberType  = ($props.'@odata.type' -replace '#microsoft.graph.', '')
        }
    }
}

Write-Host "`n[!] HIGH-RISK role assignments:" -ForegroundColor Yellow
$audit | Where-Object { $_.HighRisk -eq "YES" } |
    Select-Object Role, MemberName, MemberUPN | Format-Table -AutoSize

$audit | Sort-Object Role | Export-Csv -Path $OutputPath -NoTypeInformation
$gaCount = ($audit | Where-Object { $_.Role -eq "Global Administrator" }).Count
Write-Host "[*] Global Administrators: $gaCount  (Microsoft recommends fewer than 5)" -ForegroundColor Green
Write-Host "[*] Full audit exported to $OutputPath"

Disconnect-MgGraph | Out-Null
