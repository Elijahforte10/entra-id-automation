# Entra ID Automation Toolkit

PowerShell + Microsoft Graph scripts for everyday Entra ID (Azure AD) identity
hygiene and security reporting. Every script in this repo is **read-only** — it
reports posture and exports CSV, and changes nothing in your tenant.

Built around the SC-300 / AZ-104 skill set: identity lifecycle, access reviews,
privileged-access audit, and credential hygiene.

## Scripts

| Script | What it answers |
|---|---|
| `Get-StaleAccounts.ps1` | Which enabled users haven't signed in for N days? |
| `Get-MfaStatus.ps1` | Who is (and isn't) registered for MFA? |
| `Get-PrivilegedRoleAudit.ps1` | Who holds Global Admin and other high-risk roles? |
| `Get-ExpiringAppSecrets.ps1` | Which app secrets/certs are expired or expiring? |
| `Get-GuestAccountReview.ps1` | What external/guest accounts exist and are they used? |

## Setup

```powershell
# One-time: install the Microsoft Graph PowerShell SDK
Install-Module Microsoft.Graph -Scope CurrentUser

# Each script prompts for consent to the least-privilege scopes it needs.
.\Get-StaleAccounts.ps1 -Days 90
.\Get-MfaStatus.ps1
.\Get-PrivilegedRoleAudit.ps1
.\Get-ExpiringAppSecrets.ps1 -WarnDays 45
.\Get-GuestAccountReview.ps1
```

## Required Graph scopes (least privilege)

| Script | Scopes |
|---|---|
| Stale accounts | `User.Read.All`, `AuditLog.Read.All` |
| MFA status | `AuditLog.Read.All`, `UserAuthenticationMethod.Read.All` |
| Privileged roles | `RoleManagement.Read.Directory`, `Directory.Read.All` |
| App secrets | `Application.Read.All` |
| Guest review | `User.Read.All`, `AuditLog.Read.All` |

## Notes

- Requires PowerShell 5.1+ (7+ recommended) and the `Microsoft.Graph` module.
- `signInActivity` requires an Entra ID P1/P2 license on the tenant.
- All output is CSV for easy hand-off to access reviews or ticketing.
- No credentials are stored; auth is interactive via `Connect-MgGraph`.

> Read-only by design. These scripts assess your own tenant — run them only
> where you are authorized.
