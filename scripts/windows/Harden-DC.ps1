<#
===============================================================================
 Harden-DC.ps1  -  eCitadel Team 76  -  cabal (Windows Server 2022 Domain Controller)
===============================================================================
 WHAT THIS DOES
   Safe, reversible hardening for the scored Domain Controller. It is the Windows
   counterpart to first5_secure.sh and follows the SAME rule: do nothing that can
   drop a scored service (DNS / RDP / WinRM) or break Active Directory.

 SCORED ON THIS BOX: DNS (53), RDP (3389), WinRM (5985/5986) - and almost every
 other team's web/SSH check authenticates against THIS DC. If AD or DNS go down,
 scoring cascade-fails for the whole team. So we are deliberately conservative.

 WHAT WE DO NOT DO (on purpose):
   * We do NOT set a blanket "block all inbound" on the Domain profile. A DC needs
     a large, dynamic set of ports for AD/replication/auth; blanket-deny is how
     teams cascade-fail. We enable the firewall, make sure the built-in rule groups
     for the scored + AD services are ON, and add explicit allows as a safety net.
   * We do NOT enable an aggressive account-lockout policy by default - the scoring
     engine logs in repeatedly and a tight lockout can lock the scored account out
     (a self-inflicted outage). See the note in -Aggressive.
   * We do NOT change the DC's IP, the primary admin's password, or disable RDP/WinRM.

 USAGE (run in an elevated PowerShell):
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\Harden-DC.ps1                 # safe hardening + baseline
   .\Harden-DC.ps1 -DryRun         # PREVIEW every change, modify nothing
   .\Harden-DC.ps1 -Aggressive     # also: tighten Public-profile inbound, disable
                                    # print spooler (a common DC attack surface).
                                    # Combine with -DryRun to preview it.
   .\Harden-DC.ps1 -BaselineOnly   # just snapshot state, change nothing

 OUTPUT
   Baseline + run log -> .\dc_baseline_<timestamp>\
===============================================================================
#>

[CmdletBinding()]
param(
    [switch]$DryRun,
    [switch]$Aggressive,
    [switch]$BaselineOnly
)

$ErrorActionPreference = 'Continue'   # like 'set -u' not 'set -e' - keep going on errors

# ---- must be elevated -------------------------------------------------------
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run this in an ELEVATED PowerShell (Run as Administrator)."; exit 1
}

# ---- where output goes ------------------------------------------------------
$ts      = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutDir  = Join-Path (Get-Location) "dc_baseline_$ts"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Log     = Join-Path $OutDir 'harden_dc.log'

function Log([string]$m){ $m | Tee-Object -FilePath $Log -Append }
function Sect([string]$m){ Log ""; Log ("========== {0} ==========" -f $m) }

# Do-Step runs a change unless -DryRun. $desc is printed either way.
function Do-Step([string]$desc,[scriptblock]$action){
    if ($DryRun){ Log "  [dry-run] would: $desc"; return }
    try { & $action; Log "  [applied] $desc" }
    catch { Log "  [!] failed: $desc  -> $($_.Exception.Message)" }
}

# =============================================================================
# 1. BASELINE (read-only) - capture state so you can diff after a Red-Team hit.
# =============================================================================
Sect "BASELINE capture -> $OutDir"
try {
    Get-LocalGroupMember -Group 'Administrators' 2>$null |
        Select-Object Name,PrincipalSource | Out-File "$OutDir\local_admins.txt"
} catch {}
# Domain Admins (this is a DC)
try { Get-ADGroupMember 'Domain Admins' 2>$null | Select-Object name,objectClass |
        Out-File "$OutDir\domain_admins.txt" } catch {}
Get-Service 2>$null | Where-Object Status -eq 'Running' |
    Select-Object Name,DisplayName | Sort-Object Name | Out-File "$OutDir\services_running.txt"
Get-NetTCPConnection -State Listen 2>$null |
    Select-Object LocalAddress,LocalPort,OwningProcess | Sort-Object LocalPort |
    Out-File "$OutDir\listening_ports.txt"
Get-ScheduledTask 2>$null | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
    Select-Object TaskName,TaskPath,State | Out-File "$OutDir\scheduled_tasks_nonms.txt"
'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce' | ForEach-Object {
    if (Test-Path $_){ Get-Item $_ | Select-Object -ExpandProperty Property |
        ForEach-Object { "$_ = $((Get-ItemProperty (Split-Path $_ -Parent)).$_)" } }
} 2>$null | Out-File "$OutDir\run_keys.txt"
Log "Baseline written. Re-run Hunt-DC.ps1 and compare these files after any incident."

if ($BaselineOnly){ Log "`n[i] -BaselineOnly: stopping after snapshot. Nothing changed."; exit 0 }

# =============================================================================
# 2. RDP - keep it ENABLED (scored) but require Network Level Authentication.
# =============================================================================
Sect "RDP: keep enabled, require NLA"
Do-Step "RDP enabled (fDenyTSConnections=0)" {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
        -Name fDenyTSConnections -Value 0
}
Do-Step "RDP requires NLA (UserAuthentication=1)" {
    Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
        -Name UserAuthentication -Value 1
}

# =============================================================================
# 3. SMBv1 OFF (legacy, exploited; not needed for AD). SMBv2/3 stay ON.
# =============================================================================
Sect "Disable SMBv1 (keep SMBv2/3 for AD)"
Do-Step "Disable SMBv1 server protocol" {
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
}

# =============================================================================
# 4. FIREWALL - enable it; make sure scored + AD rule groups are ON; add explicit
#    allows for the scored ports. We do NOT blanket-deny inbound on Domain profile.
# =============================================================================
Sect "Windows Firewall: enable + ensure scored/AD services allowed"
Do-Step "Enable firewall on all profiles" {
    Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True
}
# Turn ON the built-in inbound rule groups the DC needs (idempotent).
$groups = @(
  'DNS Service','Active Directory Domain Services','Kerberos Key Distribution Center',
  'Remote Desktop','Windows Remote Management','Core Networking','File and Printer Sharing'
)
foreach($g in $groups){
    Do-Step "Enable firewall rule group '$g'" { Enable-NetFirewallRule -DisplayGroup $g -ErrorAction SilentlyContinue }
}
# Explicit safety-net allows for the scored ports (in case a group is missing).
$allow = @(
  @{N='DNS-TCP';P=53;Pr='TCP'}, @{N='DNS-UDP';P=53;Pr='UDP'},
  @{N='RDP';P=3389;Pr='TCP'},   @{N='WinRM-HTTP';P=5985;Pr='TCP'},
  @{N='WinRM-HTTPS';P=5986;Pr='TCP'}
)
foreach($a in $allow){
    Do-Step "Allow inbound $($a.N) $($a.Pr)/$($a.P)" {
        if (-not (Get-NetFirewallRule -DisplayName "eCitadel-$($a.N)" -ErrorAction SilentlyContinue)){
            New-NetFirewallRule -DisplayName "eCitadel-$($a.N)" -Direction Inbound -Action Allow `
                -Protocol $a.Pr -LocalPort $a.P -Profile Any | Out-Null
        }
    }
}

# =============================================================================
# 5. PASSWORD POLICY (domain) - tighten, but no risky lockout policy by default.
# =============================================================================
Sect "Domain password policy"
Do-Step "Set default domain password policy (min 14, complexity, 60-day max, 24 history)" {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    Set-ADDefaultDomainPasswordPolicy -Identity (Get-ADDomain).DistinguishedName `
        -MinPasswordLength 14 -ComplexityEnabled $true `
        -MaxPasswordAge (New-TimeSpan -Days 60) -MinPasswordAge (New-TimeSpan -Days 1) `
        -PasswordHistoryCount 24
}

# =============================================================================
# 6. DEFENDER ON + GUEST OFF + AUDITING ON  (all safe, all help forensics)
# =============================================================================
Sect "Defender on, Guest off, auditing on"
Do-Step "Defender real-time protection ON" {
    Set-MpPreference -DisableRealtimeMonitoring $false
}
Do-Step "Disable Guest account (domain + local if present)" {
    try { Get-ADUser -Identity Guest -ErrorAction Stop | Disable-ADAccount } catch {}
    try { Disable-LocalUser -Name Guest -ErrorAction Stop } catch {}
}
# Enable the audit categories that catch Red-Team behaviour.
$audits = @('Logon','Logoff','Account Lockout','User Account Management',
            'Security Group Management','Process Creation','Audit Policy Change')
foreach($cat in $audits){
    Do-Step "Audit '$cat' success+failure" {
        & auditpol /set /subcategory:"$cat" /success:enable /failure:enable | Out-Null
    }
}

# =============================================================================
# 7. AGGRESSIVE extras (opt-in) - still scoring-safe.
# =============================================================================
if ($Aggressive){
    Sect "AGGRESSIVE extras"
    # The DC should never be on the Public profile; block inbound THERE only.
    Do-Step "[aggressive] Public profile default inbound = Block" {
        Set-NetFirewallProfile -Profile Public -DefaultInboundAction Block
    }
    # Print Spooler on a DC is a classic attack surface (PrintNightmare) and is not
    # a scored service here. Disable it. (Reversible: Set-Service Spooler -StartupType Automatic; Start-Service Spooler)
    Do-Step "[aggressive] Stop + disable Print Spooler" {
        Stop-Service Spooler -Force -ErrorAction SilentlyContinue
        Set-Service Spooler -StartupType Disabled
    }
    Log "  NOTE: An aggressive ACCOUNT-LOCKOUT policy is intentionally NOT set - it can"
    Log "        lock out the scoring engine's repeated logins. If you must, set a HIGH"
    Log "        threshold with a short duration and watch the scoreboard."
}

Sect "DONE"
Log "Hardening complete. Baseline + log are in: $OutDir"
Log "Next: run  .\Hunt-DC.ps1   (read-only) and  .\Watch-DCServices.ps1  (monitor)."
if ($DryRun){ Log "(This was a DRY RUN - nothing was actually changed.)" }
