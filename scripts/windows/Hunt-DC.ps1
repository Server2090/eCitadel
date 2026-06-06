<#
===============================================================================
 Hunt-DC.ps1  -  eCitadel Team 76  -  cabal (Windows Server 2022 DC)
===============================================================================
 READ-ONLY. Hunts the persistence + backdoor techniques the Red Team has planted
 on the Windows DC in past seasons. It CHANGES NOTHING - it prints findings so you
 can (1) record IOCs for the Incident-Report inject, then (2) remediate by hand.

 What it looks for (mapped to known Season III DC implants):
   * Local Administrators / Domain Admins      (new backdoor admins)
   * Run / RunOnce autostart keys              (generic persistence)
   * Image File Execution Options "Debugger"   (sticky-keys / utilman hijack)
   * AppInit_DLLs                              (King's Guard userland rootkit)
   * LSA Notification/Security/Auth packages   (Nosferatu / malicious password filter)
   * Winlogon Userinit / Shell                 (logon hijack)
   * WMI permanent event subscriptions         (fileless persistence)
   * Non-Microsoft services w/ odd binary paths(service backdoors, e.g. ISRAID)
   * Non-Microsoft scheduled tasks
   * Binaries that CLAIM "Microsoft" but whose signature does NOT validate
   * C:\ProgramData\ssh\administrators_authorized_keys (attacker key + ACL check)
   * Unusual listening ports, hosts-file edits, recently-created system files

 USAGE (elevated PowerShell):
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\Hunt-DC.ps1
===============================================================================
#>

[CmdletBinding()]
param([string]$ReportDir = (Get-Location))

$ErrorActionPreference = 'SilentlyContinue'
$ts      = Get-Date -Format 'yyyyMMdd_HHmmss'
$Report  = Join-Path $ReportDir "hunt_dc_$ts.log"
$Findings = New-Object System.Collections.Generic.List[string]

function Log([string]$m){ $m | Tee-Object -FilePath $Report -Append | Out-Null; Write-Host $m }
function Sect([string]$m){ Log ""; Log ("========== {0} ==========" -f $m) }
function Find([string]$sev,[string]$m){ $line = "  [$sev] $m"; $Findings.Add($line); Log $line }

Log "eCitadel DC hunt  -  $(Get-Date)  -  read-only"
Log "Host: $env:COMPUTERNAME"

# Microsoft-standard service binary locations - anything outside these is worth a look.
$stdPaths = @('C:\Windows\System32','C:\Windows\SysWOW64','C:\Windows\Microsoft.NET',
              'C:\Program Files\Windows Defender','C:\Windows\ADWS','C:\Windows\System32\dns')

# =============================================================================
# 1. Administrators (local + domain)
# =============================================================================
Sect "Privileged group membership"
Get-LocalGroupMember -Group 'Administrators' | ForEach-Object {
    Log ("  local admin: {0} ({1})" -f $_.Name,$_.PrincipalSource)
}
try {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
    Get-ADGroupMember 'Domain Admins' | ForEach-Object { Log ("  Domain Admin: {0}" -f $_.SamAccountName) }
    Get-ADGroupMember 'Enterprise Admins' | ForEach-Object { Log ("  Enterprise Admin: {0}" -f $_.SamAccountName) }
} catch {}
Log "  -> Verify EVERY account above is one you expect. An unexpected admin = backdoor."

# =============================================================================
# 2. Run / RunOnce autostart
# =============================================================================
Sect "Run / RunOnce autostart entries"
$runKeys = @(
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
 'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run',
 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run')
foreach($k in $runKeys){
    if (Test-Path $k){
        (Get-Item $k).Property | ForEach-Object {
            $v = (Get-ItemProperty $k).$_
            Log "  $k :: $_ = $v"
            if ($v -match 'powershell|cmd\.exe|\.vbs|\.ps1|mshta|rundll32|regsvr32|certutil|bitsadmin|\\Temp\\|\\Users\\Public\\|http'){
                Find HIGH "Suspicious autostart in $k :: $_ = $v"
            }
        }
    }
}

# =============================================================================
# 3. Image File Execution Options "Debugger" - sticky-keys / utilman hijack
#    A Debugger value on sethc.exe/utilman.exe/osk.exe/etc. = pre-auth SYSTEM shell.
# =============================================================================
Sect "Image File Execution Options (accessibility / debugger hijack)"
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
if (Test-Path $ifeo){
    Get-ChildItem $ifeo | ForEach-Object {
        $dbg = (Get-ItemProperty $_.PSPath).Debugger
        if ($dbg){
            $exe = Split-Path $_.PSChildName -Leaf
            $sev = 'MED'
            if ($exe -match '^(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe$'){ $sev='HIGH' }
            Find $sev "IFEO Debugger on $exe -> $dbg  (accessibility/sticky-keys backdoor if it's a shell)"
        }
    }
}

# =============================================================================
# 4. AppInit_DLLs - King's Guard userland rootkit loads a DLL into every process
# =============================================================================
Sect "AppInit_DLLs"
foreach($w in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows',
              'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows'){
    if (Test-Path $w){
        $p = Get-ItemProperty $w
        if ($p.AppInit_DLLs -and $p.AppInit_DLLs.Trim() -ne ''){
            Find HIGH "AppInit_DLLs set ($w): '$($p.AppInit_DLLs)' (LoadAppInit_DLLs=$($p.LoadAppInit_DLLs)) - userland rootkit (King's Guard)"
        }
    }
}

# =============================================================================
# 5. LSA packages - Nosferatu / malicious password-filter DLLs
#    A DLL added to Notification/Security/Authentication Packages runs inside LSASS.
# =============================================================================
Sect "LSA security/notification/authentication packages"
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
foreach($prop in 'Notification Packages','Security Packages','Authentication Packages'){
    $vals = $lsa.$prop
    if ($vals){
        foreach($v in $vals){
            # Known-good examples: scecli, rassfm, kerberos, msv1_0, schannel, wdigest, tspkg, pku2u, cloudAP, negoexts
            if ($v -notmatch '^(scecli|rassfm|kerberos|msv1_0|schannel|wdigest|tspkg|pku2u|cloudAP|negoexts|""|)$'){
                Find HIGH "Unusual LSA $prop entry: '$v' - possible LSASS/password-filter backdoor (Nosferatu)"
            } else { Log "  LSA $prop: $v" }
        }
    }
}

# =============================================================================
# 6. Winlogon logon hijack
# =============================================================================
Sect "Winlogon Userinit / Shell"
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl.Userinit -and $wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?\s*$'){
    Find HIGH "Winlogon Userinit altered: $($wl.Userinit)"
} else { Log "  Userinit OK: $($wl.Userinit)" }
if ($wl.Shell -and $wl.Shell -notmatch '^explorer\.exe\s*$'){
    Find HIGH "Winlogon Shell altered: $($wl.Shell)"
} else { Log "  Shell OK: $($wl.Shell)" }

# =============================================================================
# 7. WMI permanent event subscriptions (fileless persistence)
# =============================================================================
Sect "WMI permanent event subscriptions"
$flt = Get-WmiObject -Namespace root\subscription -Class __EventFilter
$con = Get-WmiObject -Namespace root\subscription -Class __EventConsumer
$bnd = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
if ($flt){ foreach($f in $flt){ Find HIGH "WMI __EventFilter: '$($f.Name)' query: $($f.Query)" } }
if ($con){ foreach($c in $con){ Find HIGH "WMI __EventConsumer: '$($c.Name)' -> $($c.CommandLineTemplate)$($c.ScriptText)" } }
if (-not $flt -and -not $con){ Log "  No custom WMI subscriptions found." }

# =============================================================================
# 8. Services - non-Microsoft / odd binary path / inside Temp or user dirs
# =============================================================================
Sect "Services with suspicious image paths"
Get-CimInstance Win32_Service | ForEach-Object {
    $path = $_.PathName
    if (-not $path){ return }
    $clean = ($path -replace '^"','' -replace '".*$','')   # strip args/quotes
    $bad = $false
    if ($clean -match '\\Temp\\|\\Users\\|\\ProgramData\\(?!.*\\Microsoft)|\\PerfLogs\\|\\\$Recycle'){ $bad=$true }
    $inStd = $false; foreach($s in $stdPaths){ if ($clean -like "$s*"){ $inStd=$true } }
    if (($bad) -or (-not $inStd -and $clean -notlike 'C:\Program Files*' -and $clean -ne '')){
        Find MED "Service '$($_.Name)' image path is non-standard: $path (state=$($_.State), start=$($_.StartMode))"
    }
}

# =============================================================================
# 9. Non-Microsoft scheduled tasks
# =============================================================================
Sect "Non-Microsoft scheduled tasks"
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $act = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' ; '
    Log "  task: $($_.TaskPath)$($_.TaskName)  ->  $act"
    if ($act -match 'powershell|cmd\.exe|mshta|rundll32|regsvr32|certutil|bitsadmin|\\Temp\\|http|-enc|FromBase64'){
        Find HIGH "Suspicious scheduled task: $($_.TaskPath)$($_.TaskName) -> $act"
    }
}

# =============================================================================
# 10. Fake-"Microsoft" signatures - binaries that claim Microsoft but don't validate
#     (Season III: binaries signed by a bogus "Microsoft Corporation" CA.)
# =============================================================================
Sect "Authenticode signatures that claim Microsoft but do NOT validate"
$scan = @('C:\Windows\System32','C:\Program Files','C:\ProgramData','C:\Users\Public') 
foreach($dir in $scan){
    Get-ChildItem $dir -Recurse -Include *.exe,*.dll -ErrorAction SilentlyContinue |
      Select-Object -First 4000 | ForEach-Object {
        $sig = Get-AuthenticodeSignature $_.FullName
        if ($sig -and $sig.SignerCertificate){
            $subj = $sig.SignerCertificate.Subject
            if ($subj -match 'Microsoft' -and $sig.Status -ne 'Valid'){
                Find HIGH "Binary claims Microsoft but signature is '$($sig.Status)': $($_.FullName)"
            }
        }
    }
}

# =============================================================================
# 11. OpenSSH administrators_authorized_keys - attacker key + ACL hardening
#     (Also the target file for the 'SSH pubkey to Windows' inject.)
# =============================================================================
Sect "OpenSSH administrators_authorized_keys"
$akf = 'C:\ProgramData\ssh\administrators_authorized_keys'
if (Test-Path $akf){
    Log "  File exists: $akf"
    Get-Content $akf | ForEach-Object { Log "    key: $_" }
    Find MED "Review every key in $akf - an attacker key here = passwordless admin SSH."
    # ACL must be SYSTEM + Administrators ONLY (or sshd refuses it / it's world-abusable).
    $acl = Get-Acl $akf
    foreach($ace in $acl.Access){
        if ($ace.IdentityReference -notmatch 'SYSTEM|Administrators'){
            Find MED "administrators_authorized_keys grants '$($ace.IdentityReference)' - should be SYSTEM + Administrators ONLY."
        }
    }
} else { Log "  Not present (fine unless the SSH-key inject asks you to create it)." }

# =============================================================================
# 12. Listening ports / hosts file / recent system files
# =============================================================================
Sect "Listening TCP ports"
Get-NetTCPConnection -State Listen | Sort-Object LocalPort -Unique | ForEach-Object {
    $proc = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    Log ("  {0,-6} pid {1} ({2})" -f $_.LocalPort,$_.OwningProcess,$proc)
    if ($_.LocalPort -in 4444,1337,31337,5555,6666,8443,9001 -or $proc -match 'nc|ncat|powershell'){
        Find HIGH "Listener on port $($_.LocalPort) owned by $proc (pid $($_.OwningProcess)) - possible C2/backdoor."
    }
}
Sect "Hosts file"
$hosts = 'C:\Windows\System32\drivers\etc\hosts'
$hl = Get-Content $hosts | Where-Object { $_ -match '^\s*[0-9]' }
if ($hl){ foreach($h in $hl){ Find MED "hosts entry (redirect?): $h" } } else { Log "  No active host overrides." }

Sect "Recently-created executables in system dirs (last 3 days)"
$cut = (Get-Date).AddDays(-3)
Get-ChildItem 'C:\Windows\System32','C:\Windows','C:\ProgramData' -Include *.exe,*.dll -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.CreationTime -gt $cut } | Select-Object -First 40 | ForEach-Object {
    Find MED "Recently created: $($_.FullName)  ($($_.CreationTime))"
  }

# =============================================================================
# SUMMARY
# =============================================================================
Sect "FINDINGS SUMMARY (use this to start your Incident Report)"
if ($Findings.Count -eq 0){ Log "  No high-confidence findings - but verify admins, services, and tasks by eye." }
else { $Findings | ForEach-Object { Log $_ } }
Log ""
Log "For each HIGH: record what it is + where it points (IP/file) for the IR inject,"
Log "THEN remediate (remove key/DLL, delete task/service, clear the registry value)."
Log "Report saved: $Report"
