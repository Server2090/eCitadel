<#
===============================================================================
 seed_windows.ps1  -  eCitadel Team 76 PRACTICE LAB  -  vulnerable DC builder
===============================================================================
 Turns a FRESH, ISOLATED Windows Server practice VM into a realistic eCitadel
 Domain Controller target: it plants the find-and-fix misconfigs from the
 Win2016 practice key AND inert, DETECTABLE stand-ins for the Season III DC
 implants, so you can practice Harden-DC.ps1 / Hunt-DC.ps1 / Watch-DCServices.ps1.

 ###########################################################################
 #  DANGER - THIS DELIBERATELY WEAKENS THE MACHINE (backdoor admin, Guest   #
 #  on, SMBv1 on, firewall off, sticky-keys backdoor). Run ONLY on an        #
 #  ISOLATED throwaway VM. Take a checkpoint AFTER seeding to reset.         #
 #  NOTE: this script intentionally does NOT modify LSA Security/Notification#
 #  Packages - a bad password-filter DLL can lock you out of the box. Real   #
 #  "Nosferatu" lives there; Hunt-DC.ps1 checks it; we just don't simulate   #
 #  it destructively.                                                        #
 ###########################################################################

 USAGE (elevated PowerShell on the practice VM):
   Set-ExecutionPolicy -Scope Process Bypass -Force
   .\seed_windows.ps1 -IUnderstand          # plant everything
   .\seed_windows.ps1 -AnswerKey            # just print what a full seed plants
   .\seed_windows.ps1 -Teardown             # best-effort reverse
===============================================================================
#>

[CmdletBinding()]
param([switch]$IUnderstand, [switch]$AnswerKey, [switch]$Teardown)

$ErrorActionPreference = 'Continue'

function Answer {
@"

================= PRACTICE ANSWER KEY (what was planted) ====================
A. FIND-AND-FIX / SCORING (Harden-DC.ps1 fixes most; Hunt-DC.ps1 surfaces the rest):
   1. Backdoor LOCAL ADMIN: 'svc_backup' (in Administrators)
   2. Guest account ENABLED
   3. Weak password policy (min length 4, no complexity, no lockout)
   4. SMBv1 ENABLED (legacy/exploitable)
   5. RDP Network Level Authentication DISABLED
   6. Windows Firewall turned OFF on all profiles
   7. hosts file redirect entry added

B. RED-TEAM PERSISTENCE (Hunt-DC.ps1 should catch each):
   8.  IFEO 'Debugger' on sethc.exe -> cmd.exe  (sticky-keys pre-auth SYSTEM shell)
   9.  AppInit_DLLs set to a planted DLL path   (King's-Guard-style)
   10. Run key 'WinUpdater' launching a script from ProgramData
   11. Non-Microsoft scheduled task 'SysHealth' running encoded PowerShell
   12. Service 'WinTelemetry' whose binary lives in C:\ProgramData (non-standard)
   13. Planted 'msupdate.exe' in C:\ProgramData (stands in for a fake-MS binary)
   14. WMI permanent event subscription (filter+consumer+binding), if it registered
   15. Attacker key in C:\ProgramData\ssh\administrators_authorized_keys with a
       loose ACL (only if OpenSSH Server is installed)
   NOT simulated (on purpose): LSA password-filter DLL (would risk locking you out).
============================================================================
"@
}

if ($AnswerKey) { Answer; return }

if ($Teardown) {
    Write-Host "[teardown] reversing planted items (best-effort)..."
    try { Remove-LocalUser svc_backup -ErrorAction SilentlyContinue } catch {}
    try { Disable-LocalUser Guest -ErrorAction SilentlyContinue } catch {}
    reg delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /f 2>$null
    try { Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -Value '' } catch {}
    try { Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name LoadAppInit_DLLs -Value 0 } catch {}
    try { Remove-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name WinUpdater -ErrorAction SilentlyContinue } catch {}
    schtasks /delete /tn SysHealth /f 2>$null
    sc.exe delete WinTelemetry 2>$null
    Remove-Item C:\ProgramData\msupdate.exe,C:\ProgramData\winupd.ps1,C:\ProgramData\appinit.dll -ErrorAction SilentlyContinue
    try { Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object { $_.Filter -match 'SeedFilter' } | Remove-WmiObject } catch {}
    try { Get-WmiObject -Namespace root\subscription -Class __EventFilter | Where-Object Name -eq 'SeedFilter' | Remove-WmiObject } catch {}
    try { Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer | Where-Object Name -eq 'SeedConsumer' | Remove-WmiObject } catch {}
    # restore hosts (strip our marker line)
    (Get-Content C:\Windows\System32\drivers\etc\hosts) -notmatch 'seed-practice' |
        Set-Content C:\Windows\System32\drivers\etc\hosts
    Write-Host "[teardown] done. Re-enable firewall + SMB hardening via Harden-DC.ps1. Reboot recommended."
    return
}

if (-not $IUnderstand) {
    Write-Error "Refusing to run. This WEAKENS the box. Re-run with -IUnderstand (isolated VM only)."
    return
}
$me = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $me.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "Run elevated (Administrator)."; return
}

Write-Host "[seed] planting Windows DC practice vulnerabilities..."

# --- A. scoring / find-and-fix ----------------------------------------------
# 1. backdoor local admin
try {
    $pw = ConvertTo-SecureString 'Password1' -AsPlainText -Force
    if (-not (Get-LocalUser svc_backup -ErrorAction SilentlyContinue)) {
        New-LocalUser -Name svc_backup -Password $pw -FullName 'Backup Service' -Description 'svc' | Out-Null
    }
    Add-LocalGroupMember -Group Administrators -Member svc_backup -ErrorAction SilentlyContinue
} catch {}
# 2. Guest on
try { Enable-LocalUser Guest } catch {}
# 3. weak password policy
net accounts /minpwlen:4 /maxpwage:unlimited /uniquepw:0 2>$null | Out-Null
secedit /export /cfg C:\ProgramData\sec.cfg 2>$null | Out-Null
# (complexity off via secedit if you want a stricter sim; net accounts covers length/age)
# 4. SMBv1 on
try { Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force } catch {}
# 5. RDP NLA off
try { Set-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 0 } catch {}
# 6. firewall off
try { Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled False } catch {}
# 7. hosts redirect
Add-Content C:\Windows\System32\drivers\etc\hosts "`n203.0.113.50 update.microsoft.com # seed-practice"

# --- B. red-team persistence (inert but detectable) -------------------------
# 8. sticky-keys IFEO debugger
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v Debugger /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f 2>$null
# 9. AppInit_DLLs
"stub appinit dll" | Out-File C:\ProgramData\appinit.dll -Encoding ascii
try {
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name AppInit_DLLs -Value 'C:\ProgramData\appinit.dll'
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows' -Name LoadAppInit_DLLs -Value 1
} catch {}
# 10. Run key -> script in ProgramData
"Write-Output beacon" | Out-File C:\ProgramData\winupd.ps1 -Encoding ascii
try { Set-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run' -Name WinUpdater -Value 'powershell -w hidden -ep bypass -File C:\ProgramData\winupd.ps1' } catch {}
# 11. scheduled task running encoded powershell
schtasks /create /tn SysHealth /sc minute /mo 10 /ru SYSTEM /f /tr "powershell -enc VwByAGkAdABlAA==" 2>$null | Out-Null
# 12. service with non-standard binary path + 13. planted "msupdate.exe"
Copy-Item C:\Windows\System32\cmd.exe C:\ProgramData\msupdate.exe -ErrorAction SilentlyContinue
sc.exe create WinTelemetry binPath= "C:\ProgramData\msupdate.exe" start= demand 2>$null | Out-Null
# 14. WMI permanent subscription (filter + consumer + binding)
try {
    $f = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
        Name='SeedFilter'; EventNamespace='root\cimv2'; QueryLanguage='WQL';
        Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"}
    $c = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
        Name='SeedConsumer'; CommandLineTemplate='cmd.exe /c echo seed'}
    Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{Filter=$f; Consumer=$c} | Out-Null
} catch { Write-Host "    (WMI subscription not registered: $($_.Exception.Message))" }
# 15. attacker SSH key (only if OpenSSH server present)
$akf = 'C:\ProgramData\ssh\administrators_authorized_keys'
if (Test-Path (Split-Path $akf)) {
    'ssh-rsa AAAAB3NzaC1yc2EATTACKERKEY attacker' | Out-File $akf -Encoding ascii
    icacls $akf /grant "Everyone:F" 2>$null | Out-Null   # deliberately loose ACL
}

Answer
Write-Host "`n[seed] DONE. Practice against this DC:"
Write-Host "    .\Hunt-DC.ps1        (should flag the items in section B)"
Write-Host "    .\Harden-DC.ps1      (should fix section A: RDP NLA, SMBv1, firewall, Guest, policy)"
Write-Host "Reset by restoring your post-seed checkpoint (or .\seed_windows.ps1 -Teardown)."
