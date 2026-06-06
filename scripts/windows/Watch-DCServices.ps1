<#
===============================================================================
 Watch-DCServices.ps1  -  eCitadel Team 76  -  cabal (Windows Server 2022 DC)
===============================================================================
 Live monitor for the DC's SCORED services. Probes them locally every interval and
 warns the moment one stops answering, so you can recover before the SLA penalty.

 Scored here: DNS (53), RDP (3389), WinRM (5985/5986). AD health underpins almost
 every other team's check too, so we test AD/Netlogon as well.

 SLA reminder (from orientation): 5 CONSECUTIVE missed checks triggers the penalty.
 This script warns at 3 consecutive misses and alarms at 5 - per service.

 USAGE (elevated PowerShell):
   .\Watch-DCServices.ps1                # default 30s interval, runs until Ctrl-C
   .\Watch-DCServices.ps1 -Interval 20
   .\Watch-DCServices.ps1 -Once          # single pass (for scripting/cron)
===============================================================================
#>

[CmdletBinding()]
param([int]$Interval = 30, [switch]$Once)

$ErrorActionPreference = 'SilentlyContinue'
$miss = @{}   # consecutive-miss counter per service

function Probe-DNS {
    # Ask the DC to resolve its own domain locally.
    try {
        $dom = (Get-ADDomain).DNSRoot
        if (-not $dom){ $dom = $env:USERDNSDOMAIN }
        $r = Resolve-DnsName -Name $dom -Server 127.0.0.1 -ErrorAction Stop
        return [bool]$r
    } catch { return $false }
}
function Probe-Port([int]$p){
    try { return (Test-NetConnection -ComputerName 127.0.0.1 -Port $p -WarningAction SilentlyContinue -InformationLevel Quiet) }
    catch { return $false }
}
function Probe-WinRM { try { [bool](Test-WSMan -ComputerName localhost -ErrorAction Stop) } catch { $false } }
function Probe-AD {
    # Netlogon + a trivial directory read = AD is actually serving, not just "port open".
    try {
        $svc = (Get-Service Netlogon).Status -eq 'Running'
        $rd  = [bool](Get-ADDomain -ErrorAction Stop)
        return ($svc -and $rd)
    } catch { return $false }
}

function Check {
    $results = [ordered]@{
        'DNS(53)'      = (Probe-DNS)
        'RDP(3389)'    = (Probe-Port 3389)
        'WinRM(5985)'  = (Probe-Port 5985)
        'AD/Netlogon'  = (Probe-AD)
    }
    $stamp = Get-Date -Format 'HH:mm:ss'
    foreach($k in $results.Keys){
        if ($results[$k]){
            if ($miss[$k] -gt 0){ Write-Host "[$stamp] $k RECOVERED (was down $($miss[$k])x)" -ForegroundColor Green }
            $miss[$k] = 0
            Write-Host "[$stamp]  OK   $k"
        } else {
            $miss[$k] = [int]$miss[$k] + 1
            $c = $miss[$k]
            if ($c -ge 5){
                Write-Host "[$stamp] ALARM $k DOWN x$c  >>> SLA PENALTY RANGE - RECOVER NOW (DB->DNS->web order; it may be stopped/disabled/renamed, not firewalled)" -ForegroundColor Red
            } elseif ($c -ge 3){
                Write-Host "[$stamp]  WARN $k down x$c (penalty at 5 consecutive)" -ForegroundColor Yellow
            } else {
                Write-Host "[$stamp]  miss $k down x$c" -ForegroundColor DarkYellow
            }
        }
    }
}

Write-Host "Watching DC scored services every ${Interval}s (Ctrl-C to stop)..."
do {
    Check
    if (-not $Once){ Start-Sleep -Seconds $Interval }
} while (-not $Once)
