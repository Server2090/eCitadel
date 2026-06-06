# Windows DC pack — cabal (Windows Server 2022, `rrintel.internal`)

**Team 76 · RR Intel / eCitadel Season IV**

`cabal` is the **Domain Controller** and the most important box you own: it serves
**DNS (53)**, **RDP (3389)**, and **WinRM (5985/5986)** as scored services, and almost
every *other* box's check authenticates against its **Active Directory**. If AD or DNS
goes down, scoring cascade-fails for the whole team. Treat availability as sacred.

> These are PowerShell scripts. They can't be run from Linux — run them **on cabal**,
> in an **elevated** PowerShell. The Linux kit (`scripts/`) covers `concierge` and
> `blacklist`; this folder is the DC equivalent.

---

## Running the scripts

In an elevated PowerShell on cabal:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force   # allow these scripts for this session only

.\Harden-DC.ps1 -DryRun         # 1) PREVIEW the safe hardening (changes nothing)
.\Harden-DC.ps1                 # 2) apply safe hardening + write a baseline
.\Hunt-DC.ps1                   # 3) read-only hunt for planted persistence
.\Watch-DCServices.ps1          # 4) leave running in a window to catch outages
```

- **`Harden-DC.ps1`** — safe, reversible hardening (RDP+NLA, SMBv1 off, firewall on
  with scored/AD rule groups enabled, domain password policy, Defender on, Guest off,
  audit logging on). `-DryRun` previews; `-Aggressive` adds Public-profile inbound block
  and disables Print Spooler; `-BaselineOnly` just snapshots.
- **`Hunt-DC.ps1`** — READ-ONLY. Surfaces the DC implant classes below; record IOCs for
  the IR inject, then remediate by hand.
- **`Watch-DCServices.ps1`** — probes DNS/RDP/WinRM/AD locally on an interval; warns at 3
  consecutive misses, alarms at 5 (the SLA penalty threshold).

### Why the hardening is deliberately gentle on a DC
A DC needs a **large, dynamic** set of inbound ports for AD, replication, Kerberos, LDAP,
RPC, etc. A blanket "block all inbound" is the classic way teams **cascade-fail** their
own scoring. So `Harden-DC.ps1` enables the firewall and the **built-in rule groups** for
the scored + AD services, adds explicit allows for 53/3389/5985/5986, and **does not** flip
the Domain profile to default-deny. It also **does not** set an aggressive account-lockout
policy — the scoring engine logs in repeatedly and a tight lockout can lock the **scorer**
out (a self-inflicted outage).

---

## DC implants to hunt (Season III playbook)

`Hunt-DC.ps1` checks each of these; here's what they are and how to remove them.

| Implant / technique | What it is | Find | Remove |
|---|---|---|---|
| **Sticky-keys / utilman hijack (IFEO)** | A `Debugger` value under *Image File Execution Options* for `sethc.exe`/`utilman.exe`/`osk.exe` etc. gives a **pre-auth SYSTEM shell** from the logon screen | Hunt flags IFEO Debugger keys | Delete the `Debugger` value for that exe |
| **King's Guard (AppInit_DLLs)** | A DLL listed in `AppInit_DLLs` loads into **every** user-mode process (userland rootkit) | Hunt flags non-empty AppInit_DLLs | Clear `AppInit_DLLs`, set `LoadAppInit_DLLs=0`, remove the DLL |
| **Nosferatu (LSA/NLM backdoor)** | A malicious DLL in LSA `Notification`/`Security`/`Authentication Packages` runs **inside LSASS**, harvests/handles auth (the "invalid password" weirdness on login) | Hunt flags unknown LSA package entries | Remove the rogue entry, reboot, rotate krbtgt + affected creds |
| **ISRAID (malicious IIS module)** | A native/managed **IIS module** backdooring the web stack (if IIS is present on the DC/web) | `appcmd list modules`; Hunt flags odd service/binary paths | `appcmd uninstall module`, remove the DLL, restart IIS |
| **Malicious WFP filter** | A Windows Filtering Platform rule redirecting/permitting attacker traffic | `netsh wfp show filters` (manual) | Remove the filter; re-check firewall |
| **Goose Desktop** | Dropped at ~4h; killing it can **blue-screen** (treated as critical) | Visible process/file | Find and remove its **persistence**, then remove the binary; don't just kill it |
| **Fake-"Microsoft" signed binaries** | Tools signed by a **bogus "Microsoft Corporation" CA** to look legit | Hunt flags binaries that claim Microsoft but whose signature **doesn't validate** | Remove the binary + the rogue CA from the cert store |
| **Backdoor admins** | Extra Local Administrators / Domain Admins / Enterprise Admins | Hunt lists all three groups | Remove from group; investigate how they were added |
| **WMI subscription** | Fileless persistence via `__EventFilter`+`__EventConsumer` | Hunt lists custom subscriptions | Delete the filter, consumer, and binding |

After any LSASS-resident implant (Nosferatu/password filter) or suspected credential
theft, plan to **rotate krbtgt** (twice) and the affected service accounts.

---

## The inject no team has solved in 3 years: SSH public-key auth to Windows

If the "add an admin + SSH public-key auth" inject appears, this is the winning recipe —
the trap is **where the key goes** and **its ACL**:

1. **Install the OpenSSH Server** feature and start it:
   ```powershell
   Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
   Start-Service sshd; Set-Service sshd -StartupType Automatic
   ```
2. **Create/confirm the admin** is in the domain **and** in **Domain Admins** (show it in
   your memo). Make sure the box is properly domain-joined (ties to the domain-join inject).
3. **Key location is the whole game.** Members of Administrators do **NOT** use their home
   `~\.ssh\authorized_keys`. They share **one** file:
   ```
   C:\ProgramData\ssh\administrators_authorized_keys
   ```
   Put the public key there (one key per line).
4. **Fix the ACL** or sshd silently refuses it. It must grant **SYSTEM** and
   **Administrators** only — remove inherited "Authenticated Users", and it must not be
   world-writable:
   ```powershell
   icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r
   icacls C:\ProgramData\ssh\administrators_authorized_keys /grant "SYSTEM:F" "Administrators:F"
   icacls C:\ProgramData\ssh\administrators_authorized_keys /remove "Authenticated Users" "Users" "Everyone"
   ```
5. Confirm the sshd config doesn't override this (the default `sshd_config` has a Match
   block pointing administrators at that file — leave it). Restart sshd, then test
   `ssh admin@cabal` with the private key. Document the steps + a successful login.

> `Hunt-DC.ps1` also reads this file and checks its ACL — so it doubles as a way to catch
> an **attacker's** key planted there.

---

## Domain-join inject (for the two Linux boxes)

Joining `concierge`/`blacklist` to `rrintel.internal` (handled on the Linux side, but the
DC is the authority):

- Use **realmd + SSSD** on Linux; authenticate with a **DOMAIN ADMIN** (e.g.
  `Administrator@rrintel.internal`), not a local user.
- Pattern: `realm join --user=Administrator rrintel.internal` (point DNS at cabal first).
- If Kerberos crypto errors appear, fix the allowed enc-types on the DC or in the Linux
  `krb5.conf`. Show the successful `realm list` / `id user@rrintel.internal` in your memo.

---

## Quick reference

| Need | Command (elevated PowerShell on cabal) |
|---|---|
| Preview hardening | `.\Harden-DC.ps1 -DryRun` |
| Apply safe hardening | `.\Harden-DC.ps1` |
| Aggressive extras | `.\Harden-DC.ps1 -Aggressive` |
| Hunt persistence | `.\Hunt-DC.ps1` |
| Monitor services | `.\Watch-DCServices.ps1` |
| List IIS modules | `C:\Windows\System32\inetsrv\appcmd list modules` |
| Show WFP filters | `netsh wfp show filters` |
| Local admins | `Get-LocalGroupMember Administrators` |
| Domain Admins | `Get-ADGroupMember 'Domain Admins'` |
| Reset a service | `Set-Service <name> -StartupType Automatic; Start-Service <name>` |
