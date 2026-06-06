# Practice Lab — build your own vulnerable eCitadel targets in Proxmox

**Team 76 · RR Intel / eCitadel Season IV**

This folder builds **practice VMs** that mirror the competition boxes and are pre-loaded
with the past problems (the practice-round answer keys + the Season III Red-Team malware),
so you can rehearse the whole kit — `first5_secure.sh`, `audit_linux.sh`, `hunt_malware.sh`,
`build_golden_baseline.sh`, `defend_redteam.sh`, `anomaly_guard.py`, and the Windows/pfSense
packs — against a known, realistic target.

---

## Why this is a builder, not a `.qcow2` download

You asked for ready-made qcow2 disk images. Honest answer: those can't be produced in the
sandbox I'm running in (no virtualization, and the OS images can't be downloaded or — for
Windows/pfSense — legally redistributed from here). Shipping you a fake/empty `.qcow2` would
just waste your time.

Instead you get the thing that actually works and is how every vulnerable-VM project
(Metasploitable, DVWA, …) is distributed: a **builder + seeders** you run on *your* Proxmox
host. Proxmox has internet and KVM, so it pulls the **official, free** cloud images, and the
seeders plant the exact vulnerabilities. This is reproducible, inspectable, license-clean,
and the Linux seeder is **tested** — seeding a box and then running the kit catches every
planted indicator.

---

## What you need

- A **Proxmox VE 8.x** host (or adjust the `qm` commands for older versions).
- Internet on the Proxmox host (to fetch the cloud images).
- For Windows: a **Windows Server 2022 evaluation ISO** (free 180-day eval from Microsoft).
- For pfSense: the **pfSense CE installer ISO** (free from Netgate).
- An **isolated bridge** (e.g. `vmbr1`) with **no NAT/internet** for the seeded targets —
  the seeders create genuinely vulnerable accounts and backdoors, so keep them off any real
  network once seeded.

---

## Files in this folder

| File | What it is | Runs where |
|---|---|---|
| `build_proxmox_lab.sh` | downloads the Fedora 43 + Debian 13 cloud images and creates the two Linux VMs with cloud-init | **Proxmox host** |
| `seed_linux.sh` | plants the scoring vulns + Red-Team malware on a Fedora **or** Debian VM (auto-detects); prints an answer key | **inside each Linux VM** |
| `seed_windows.ps1` | plants DC misconfigs + inert, detectable Season III DC implants | **inside the Windows VM** (elevated) |
| `pfsense_setup.md` | import pfSense + the misconfigs to introduce by hand | **Proxmox + pfSense console** |
| `README_LAB.md` | this file | — |

---

## The workflow (Linux boxes)

```bash
# ON THE PROXMOX HOST:
./build_proxmox_lab.sh                      # fetch images + create VMs 9101 (Debian) & 9102 (Fedora)
qm start 9101 ; qm start 9102
qm snapshot 9101 clean ; qm snapshot 9102 clean    # <- a CLEAN restore point

# capture a GOLDEN baseline from the CLEAN box for build_golden_baseline.sh later:
scp ../scripts/build_golden_baseline.sh root@<deb-ip>:/root/
ssh root@<deb-ip> 'bash build_golden_baseline.sh --capture clean-deb'
scp -r root@<deb-ip>:/root/.../baselines/golden/clean-deb ./golden-deb   # keep it off-box

# now make it vulnerable:
scp seed_linux.sh root@<deb-ip>:/root/
ssh root@<deb-ip> 'bash seed_linux.sh --i-understand --with-live-procs'
qm snapshot 9101 seeded

# PRACTICE: copy your kit in and go
scp -r ../scripts root@<deb-ip>:/root/kit
ssh root@<deb-ip>
  cd kit
  sudo bash first5_secure.sh --dry-run        # preview
  sudo bash audit_linux.sh                    # should FAIL on the planted misconfigs
  sudo bash hunt_malware.sh                   # should flag the planted malware
  sudo bash build_golden_baseline.sh --compare /root/golden-deb   # surfaces what was added
  python3 anomaly_guard.py --selftest
  bash anomaly_lab.sh                          # watch the anomaly sensor fire

# RESET between attempts:
qm rollback 9101 seeded    # back to the vulnerable state
qm rollback 9101 clean     # back to pristine
```

Windows and pfSense follow the same idea — see `seed_windows.ps1` (run it inside the DC,
then practice `Hunt-DC.ps1`/`Harden-DC.ps1`) and `pfsense_setup.md`.

---

## Suggested topology (mirror the real event)

```
            [ vmbr0 = "WAN" ]              [ vmbr1 = "LAN", isolated, no internet ]
                  |                                   |
            thebox-practice (pfSense) ----------------+--- blacklist-practice (Debian, DB)
              WAN on vmbr0,  LAN 172.21.0.254/24      |--- concierge-practice (Fedora, web)
                                                      |--- cabal-practice   (Win 2022, DC)
```
Put the three target VMs on `vmbr1` with pfSense as their gateway, so you can also practice
the firewall rules end-to-end (allow scored ports in, lock egress out) against real traffic.

---

## Safety & honesty notes

- The seeders **deliberately weaken and backdoor** the VMs (empty-password and root-equivalent
  accounts, an SSH CA backdoor, sticky-keys hijack, etc.). That's the point — but it means
  **isolation is mandatory**. Never seed a VM that can reach the internet or a real network.
- The "malware" is **inert stand-ins** (a `sleep` binary disguised as `udevd`, text files,
  benign DLLs/scripts, a no-op preload library) that *trip your detectors* without actually
  phoning home — except the genuine weaknesses above, which is why you isolate.
- `seed_windows.ps1` intentionally **does not** modify LSA password-filter packages: a bad
  one can lock you out of Windows. Real "Nosferatu" lives there and `Hunt-DC.ps1` checks it;
  we just don't simulate it in a way that could brick your VM.
- Reset with Proxmox snapshots (`qm rollback`). The `--teardown` options in the seeders are
  best-effort; snapshots are the reliable reset.
- Everything here is for practicing **defense** on **your own** machines for a sanctioned
  competition.
