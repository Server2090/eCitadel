# pfSense practice VM — setup & vulnerabilities to introduce

**Team 76 · RR Intel / eCitadel Season IV — practice lab**

pfSense can't be shipped as a ready-made disk here (it's FreeBSD-based and the image isn't
redistributable), and unlike Linux there's no clean headless seeder — pfSense is configured
through its console/GUI. So this is a short build + a checklist of misconfigurations to set
by hand, so you can practice the fixes in `pfsense/PFSENSE_HARDENING.md`.

> Keep the whole practice lab on an **isolated bridge with no real internet** once you've
> introduced these weaknesses — several of them genuinely expose the box.

---

## 1. Get the image and import it

1. Download the official **pfSense CE** installer ISO from netgate.com (free; you accept
   their terms). Put it in `/var/lib/vz/template/iso` on your Proxmox node.
2. Create the VM (two NICs — WAN + LAN — to mirror the real `thebox`):
   ```bash
   qm create 9103 --name thebox-practice --memory 1024 --cores 2 \
      --net0 virtio,bridge=vmbr0 --net1 virtio,bridge=vmbr1 --ostype other --scsihw virtio-scsi-pci
   qm set 9103 --scsi0 local-lvm:8                 # 8 GB disk
   qm set 9103 --ide2 local-lvm:iso/<pfSense-CE-installer>.iso,media=cdrom
   qm set 9103 --boot order=ide2;scsi0
   qm start 9103
   ```
   - `vmbr0` = WAN side, `vmbr1` = LAN side (put your Fedora/Debian practice VMs on `vmbr1`
     so pfSense is their gateway, just like the real topology).
3. Open the VM console and run the pfSense installer (defaults are fine). After it reboots,
   assign interfaces: **WAN = the vmbr0 NIC**, **LAN = the vmbr1 NIC**. Set the LAN IP to
   something like `172.21.0.254/24` to match the real lab.
4. Browse to the LAN IP from a VM on `vmbr1` to reach the GUI (default `admin` / `pfsense`).
5. **Snapshot now:** `qm snapshot 9103 clean`.

---

## 2. Misconfigurations to introduce (then practice fixing them)

Set these by hand in the console/GUI, then snapshot as `seeded`. Each maps to a fix in
`pfsense/PFSENSE_HARDENING.md`.

| # | Weakness to set | Where | The fix you'll practice |
|---|---|---|---|
| 1 | Leave the **default admin password** (`pfsense`) | — | change it; submit via inject format |
| 2 | **Enable webGUI/SSH on WAN** (System → Advanced → Admin Access; allow from WAN) | Admin Access | restrict management to **LAN only** |
| 3 | Add a permissive **"WAN allow any→any"** firewall rule | Firewall → Rules → WAN | replace with **port-only allows** to the scored hosts, default-deny |
| 4 | Keep the **"LAN allow any→any (out)"** default | Firewall → Rules → LAN | replace with box-to-box + DNS allow, **block the rest (egress)** |
| 5 | **Disable** the anti-lockout rule | Admin Access | re-enable it (keep yourself in) |
| 6 | Turn **GUI to HTTP** (not HTTPS) | Admin Access | switch back to **HTTPS** |
| 7 | (optional) Add a port-forward exposing an internal admin port to WAN | Firewall → NAT | remove it; only scored services reach in |
| 8 | (optional) Enable an unused service (e.g. UPnP) | Services | disable what you don't need |

Practice flow: from a VM on the LAN side, confirm you can reach the GUI; build the WAN
allow-list and the LAN egress rules from the hardening doc; verify the scored ports still
pass (test 53/80/443/3389 to your other practice VMs) while general outbound is blocked;
then download a **config backup** (Diagnostics → Backup & Restore) as your fast restore point.

> If you lock yourself out while practicing, that's the lesson — in the real event you'd
> use one of your **4 reverts**; here just `qm rollback 9103 clean`.

---

## 3. Reset

```bash
qm rollback 9103 clean      # back to a fresh install
# or roll to 'seeded' to redo the fix drills from the vulnerable state
```
