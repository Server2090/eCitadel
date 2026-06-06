#!/usr/bin/env bash
# =============================================================================
#  build_proxmox_lab.sh  -  eCitadel Team 76 PRACTICE LAB  -  Proxmox VM builder
# =============================================================================
#  RUN THIS ON YOUR PROXMOX HOST (it has internet + KVM; this sandbox does not,
#  which is why the OS images are downloaded here on your side rather than
#  shipped as .qcow2 files). It downloads the official Fedora 43 and Debian 13
#  CLOUD images and creates two practice VMs with cloud-init so you can log in.
#  You then snapshot, run seed_linux.sh inside each, and snapshot again.
#
#  Tested against the documented Proxmox VE 8.x `qm` workflow. Review the
#  variables below before running. It will NOT overwrite an existing VMID.
#
#  USAGE (as root on the Proxmox node):
#    ./build_proxmox_lab.sh                 # download images + create both VMs
#    ./build_proxmox_lab.sh --download-only # just fetch the images
#    STORAGE=local-lvm BRIDGE=vmbr1 ./build_proxmox_lab.sh
# =============================================================================
set -eu

# ---- knobs (override via env) ----------------------------------------------
STORAGE="${STORAGE:-local-lvm}"     # where VM disks live (e.g. local-lvm, local-zfs)
BRIDGE="${BRIDGE:-vmbr0}"           # the network bridge for the VMs
RAM="${RAM:-2048}"                  # MB per VM
CORES="${CORES:-2}"
DISK="${DISK:-16}"                  # GB (cloud images are tiny; we grow them)
CIPASS="${CIPASS:-Practice123!}"    # cloud-init root password for the practice VMs
IMGDIR="${IMGDIR:-/var/lib/vz/template/iso}"

VMID_DEB="${VMID_DEB:-9101}";  NAME_DEB="blacklist-practice"
VMID_FED="${VMID_FED:-9102}";  NAME_FED="concierge-practice"

# Official cloud images. These filenames change over time - if a download 404s,
# open the directory in a browser and update the URL to the current .qcow2.
#   Debian:  https://cloud.debian.org/images/cloud/trixie/latest/
#   Fedora:  https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/
DEB_URL="${DEB_URL:-https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2}"
FED_URL="${FED_URL:-https://download.fedoraproject.org/pub/fedora/linux/releases/43/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-43-1.4.x86_64.qcow2}"

DOWNLOAD_ONLY=0
[ "${1:-}" = "--download-only" ] && DOWNLOAD_ONLY=1

command -v qm >/dev/null || { echo "qm not found - run this ON the Proxmox host."; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 1; }
mkdir -p "$IMGDIR"

fetch() {  # fetch <url> <dest>
  local url="$1" dest="$2"
  if [ -f "$dest" ]; then echo "[img] already have $(basename "$dest")"; return; fi
  echo "[img] downloading $(basename "$dest") ..."
  if command -v wget >/dev/null; then wget -q --show-progress -O "$dest" "$url"
  else curl -L -o "$dest" "$url"; fi
}

DEB_IMG="$IMGDIR/$(basename "$DEB_URL")"
FED_IMG="$IMGDIR/$(basename "$FED_URL")"
fetch "$DEB_URL" "$DEB_IMG"
fetch "$FED_URL" "$FED_IMG"
[ "$DOWNLOAD_ONLY" -eq 1 ] && { echo "[done] images in $IMGDIR"; exit 0; }

make_vm() {  # make_vm <vmid> <name> <image> <ostype>
  local vmid="$1" name="$2" img="$3" ost="$4"
  if qm status "$vmid" >/dev/null 2>&1; then
    echo "[vm] VMID $vmid already exists - skipping (delete it first to rebuild)."; return
  fi
  echo "[vm] creating $vmid ($name) from $(basename "$img")"
  qm create "$vmid" --name "$name" --memory "$RAM" --cores "$CORES" \
     --net0 "virtio,bridge=$BRIDGE" --ostype "$ost" --scsihw virtio-scsi-pci --agent 1
  # import the cloud image as the system disk (PVE 8 one-liner)
  qm set "$vmid" --scsi0 "$STORAGE:0,import-from=$img"
  # cloud-init drive + boot + serial console (cloud images expect a serial console)
  qm set "$vmid" --ide2 "$STORAGE:cloudinit"
  qm set "$vmid" --boot "order=scsi0" --serial0 socket --vga serial0
  # cloud-init: root login with a known practice password, DHCP
  qm set "$vmid" --ciuser root --cipassword "$CIPASS" --ipconfig0 "ip=dhcp"
  # grow the tiny cloud image to a usable size
  qm disk resize "$vmid" scsi0 "${DISK}G"
  echo "[vm] $vmid ready."
}

make_vm "$VMID_DEB" "$NAME_DEB" "$DEB_IMG" "l26"
make_vm "$VMID_FED" "$NAME_FED" "$FED_IMG" "l26"

cat <<EOF

================= NEXT STEPS =================================================
1. Start the VMs:        qm start $VMID_DEB ; qm start $VMID_FED
2. Find their IPs:       qm guest cmd $VMID_DEB network-get-interfaces   (or check your DHCP)
                         (install qemu-guest-agent inside if 'agent' info is empty)
3. Log in (cloud-init):  ssh root@<vm-ip>     password: $CIPASS
4. TAKE A SNAPSHOT now:  qm snapshot $VMID_DEB clean ; qm snapshot $VMID_FED clean
5. Copy the seeder in:   scp seed_linux.sh root@<vm-ip>:/root/
6. Seed the box:         ssh root@<vm-ip> 'bash /root/seed_linux.sh --i-understand --with-live-procs'
7. Snapshot the target:  qm snapshot $VMID_DEB seeded ; qm snapshot $VMID_FED seeded
8. Practice your kit, then reset with:  qm rollback $VMID_DEB clean   (or 'seeded')

Windows DC + pfSense: see practice-lab/README_LAB.md and pfsense_setup.md (you supply
the Windows eval ISO and the pfSense image - they can't be redistributed here).

IMPORTANT: keep this practice lab on an ISOLATED bridge with NO internet/NAT once
seeded - seed_linux.sh creates genuinely vulnerable accounts and backdoors.
=============================================================================
EOF
