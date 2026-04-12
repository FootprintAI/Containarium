# Windows Server VM Setup on Incus

This guide covers running Windows Server 2022 as a VM inside Incus on a Containarium peer node. Incus uses QEMU/KVM for VMs, providing full hardware virtualization with GPU passthrough support.

> **Note**: Windows cannot run as an LXC container (LXC shares the host Linux kernel). It must run as a full VM using `incus launch --vm`.

## Prerequisites

- Incus installed and initialized on the peer node
- KVM support enabled (`kvm-ok` should return "KVM acceleration can be used")
- At least 8GB free RAM and 50GB free disk
- (Optional) GPU for passthrough

## Step 1: Download ISOs

### Windows Server 2022 Evaluation ISO (~5.5GB)

Download from Microsoft Evaluation Center (180-day free evaluation, requires browser):

**https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022**

1. Fill in the registration form
2. Select **ISO** format, **64-bit edition**, **English**
3. Download and upload to the peer:

```bash
scp ~/Downloads/SERVER_EVAL_x64FRE_en-us.iso <peer>:/tmp/windows-server-2022.iso
```

### Virtio Drivers ISO (~600MB)

Required for disk and network I/O performance. Download directly on the peer:

```bash
wget -O /tmp/virtio-win.iso \
  "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso"
```

## Step 2: Create the VM

```bash
# Create an empty VM (no image — we boot from ISO)
sudo incus init win2022 --empty --vm \
  -c limits.cpu=4 \
  -c limits.memory=8GiB \
  -c security.secureboot=false \
  -d root,size=50GiB

# Attach Windows install ISO (boot priority ensures it boots first)
sudo incus config device add win2022 install disk \
  source=/tmp/windows-server-2022.iso boot.priority=10

# Attach virtio drivers ISO (accessible as second CD drive during install)
sudo incus config device add win2022 virtio disk \
  source=/tmp/virtio-win.iso
```

## Step 3: Install Windows

```bash
# Start the VM
sudo incus start win2022

# Connect to the VGA console (graphical installer)
sudo incus console win2022 --type=vga
```

During installation:

1. Select language/keyboard, click **Install Now**
2. Choose **Windows Server 2022 Standard (Desktop Experience)**
3. Accept license terms
4. Select **Custom: Install Windows only**
5. At the disk selection screen, the disk won't be visible yet — you need to load the virtio SCSI driver:
   - Click **Load driver** → **Browse**
   - Navigate to the virtio CD → `vioscsi` → `2k22` → `amd64`
   - Select the driver and click **Next**
   - The 50GB disk will now appear — select it and continue
6. Windows will install and reboot (takes ~15-20 minutes)
7. Set the Administrator password when prompted

> **Tip**: To exit the VGA console, press `Ctrl+a q`.

## Step 4: Install Virtio Drivers (Post-Install)

After Windows boots, connect to the console again:

```bash
sudo incus console win2022 --type=vga
```

Inside Windows:

1. Open **File Explorer** → navigate to the virtio CD drive (usually `D:` or `E:`)
2. Run `virtio-win-gt-x64.exe` — this installs all virtio drivers:
   - Network (virtio-net)
   - Balloon (memory management)
   - Serial port
   - QEMU guest agent
3. Reboot when prompted

## Step 5: Enable Remote Access

### Enable RDP (Remote Desktop)

Open **PowerShell as Administrator** inside Windows:

```powershell
# Enable RDP
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' `
  -Name "fDenyTSConnections" -Value 0

# Allow RDP through firewall
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# (Optional) Allow RDP from any network
Set-NetFirewallRule -Name "RemoteDesktop-UserMode-In-TCP" -Profile Any
```

### (Optional) Install OpenSSH Server

```powershell
# Install OpenSSH server
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start and enable SSH
Start-Service sshd
Set-Service -Name sshd -StartupType Automatic

# Allow SSH through firewall
New-NetFirewallRule -Name "OpenSSH" -DisplayName "OpenSSH Server" `
  -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22
```

## Step 6: Remove Install ISO

After installation is complete, remove the ISO to free resources:

```bash
sudo incus config device remove win2022 install
```

## Step 7: Access the VM

### Find the VM's IP address

```bash
sudo incus list win2022 -f csv -c 4
# Example output: 10.100.0.50 (eth0)
```

### RDP Access

From your local machine (assuming SSH tunnel or VPN to the peer network):

```bash
# macOS
open rdp://10.100.0.50

# Linux
xfreerdp /v:10.100.0.50 /u:Administrator

# Windows
mstsc /v:10.100.0.50
```

### SSH Access (if OpenSSH installed)

```bash
ssh Administrator@10.100.0.50
```

## GPU Passthrough (Optional)

To pass a GPU to the Windows VM for CUDA/DirectX workloads:

```bash
# Find GPU PCI address
lspci | grep -i nvidia
# Example: 01:00.0 3D controller: NVIDIA Corporation ...

# Add GPU to VM (VM must be stopped)
sudo incus stop win2022
sudo incus config device add win2022 gpu gpu \
  pci=01:00.0
sudo incus start win2022
```

Inside Windows, install the NVIDIA driver from https://www.nvidia.com/drivers/.

> **Note**: GPU passthrough requires the GPU to not be in use by the host. If the host is using the GPU, you'll need to unbind it first or use a dedicated GPU for the VM.

## Save as Reusable Image

After setup is complete, publish the VM as a local image to avoid repeating the installation:

```bash
# Stop the VM first
sudo incus stop win2022

# Publish as local image
sudo incus publish win2022 --alias windows-server-2022

# Now you can create new VMs from this image:
sudo incus launch windows-server-2022 win2022-dev --vm \
  -c limits.cpu=4 -c limits.memory=8GiB
```

## Troubleshooting

### VM won't boot from ISO
- Ensure `security.secureboot=false` is set
- Check boot priority: `sudo incus config device show win2022`

### No disk visible during install
- You forgot to load the virtio SCSI driver — see Step 3.5

### No network after install
- Install virtio-net driver from the virtio CD
- Or run `virtio-win-gt-x64.exe` which installs all drivers

### VGA console shows black screen
- Wait 30 seconds — Windows boot can be slow
- Try `sudo incus console win2022 --type=vga` again

### RDP connection refused
- Verify RDP is enabled: `Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name "fDenyTSConnections"`
- Check Windows Firewall: `Get-NetFirewallRule -DisplayGroup "Remote Desktop"`
- Verify VM IP: `sudo incus list win2022 -f csv -c 4`
