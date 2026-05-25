# Android Development Environment on Containarium

Run a full Android development environment inside an Incus container with hardware-accelerated emulator via KVM.

## Two Modes

| Mode | Stack | Use Case | Access |
|------|-------|----------|--------|
| **Headless** | `android` | CI/CD, automated testing, command-line builds | SSH + ADB |
| **GUI** | `android-studio` | App UI development, manual testing, full IDE | SSH + VNC |

## Prerequisites

- Container must have `security.nesting=true` (Containarium sets this by default when Podman is enabled)
- Host must support KVM (`grep -c vmx /proc/cpuinfo` > 0)
- Recommended: 8+ CPU cores, 16GB+ RAM, 50GB+ disk

## Quick Start

### Headless (CI/CD & Command-Line)

```bash
containarium create android-dev \
  --ssh-key ~/.ssh/id_ed25519.pub \
  --cpu 8 --memory 16GB --disk 100GB \
  --stack android \
  --backend-id tunnel-node-b-gpu
```

After creation, SSH in and use:
```bash
ssh android-dev

# Build a project
cd /path/to/project
./gradlew assembleDebug

# Start emulator (headless)
emulator -avd default -no-window -no-audio -gpu swiftshader_indirect &

# Wait for boot
adb wait-for-device
adb shell getprop sys.boot_completed  # Returns "1" when ready

# Run tests
./gradlew connectedAndroidTest

# Stop emulator
adb emu kill
```

### GUI (Android Studio)

```bash
containarium create android-studio-dev \
  --ssh-key ~/.ssh/id_ed25519.pub \
  --cpu 8 --memory 16GB --disk 100GB \
  --stack android-studio \
  --backend-id tunnel-node-b-gpu
```

After creation:
```bash
ssh android-studio-dev

# Start VNC server (first time sets up desktop)
vncserver :1 -geometry 1920x1080 -depth 24

# VNC is now listening on port 5901
```

Access the desktop:

**Option A — VNC client** (recommended for low latency):
```bash
# From your laptop, create SSH tunnel:
ssh -L 5901:localhost:5901 android-studio-dev

# Connect VNC client to localhost:5901
# Password: containarium
```

**Option B — Browser via noVNC** (no client install):
```bash
# Inside the container:
sudo apt install novnc websockify
websockify --web /usr/share/novnc 6080 localhost:5901 &

# From your laptop, tunnel port 6080:
ssh -L 6080:localhost:6080 android-studio-dev

# Open browser: http://localhost:6080/vnc.html
```

Then launch Android Studio:
```bash
# In the VNC desktop terminal:
studio.sh &
```

## What's Installed

### `android` stack (headless)
- OpenJDK 17 (headless)
- Android SDK command-line tools
- Android SDK platform tools (adb, fastboot)
- Android build tools 35.0.0
- Android platform API 35
- Android Emulator with x86_64 system image
- Pre-created AVD: `default` (Pixel 6, Android 15)
- QEMU/KVM for emulator acceleration

### `android-studio` stack (GUI)
- Everything in `android` stack, plus:
- OpenJDK 17 (full, with GUI support)
- Android Studio (latest stable)
- XFCE4 desktop environment
- TigerVNC server
- Noto fonts

## Emulator Usage

### Start Emulator

```bash
# Headless (no GUI needed)
emulator -avd default -no-window -no-audio -gpu swiftshader_indirect &

# With VNC (visible in VNC desktop)
emulator -avd default -gpu swiftshader_indirect &
```

### GPU Acceleration

For better emulator performance on GPU-equipped peers:
```bash
# If the container has GPU passthrough:
emulator -avd default -gpu host &

# Software rendering (always works, slower):
emulator -avd default -gpu swiftshader_indirect &
```

### Create Additional AVDs

```bash
# List available system images
sdkmanager --list | grep system-images

# Install a different API level
sdkmanager "system-images;android-34;google_apis;x86_64"

# Create AVD
avdmanager create avd -n android34 \
  -k "system-images;android-34;google_apis;x86_64" \
  -d pixel_6

# List AVDs
avdmanager list avd
```

### ADB Commands

```bash
# List connected devices/emulators
adb devices

# Install APK
adb install app-debug.apk

# Logcat
adb logcat

# Shell into emulator
adb shell

# Screenshot
adb exec-out screencap -p > screenshot.png

# Record screen
adb shell screenrecord /sdcard/demo.mp4
adb pull /sdcard/demo.mp4
```

## CI/CD Example

Example script for automated builds and tests:
```bash
#!/bin/bash
set -euo pipefail

# Start emulator
emulator -avd default -no-window -no-audio -gpu swiftshader_indirect &
EMU_PID=$!

# Wait for boot (up to 5 minutes)
adb wait-for-device
timeout 300 bash -c 'while [ "$(adb shell getprop sys.boot_completed 2>/dev/null)" != "1" ]; do sleep 5; done'

# Disable animations for faster tests
adb shell settings put global window_animation_scale 0
adb shell settings put global transition_animation_scale 0
adb shell settings put global animator_duration_scale 0

# Run tests
./gradlew connectedAndroidTest

# Cleanup
kill $EMU_PID 2>/dev/null
```

## Troubleshooting

### Emulator fails with "KVM is required"
The container needs nested virtualization:
```bash
# Check from inside container
kvm-ok

# If not supported, the container needs security.nesting=true
# Containarium sets this by default with --podman flag
```

### Emulator extremely slow
- Use `-gpu swiftshader_indirect` (software GPU)
- Ensure KVM is working: `emulator -accel-check`
- Increase container CPU/memory

### "ANDROID_HOME not set"
```bash
source ~/.bashrc
# Or set manually:
export ANDROID_HOME=/opt/android-sdk
export PATH=$ANDROID_HOME/cmdline-tools/latest/bin:$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH
```

### VNC connection refused
```bash
# Check if VNC is running
vncserver -list

# Start if not running
vncserver :1 -geometry 1920x1080 -depth 24

# Kill and restart
vncserver -kill :1
vncserver :1 -geometry 1920x1080 -depth 24
```
