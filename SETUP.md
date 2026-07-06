# SETUP — Running the Network Baseline Monitor on a New Computer

This guide walks a complete beginner from a blank computer to a working
demo. Pick the section that matches your operating system and follow it
**in order**. Don't skip steps.

> **Quick map of what you're doing**
> 1. Install Python 3 (one-time, ~5 min)
> 2. Copy the project folder onto the computer
> 3. Open a terminal in that folder
> 4. Create a virtual environment and install Flask (one command)
> 5. Run `python main.py` and open the dashboard in a browser
>
> That's the **simulator demo** — works in 5 minutes on any computer with
> zero admin privileges. The **live-capture demo** (real packets from the
> Wi-Fi card) needs ~3 extra steps and admin rights — see Section 5.

---

## Part 1 — Windows setup

### Step 1.1 — Install Python 3

1. Go to <https://www.python.org/downloads/windows/>.
2. Download the latest **Python 3.x** "Windows installer (64-bit)".
3. **Run the installer.**
4. ⚠️ **CRITICAL: tick the box "Add python.exe to PATH"** at the bottom of the first
   installer screen. Without this, none of the commands below will work.
5. Click **Install Now**.
6. After install, open **Command Prompt** (press `Win+R`, type `cmd`,
   press Enter) and type:
   ```cmd
   python --version
   ```
   You should see `Python 3.12.x` (or similar). If you see "command not
   found", the PATH checkbox was missed — uninstall and reinstall.

> **Don't use the Microsoft Store version of Python** — it has permission
> quirks that break virtual environments and packet capture.

### Step 1.2 — Copy the project to the computer

You have two options:

**Option A — From a USB stick / cloud drive (easiest):**
1. Copy the entire `network-baseline-monitor` folder to the new computer.
   A good place is `C:\Users\<YourName>\Documents\network-baseline-monitor`.

**Option B — From the zip file:**
1. Right-click the `network-baseline-monitor.zip` file → **Extract All...**
2. Choose `C:\Users\<YourName>\Documents` as the destination.
3. You should now have `C:\Users\<YourName>\Documents\network-baseline-monitor`.

### Step 1.3 — Open a Command Prompt in the project folder

1. Open **File Explorer** and navigate into `network-baseline-monitor`.
2. Click in the address bar at the top of the window (where it shows the
   path), delete what's there, type `cmd`, and press Enter.
3. A black Command Prompt window opens, already inside the project folder.

(Alternative: open Command Prompt manually and `cd` into the folder:
`cd C:\Users\<YourName>\Documents\network-baseline-monitor`)

### Step 1.4 — One-shot install + run

Double-click **`run.bat`** in File Explorer. That's it.

The first time it runs it will:
1. Create a virtual environment (a clean isolated Python).
2. Install Flask (~10 seconds).
3. Start the monitor in simulator mode.

You'll see:
```
[boot] dashboard:  http://127.0.0.1:5050/
```

Open a browser and visit **<http://127.0.0.1:5050/>**. You should see the
dashboard with packets per second, charts, and (after ~30 seconds) the
status pill flipping from "training" to "monitoring".

To stop: click in the Command Prompt window and press `Ctrl+C`.

### Step 1.5 — If you prefer the manual route

```cmd
cd C:\Users\<YourName>\Documents\network-baseline-monitor
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

When you come back later, you only need:
```cmd
cd C:\Users\<YourName>\Documents\network-baseline-monitor
.venv\Scripts\activate
python main.py
```

---

## Part 2 — macOS setup

### Step 2.1 — Install Python 3 (if not already installed)

Most modern Macs have Python 3 already. Check:
```bash
python3 --version
```

If you see `Python 3.x.x`, skip to Step 2.2. Otherwise, install Homebrew
from <https://brew.sh> and then:
```bash
brew install python
```

### Step 2.2 — Copy the project, open Terminal in it

1. Copy the `network-baseline-monitor` folder to `~/Documents`.
2. Open **Terminal** (press `Cmd+Space`, type "terminal", press Enter).
3. Navigate to the folder:
   ```bash
   cd ~/Documents/network-baseline-monitor
   ```

### Step 2.3 — One-shot install + run

```bash
chmod +x run.sh
./run.sh
```

Open <http://127.0.0.1:5050/> in any browser. To stop: `Ctrl+C` in Terminal.

---

## Part 3 — Linux setup (Ubuntu / Debian / Fedora)

### Step 3.1 — Install Python 3 + venv

Ubuntu / Debian:
```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip
```

Fedora:
```bash
sudo dnf install -y python3 python3-pip
```

### Step 3.2 — Copy + run

```bash
cd ~/network-baseline-monitor
chmod +x run.sh
./run.sh
```

Open <http://127.0.0.1:5050/>.

---

## Part 4 — Verifying everything works (1-minute check)

After the dashboard is up:

| What you should see in the browser | Within | If you don't, try |
|------------------------------------|--------|-------------------|
| Packets/sec counter > 0 | 5 sec | Refresh the page |
| Status pill: `training X%` | 5 sec | Wait |
| Status pill: `monitoring` (green) | 30 sec | Check terminal for errors |
| First **port-scan** alert pops up | ~55 sec | Wait, anomalies are scheduled |
| First **DDoS** alert pops up | ~85 sec | — |
| First **exfil** alert pops up | ~120 sec | — |

If all five appear, you're ready for the demo. ✅

---

## Part 5 — Optional: real network packet capture (live mode)

Use this if you want to demonstrate the system on **actual packets from
the Wi-Fi card** rather than the built-in simulator.

### 5.1 — On Windows

**5.1.1 — Install Npcap (Windows packet capture driver)**

Scapy can't read raw network packets on Windows without Npcap.

1. Go to <https://npcap.com/#download>.
2. Download the latest "Npcap [version] installer".
3. Run the installer. ✅ **Tick "Install Npcap in WinPcap API-compatible
   Mode"** during installation.
4. Click Install. Reboot if it asks.

**5.1.2 — Install Scapy**

In your project Command Prompt (inside the venv):
```cmd
.venv\Scripts\activate
pip install scapy
```

**5.1.3 — Find your Wi-Fi interface name**

In PowerShell:
```powershell
Get-NetAdapter | Format-Table -AutoSize
```

The "Name" column gives you something like `"Wi-Fi"` or `"Ethernet"`.
Or, ask scapy directly:
```cmd
python -c "from scapy.all import get_if_list; print(get_if_list())"
```

You'll see entries like `\Device\NPF_{ABCD-1234-...}`. The name listed in
`Get-NetAdapter` (e.g. `Wi-Fi`) is what you'll pass to `--iface`.

**5.1.4 — Run as Administrator**

Capturing raw packets needs admin rights. Close the existing Command
Prompt. Open a **new** one as administrator:

1. Press `Win`, type `cmd`.
2. Right-click "Command Prompt" → **"Run as administrator"**.
3. Click Yes on the UAC prompt.

Then:
```cmd
cd C:\Users\<YourName>\Documents\network-baseline-monitor
.venv\Scripts\activate
python main.py --mode live --iface "Wi-Fi"
```

Browse some websites — you'll see real packets in the dashboard.

### 5.2 — On macOS

```bash
source .venv/bin/activate
pip install scapy
```

Find interface (almost always `en0` for Wi-Fi):
```bash
networksetup -listallhardwareports
```

Run with sudo:
```bash
sudo .venv/bin/python main.py --mode live --iface en0
```

### 5.3 — On Linux

```bash
sudo apt install -y libpcap-dev   # Ubuntu/Debian only
source .venv/bin/activate
pip install scapy
```

Find interface:
```bash
ip link show
```

Run with sudo:
```bash
sudo .venv/bin/python main.py --mode live --iface eth0
```

---

## Part 6 — Optional: install nmap for the port-scan demo

If you'll trigger a port-scan attack against your own router during the
demo, you need nmap.

| OS | Install command |
|----|-----------------|
| Windows | Download from <https://nmap.org/download.html> (the installer also installs Npcap) |
| macOS | `brew install nmap` |
| Linux | `sudo apt install nmap` |

Test:
```
nmap --version
```

---

## Part 7 — Common problems and fixes

| Symptom | Cause | Fix |
|---------|-------|-----|
| `'python' is not recognized` (Windows) | Python's PATH wasn't added during install | Reinstall Python, **tick "Add python.exe to PATH"** |
| `python: command not found` (macOS/Linux) | Use `python3` instead of `python` | Try `python3 main.py` |
| `ModuleNotFoundError: No module named 'flask'` | venv not activated, or deps not installed | Activate the venv, run `pip install -r requirements.txt` |
| Browser says "can't reach 127.0.0.1:5050" | Server didn't start, port already in use, or firewall | Check terminal for errors. Try `python main.py --port 5051` |
| Dashboard shows 0 packets in **live** mode | Wrong interface name, or no traffic | Re-check Step 5.1.3 / 5.2 / 5.3, browse a website to test |
| `PermissionError: [Errno 13]` in live mode | Not running as admin/sudo | Re-open terminal with admin rights (see 5.1.4) |
| `Npcap not found` (Windows) | Npcap missing or installed without WinPcap mode | Reinstall Npcap, tick the WinPcap-compatible-mode box |
| Status stuck on "training" forever | Engine isn't producing windows | Check terminal for errors, restart |

---

## Part 8 — Quick reference card

### Start the simulator demo
| OS | Command |
|----|---------|
| Windows | double-click `run.bat` |
| macOS / Linux | `./run.sh` |

### Start live capture
| OS | Command |
|----|---------|
| Windows | Admin CMD: `python main.py --mode live --iface "Wi-Fi"` |
| macOS | `sudo .venv/bin/python main.py --mode live --iface en0` |
| Linux | `sudo .venv/bin/python main.py --mode live --iface eth0` |

### Trigger attacks (cross-platform helpers)
```
python triggers/portscan.py 192.168.1.1
python triggers/exfil.py
python triggers/spike.py
```

### Open the dashboard
<http://127.0.0.1:5050/>

### Stop the monitor
`Ctrl+C` in the terminal window.

---

You're now set up. For the actual demo flow — what to do, click, and say
in front of your professor — see [`DEMO.md`](DEMO.md).
