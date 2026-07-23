# Download & Install on Kali Linux

Step-by-step guide to get **wifi-solution** (Aircrack-ng GUI) running on Kali Linux.

## Prerequisites

- Kali Linux (recommended) with **root / sudo** access
- Internet connection
- Wi-Fi adapter that supports **monitor mode** and **packet injection**
- Python **3.10+** (included on current Kali)

---

## 1. Install system packages

```bash
sudo apt update
sudo apt install -y git aircrack-ng python3-pip python3-tk python3-venv python3-full
```

| Package        | Purpose                                      |
|----------------|----------------------------------------------|
| `git`          | Clone this repository                        |
| `aircrack-ng`  | `airmon-ng`, `airodump-ng`, `aireplay-ng`, etc. |
| `python3-tk`   | Tk GUI support (required by CustomTkinter)   |
| `python3-venv` | Virtual environment (required on Kali)       |
| `python3-full` | Ensures venv works fully                     |

---

## 2. Download the repository

```bash
cd ~
git clone https://github.com/hamadraufkhan/wifi-solution.git
cd wifi-solution
```

Or download a ZIP from GitHub, extract it, then `cd` into the folder.

---

## 3. Install Python dependencies (use a venv)

Kali blocks system-wide `pip3 install` (`externally-managed-environment` / PEP 668).  
**Do not** run bare `pip3 install -r requirements.txt` on the system Python.

**Recommended — setup script:**

```bash
chmod +x setup.sh run.sh
./setup.sh
```

**Manual equivalent:**

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

This installs `customtkinter` and `Pillow` **inside `.venv` only**.

---

## 4. Run the application

Monitor mode and packet injection need root. Use the **venv Python under sudo** (plain `sudo python3` will not see venv packages):

```bash
./run.sh
```

Or:

```bash
sudo .venv/bin/python main.py
```

---

## Quick checklist

```bash
sudo apt install -y git aircrack-ng python3-tk python3-venv python3-full
git clone https://github.com/hamadraufkhan/wifi-solution.git
cd wifi-solution
chmod +x setup.sh run.sh
./setup.sh
./run.sh
```

---

## Screenshots

See [README.md](README.md#screenshots) or `docs/screenshots/`:

| Step | Image |
|------|-------|
| Interface | `docs/screenshots/ui-01-interface.png` |
| Scan | `docs/screenshots/ui-02-scan.png` |
| Capture | `docs/screenshots/ui-03-capture.png` |
| Crack | `docs/screenshots/ui-04-crack.png` |

---

## Troubleshooting

| Issue | What to try |
|-------|-------------|
| `externally-managed-environment` | Use `./setup.sh` / a venv — do not use system `pip3` |
| `Missing dependency: customtkinter` | You ran system `python3`. Use `sudo .venv/bin/python main.py` or `./run.sh` |
| `customtkinter` import error after setup | Re-run `./setup.sh` |
| Scan shows **0 APs** (RTL8188EUS / rtl8xxxu) | Open **Drivers** step → Verify → Install `realtek-rtl8188eus-dkms` → Blacklist + reload → unplug/replug USB → Scan again |
| Driver install | GUI Drivers step installs Kali packages (`realtek-rtl8188eus-dkms`, `realtek-rtl88xxau-dkms`, …) and blacklists stock modules |
| No wireless interfaces listed | Plug in a USB Wi-Fi adapter; check `iwconfig` / `ip link` |
| Monitor mode fails | Use **Check kill** on the Monitor step; try another adapter/driver |
| GUI does not open | `sudo apt install -y python3-tk` |
| `SessionState object is not callable` | Update to latest code (`self.session` rename) and restart |

---

## Legal notice

Use this tool **only** on networks you own or have **written authorization** to test. Unauthorized access to wireless networks is illegal.
