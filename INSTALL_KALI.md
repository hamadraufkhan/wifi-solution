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
sudo apt install -y git aircrack-ng python3-pip python3-tk python3-venv
```

| Package        | Purpose                                      |
|----------------|----------------------------------------------|
| `git`          | Clone this repository                        |
| `aircrack-ng`  | `airmon-ng`, `airodump-ng`, `aireplay-ng`, etc. |
| `python3-pip`  | Install Python dependencies                  |
| `python3-tk`   | Tk GUI support (required by CustomTkinter)   |
| `python3-venv` | Optional isolated virtual environment        |

---

## 2. Download the repository

```bash
cd ~
git clone https://github.com/hamadraufkhan/wifi-solution.git
cd wifi-solution
```

Or download a ZIP from GitHub:

1. Open [https://github.com/hamadraufkhan/wifi-solution](https://github.com/hamadraufkhan/wifi-solution)
2. Click **Code → Download ZIP**
3. Extract it, then:

```bash
cd ~/Downloads   # or wherever you extracted it
unzip wifi-solution-main.zip
cd wifi-solution-main
```

---

## 3. Install Python dependencies

**Option A — system-wide (simple):**

```bash
pip3 install -r requirements.txt
```

If Kali blocks system-wide pip installs, use:

```bash
pip3 install --break-system-packages -r requirements.txt
```

**Option B — virtual environment (recommended):**

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

This installs:

- `customtkinter`
- `Pillow`

---

## 4. Run the application

Monitor mode and packet injection need root:

```bash
sudo python3 main.py
```

If you used a venv, activate it first, then run with the venv’s Python under sudo:

```bash
source .venv/bin/activate
sudo .venv/bin/python main.py
```

---

## Quick checklist

1. `sudo apt install -y git aircrack-ng python3-pip python3-tk`
2. `git clone https://github.com/hamadraufkhan/wifi-solution.git && cd wifi-solution`
3. `pip3 install -r requirements.txt`
4. `sudo python3 main.py`

---

## Troubleshooting

| Issue | What to try |
|-------|-------------|
| `customtkinter` import error | Run `pip3 install -r requirements.txt` again |
| No wireless interfaces listed | Plug in a USB Wi-Fi adapter; check `iwconfig` / `ip link` |
| Monitor mode fails | Kill NetworkManager conflicts from the GUI **Monitor** step, or try another adapter/driver |
| GUI does not open | Ensure `python3-tk` is installed: `sudo apt install -y python3-tk` |

---

## Legal notice

Use this tool **only** on networks you own or have **written authorization** to test. Unauthorized access to wireless networks is illegal.
