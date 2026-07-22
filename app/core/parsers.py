"""Parsers for airodump CSV, airmon output, and aircrack results."""

from __future__ import annotations

import csv
import io
import re
from pathlib import Path
from typing import Optional

from app.core.state import AccessPoint, Station


IWCONFIG_IFACE_RE = re.compile(r"^(\S+)\s+IEEE\s+802\.11", re.MULTILINE)
AIRMON_ENABLED_RE = re.compile(
    r"(?:monitor mode (?:vif )?enabled(?: for \S+)? on\s+)(\S+)",
    re.IGNORECASE,
)
AIRMON_DISABLED_RE = re.compile(
    r"(?:monitor mode (?:vif )?disabled(?: for \S+)? on\s+)(\S+)",
    re.IGNORECASE,
)
HANDSHAKE_LINE_RE = re.compile(r"WPA handshake:\s*([0-9A-Fa-f:]{17})", re.IGNORECASE)
AIRCRACK_KEY_RE = re.compile(
    r"KEY FOUND!\s*\[\s*(.+?)\s*\]",
    re.IGNORECASE,
)
AIRCRACK_HANDSHAKE_COUNT_RE = re.compile(
    r"(\d+)\s+handshake",
    re.IGNORECASE,
)
MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def parse_wireless_interfaces(iwconfig_output: str) -> list[str]:
    """Return wireless interface names from `iwconfig` output."""
    found = IWCONFIG_IFACE_RE.findall(iwconfig_output)
    # Also catch interfaces that show "no wireless extensions" skip;
    # iwconfig lists wireless ones with IEEE 802.11.
    return sorted(set(found))


def parse_ip_link_wireless_hint(ip_link_output: str) -> list[str]:
    """Fallback: interfaces whose name looks like wifi (wlan*, wlp*, wlx*)."""
    names: list[str] = []
    for line in ip_link_output.splitlines():
        # e.g. "3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
        m = re.match(r"^\d+:\s+([^:@]+)", line.strip())
        if not m:
            continue
        name = m.group(1)
        lower = name.lower()
        if lower.startswith(("wlan", "wlp", "wlx", "wifi")) or lower.endswith("mon"):
            names.append(name)
    return sorted(set(names))


def _strip_phy_prefix(name: str) -> str:
    """Convert '[phy0]wlan0mon' -> 'wlan0mon'."""
    name = name.strip().rstrip(")")
    name = name.split()[0]
    m = re.match(r"\[phy\d+\](.+)", name, re.IGNORECASE)
    if m:
        return m.group(1)
    return name


def parse_airmon_monitor_iface(airmon_output: str) -> Optional[str]:
    """Extract monitor interface name from airmon-ng start output."""
    m = AIRMON_ENABLED_RE.search(airmon_output)
    if not m:
        return None
    return _strip_phy_prefix(m.group(1))


def parse_airmon_disabled_iface(airmon_output: str) -> Optional[str]:
    m = AIRMON_DISABLED_RE.search(airmon_output)
    if not m:
        return None
    return _strip_phy_prefix(m.group(1))


def _clean(cell: Optional[str]) -> str:
    return (cell or "").strip()


def parse_airodump_csv(text: str) -> tuple[list[AccessPoint], list[Station]]:
    """Parse airodump-ng CSV (AP section then Station section)."""
    # Normalize Windows/Unix newlines; airodump uses blank line between sections.
    raw = text.replace("\r\n", "\n").replace("\r", "\n")
    # Split on empty line that precedes "Station MAC"
    parts = re.split(r"\n\s*\n", raw.strip(), maxsplit=1)
    ap_blob = parts[0] if parts else ""
    sta_blob = parts[1] if len(parts) > 1 else ""

    access_points: list[AccessPoint] = []
    stations: list[Station] = []

    # AP section
    ap_reader = csv.reader(io.StringIO(ap_blob))
    ap_rows = list(ap_reader)
    if ap_rows:
        # Skip header if present
        start = 1 if ap_rows and "BSSID" in "".join(ap_rows[0]).upper() else 0
        for row in ap_rows[start:]:
            if len(row) < 14:
                continue
            bssid = _clean(row[0])
            if not MAC_RE.match(bssid):
                continue
            access_points.append(
                AccessPoint(
                    bssid=bssid,
                    first_seen=_clean(row[1]) if len(row) > 1 else "",
                    last_seen=_clean(row[2]) if len(row) > 2 else "",
                    channel=_clean(row[3]) if len(row) > 3 else "",
                    speed=_clean(row[4]) if len(row) > 4 else "",
                    privacy=_clean(row[5]) if len(row) > 5 else "",
                    cipher=_clean(row[6]) if len(row) > 6 else "",
                    auth=_clean(row[7]) if len(row) > 7 else "",
                    power=_clean(row[8]) if len(row) > 8 else "",
                    beacons=_clean(row[9]) if len(row) > 9 else "",
                    iv=_clean(row[10]) if len(row) > 10 else "",
                    lan_ip=_clean(row[11]) if len(row) > 11 else "",
                    id_length=_clean(row[12]) if len(row) > 12 else "",
                    essid=_clean(row[13]) if len(row) > 13 else "",
                    key=_clean(row[14]) if len(row) > 14 else "",
                )
            )

    # Station section
    if sta_blob:
        # May still include header line "Station MAC, ..."
        sta_reader = csv.reader(io.StringIO(sta_blob.strip()))
        sta_rows = list(sta_reader)
        start = 1 if sta_rows and "STATION" in "".join(sta_rows[0]).upper() else 0
        for row in sta_rows[start:]:
            if len(row) < 6:
                continue
            mac = _clean(row[0])
            if not MAC_RE.match(mac):
                continue
            stations.append(
                Station(
                    station_mac=mac,
                    first_seen=_clean(row[1]) if len(row) > 1 else "",
                    last_seen=_clean(row[2]) if len(row) > 2 else "",
                    power=_clean(row[3]) if len(row) > 3 else "",
                    packets=_clean(row[4]) if len(row) > 4 else "",
                    bssid=_clean(row[5]) if len(row) > 5 else "",
                    probed_essids=_clean(",".join(row[6:])) if len(row) > 6 else "",
                )
            )

    return access_points, stations


def parse_airodump_csv_file(path: Path) -> tuple[list[AccessPoint], list[Station]]:
    if not path.exists():
        return [], []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], []
    return parse_airodump_csv(text)


def handshake_from_airodump_line(line: str) -> Optional[str]:
    m = HANDSHAKE_LINE_RE.search(line)
    return m.group(1) if m else None


def parse_aircrack_key(output: str) -> Optional[str]:
    m = AIRCRACK_KEY_RE.search(output)
    return m.group(1).strip() if m else None


def aircrack_reports_handshake(output: str) -> bool:
    """True if aircrack-ng sees at least one handshake in the cap."""
    # Common phrases: "1 handshake", "Opening ...", "No networks found"
    if re.search(r"No networks found", output, re.IGNORECASE):
        return False
    m = AIRCRACK_HANDSHAKE_COUNT_RE.search(output)
    if m and int(m.group(1)) >= 1:
        return True
    if re.search(r"handshake", output, re.IGNORECASE) and not re.search(
        r"0 handshake", output, re.IGNORECASE
    ):
        # Heuristic: presence of handshake wording without zero
        if re.search(r"[1-9]\d*\s+handshake", output, re.IGNORECASE):
            return True
    return False


def which_missing(binaries: list[str]) -> list[str]:
    """Return names of binaries not found on PATH (uses `command -v` style via shutil)."""
    import shutil

    return [b for b in binaries if shutil.which(b) is None]
