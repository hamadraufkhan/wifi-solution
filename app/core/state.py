"""Shared session state for the wizard flow."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class AccessPoint:
    bssid: str
    first_seen: str = ""
    last_seen: str = ""
    channel: str = ""
    speed: str = ""
    privacy: str = ""
    cipher: str = ""
    auth: str = ""
    power: str = ""
    beacons: str = ""
    iv: str = ""
    lan_ip: str = ""
    id_length: str = ""
    essid: str = ""
    key: str = ""


@dataclass
class Station:
    station_mac: str
    first_seen: str = ""
    last_seen: str = ""
    power: str = ""
    packets: str = ""
    bssid: str = ""
    probed_essids: str = ""


@dataclass
class SessionState:
    """Mutable session shared across wizard pages."""

    interface: Optional[str] = None
    monitor_interface: Optional[str] = None
    selected_ap: Optional[AccessPoint] = None
    selected_client: Optional[Station] = None
    capture_prefix: Optional[str] = None
    capture_cap_path: Optional[Path] = None
    handshake_ready: bool = False
    cracked_key: Optional[str] = None
    wordlist_path: Optional[Path] = None
    access_points: list[AccessPoint] = field(default_factory=list)
    stations: list[Station] = field(default_factory=list)
    scan_csv_path: Optional[Path] = None

    def reset_scan(self) -> None:
        self.access_points.clear()
        self.stations.clear()
        self.scan_csv_path = None
        self.selected_ap = None
        self.selected_client = None
        self.handshake_ready = False
        self.cracked_key = None
        self.capture_prefix = None
        self.capture_cap_path = None
