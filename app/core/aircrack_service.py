"""High-level wrappers around the aircrack-ng suite."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Optional

from app.core import parsers
from app.core.process_runner import ProcessRunner
from app.core.state import SessionState, Station

REQUIRED_BINARIES = [
    "airmon-ng",
    "airodump-ng",
    "aireplay-ng",
    "aircrack-ng",
]

OnLine = Callable[[str], None]
OnDone = Callable[[int], None]


class AircrackService:
    def __init__(
        self,
        state: SessionState,
        *,
        captures_dir: Optional[Path] = None,
        log: Optional[OnLine] = None,
    ) -> None:
        self.state = state
        self.log = log or (lambda _msg: None)
        root = Path(__file__).resolve().parents[2]
        self.captures_dir = captures_dir or (root / "captures")
        self.captures_dir.mkdir(parents=True, exist_ok=True)

        self._scan_runner = ProcessRunner()
        self._capture_runner = ProcessRunner()
        self._deauth_runner = ProcessRunner()
        self._crack_runner = ProcessRunner()
        self._helper = ProcessRunner()

        self._scan_prefix: Optional[Path] = None
        self._capture_prefix: Optional[Path] = None

    # ------------------------------------------------------------------ utils
    def missing_binaries(self) -> list[str]:
        return parsers.which_missing(REQUIRED_BINARIES)

    def is_root(self) -> bool:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        return False

    def _emit(self, msg: str) -> None:
        self.log(msg)

    def stop_all(self) -> None:
        for runner in (
            self._scan_runner,
            self._capture_runner,
            self._deauth_runner,
            self._crack_runner,
        ):
            runner.stop(force=True)

    # ------------------------------------------------------------- interfaces
    def list_interfaces(self) -> list[str]:
        code, out = self._helper.run_capture(["iwconfig"])
        ifaces = parsers.parse_wireless_interfaces(out)
        if not ifaces:
            code2, out2 = self._helper.run_capture(["ip", "link", "show"])
            ifaces = parsers.parse_ip_link_wireless_hint(out2)
            if code2 != 0 and not ifaces:
                self._emit(out2.strip() or "Failed to list interfaces via ip link")
        if code != 0 and "no wireless extensions" not in out.lower() and not ifaces:
            # iwconfig exits non-zero sometimes when some ifaces lack wireless
            pass
        # Include current monitor iface if known
        mon = self.state.monitor_interface
        if mon and mon not in ifaces:
            ifaces.append(mon)
        return sorted(set(ifaces))

    # ----------------------------------------------------------- monitor mode
    def check_kill(self) -> tuple[bool, str]:
        self._emit("Running: airmon-ng check kill")
        code, out = self._helper.run_capture(["airmon-ng", "check", "kill"])
        self._emit(out.strip() or "(no output)")
        return code == 0, out

    def start_monitor(self, interface: str) -> tuple[bool, str, Optional[str]]:
        self._emit(f"Running: airmon-ng start {interface}")
        code, out = self._helper.run_capture(["airmon-ng", "start", interface])
        self._emit(out.strip() or "(no output)")
        mon = parsers.parse_airmon_monitor_iface(out)

        if not mon:
            mon = self._discover_monitor_iface(preferred=interface)

        if not mon:
            # Realtek (rtl8xxxu / RTL8188EUS) often needs iw instead of airmon-ng
            self._emit(
                "airmon-ng did not report a clear monitor iface; "
                f"trying iw fallback on {interface}…"
            )
            ok_iw, iw_out = self._enable_monitor_via_iw(interface)
            out = (out or "") + "\n" + iw_out
            if ok_iw:
                mon = interface

        if not mon:
            mon = self._discover_monitor_iface(preferred=interface)

        if mon:
            self.state.interface = interface
            self.state.monitor_interface = mon
            self._emit(f"Monitor interface: {mon}")
            return True, out, mon
        return False, out or "Could not determine monitor interface", None

    def _discover_monitor_iface(self, preferred: Optional[str] = None) -> Optional[str]:
        """Find an interface already in monitor mode via iw/iwconfig."""
        code, iw_out = self._helper.run_capture(["iw", "dev"])
        mons = parsers.parse_iw_monitor_interfaces(iw_out) if code == 0 or iw_out else []
        if preferred and preferred in mons:
            return preferred
        if mons:
            return mons[0]

        # iwconfig fallback
        _c, iwc = self._helper.run_capture(["iwconfig"])
        if preferred and parsers.iface_is_monitor(iwc, preferred):
            return preferred
        ifaces = parsers.parse_wireless_interfaces(iwc)
        for name in ifaces:
            if parsers.iface_is_monitor(iwc, name):
                return name
        guess = None
        if preferred:
            guess = f"{preferred}mon" if not preferred.endswith("mon") else preferred
            if guess in ifaces:
                return guess
        for name in ifaces:
            if name.endswith("mon"):
                return name
        return None

    def _enable_monitor_via_iw(self, interface: str) -> tuple[bool, str]:
        """Set type monitor with iw (works on many mac80211 Realtek sticks)."""
        logs: list[str] = []
        for cmd in (
            ["ip", "link", "set", interface, "down"],
            ["iw", "dev", interface, "set", "type", "monitor"],
            ["ip", "link", "set", interface, "up"],
        ):
            self._emit("Running: " + " ".join(cmd))
            code, out = self._helper.run_capture(cmd)
            chunk = out.strip() or f"(exit {code})"
            logs.append(" ".join(cmd) + " -> " + chunk)
            self._emit(chunk)
            if code != 0 and "set type monitor" in " ".join(cmd):
                return False, "\n".join(logs)

        # Confirm
        mon = self._discover_monitor_iface(preferred=interface)
        if mon:
            return True, "\n".join(logs)
        return False, "\n".join(logs) + "\nMonitor mode not confirmed after iw fallback"

    def stop_monitor(self, mon_iface: Optional[str] = None) -> tuple[bool, str]:
        target = mon_iface or self.state.monitor_interface
        if not target:
            return False, "No monitor interface set"
        self._emit(f"Running: airmon-ng stop {target}")
        code, out = self._helper.run_capture(["airmon-ng", "stop", target])
        self._emit(out.strip() or "(no output)")
        restored = parsers.parse_airmon_disabled_iface(out)

        # If still in monitor (airmon no-op / same-iface Realtek), restore via iw
        still = self._discover_monitor_iface(preferred=target)
        if still == target:
            self._emit(f"Trying iw managed restore on {target}…")
            for cmd in (
                ["ip", "link", "set", target, "down"],
                ["iw", "dev", target, "set", "type", "managed"],
                ["ip", "link", "set", target, "up"],
            ):
                c, o = self._helper.run_capture(cmd)
                self._emit((o.strip() or f"(exit {c})"))
            restored = restored or target

        self.state.monitor_interface = None
        if restored:
            self.state.interface = restored
        elif self.state.interface is None:
            self.state.interface = target
        return True, out

    # ------------------------------------------------------------------- scan
    @property
    def scanning(self) -> bool:
        return self._scan_runner.running

    def start_scan(
        self,
        *,
        on_line: Optional[OnLine] = None,
        on_done: Optional[OnDone] = None,
    ) -> Path:
        mon = self.state.monitor_interface
        if not mon:
            raise RuntimeError("Monitor interface not set. Enable monitor mode first.")

        self.stop_scan()
        self.state.reset_scan()

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = self.captures_dir / f"scan_{stamp}"
        self._scan_prefix = prefix
        csv_path = Path(f"{prefix}-01.csv")
        self.state.scan_csv_path = csv_path

        cmd = [
            "airodump-ng",
            "--write-interval",
            "1",
            "-w",
            str(prefix),
            "--output-format",
            "csv",
            mon,
        ]
        self._emit("Starting scan: " + " ".join(cmd))

        def _line(line: str) -> None:
            if on_line:
                on_line(line)

        def _done(code: int) -> None:
            self._emit(f"Scan process exited ({code})")
            if on_done:
                on_done(code)

        self._scan_runner.start(cmd, on_line=_line, on_done=_done)
        return csv_path

    def stop_scan(self) -> None:
        if self._scan_runner.running:
            self._emit("Stopping scan...")
            self._scan_runner.stop()

    def refresh_scan_results(self) -> tuple[list[AccessPoint], list[Station]]:
        path = self.state.scan_csv_path
        if not path:
            return [], []
        # airodump may still be writing; retry briefly
        aps, stas = [], []
        for _ in range(3):
            aps, stas = parsers.parse_airodump_csv_file(path)
            if aps or stas:
                break
            time.sleep(0.2)
        self.state.access_points = aps
        self.state.stations = stas
        return aps, stas

    def stations_for_ap(self, bssid: str) -> list[Station]:
        bssid_l = bssid.lower()
        return [
            s
            for s in self.state.stations
            if s.bssid.lower() == bssid_l and s.bssid.lower() != "(not associated)"
        ]

    # ---------------------------------------------------------------- capture
    @property
    def capturing(self) -> bool:
        return self._capture_runner.running

    def start_capture(
        self,
        *,
        on_line: Optional[OnLine] = None,
        on_done: Optional[OnDone] = None,
        on_handshake: Optional[Callable[[], None]] = None,
    ) -> Path:
        mon = self.state.monitor_interface
        ap = self.state.selected_ap
        if not mon:
            raise RuntimeError("Monitor interface not set")
        if not ap:
            raise RuntimeError("No access point selected")
        channel = (ap.channel or "").strip()
        if not channel or channel == "-1":
            raise RuntimeError("Selected AP has no valid channel")

        self.stop_capture()
        self.state.handshake_ready = False
        self.state.cracked_key = None

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_essid = re.sub(r"[^\w\-]+", "_", ap.essid or "unknown")[:32]
        prefix = self.captures_dir / f"cap_{safe_essid}_{stamp}"
        self._capture_prefix = prefix
        self.state.capture_prefix = str(prefix)
        cap_path = Path(f"{prefix}-01.cap")
        self.state.capture_cap_path = cap_path

        cmd = [
            "airodump-ng",
            "--write-interval",
            "1",
            "-c",
            channel,
            "--bssid",
            ap.bssid,
            "-w",
            str(prefix),
            mon,
        ]
        self._emit("Starting capture: " + " ".join(cmd))

        def _line(line: str) -> None:
            if on_line:
                on_line(line)
            hs = parsers.handshake_from_airodump_line(line)
            if hs and not self.state.handshake_ready:
                self.state.handshake_ready = True
                self._emit(f"Handshake detected for {hs}")
                if on_handshake:
                    on_handshake()

        def _done(code: int) -> None:
            self._emit(f"Capture process exited ({code})")
            # Final handshake probe
            if not self.state.handshake_ready:
                if self.probe_handshake():
                    if on_handshake:
                        on_handshake()
            if on_done:
                on_done(code)

        self._capture_runner.start(cmd, on_line=_line, on_done=_done)
        return cap_path

    def stop_capture(self) -> None:
        if self._capture_runner.running:
            self._emit("Stopping capture...")
            self._capture_runner.stop()

    def deauth(
        self,
        *,
        count: int = 5,
        on_line: Optional[OnLine] = None,
        on_done: Optional[OnDone] = None,
    ) -> None:
        mon = self.state.monitor_interface
        ap = self.state.selected_ap
        client = self.state.selected_client
        if not mon or not ap:
            raise RuntimeError("Monitor interface and AP required for deauth")

        cmd = ["aireplay-ng", "-0", str(count), "-a", ap.bssid]
        if client and client.station_mac:
            cmd.extend(["-c", client.station_mac])
        cmd.append(mon)

        self._emit("Deauth: " + " ".join(cmd))

        def _line(line: str) -> None:
            self._emit(line)
            if on_line:
                on_line(line)

        self._deauth_runner.start(cmd, on_line=_line, on_done=on_done)

    def probe_handshake(self) -> bool:
        cap = self.state.capture_cap_path
        if not cap or not cap.exists():
            return False
        code, out = self._helper.run_capture(
            ["aircrack-ng", str(cap)],
            timeout=30,
        )
        ready = parsers.aircrack_reports_handshake(out)
        if ready:
            self.state.handshake_ready = True
            self._emit("Handshake confirmed via aircrack-ng probe")
        return ready

    # ------------------------------------------------------------------- crack
    @property
    def cracking(self) -> bool:
        return self._crack_runner.running

    def start_crack(
        self,
        wordlist: Path,
        *,
        on_line: Optional[OnLine] = None,
        on_done: Optional[Callable[[int, Optional[str]], None]] = None,
    ) -> None:
        cap = self.state.capture_cap_path
        ap = self.state.selected_ap
        if not cap or not cap.exists():
            raise RuntimeError(f"Capture file not found: {cap}")
        if not wordlist.exists():
            raise RuntimeError(f"Wordlist not found: {wordlist}")
        if not ap:
            raise RuntimeError("No AP selected")

        self.state.wordlist_path = wordlist
        self.state.cracked_key = None

        cmd = ["aircrack-ng", "-w", str(wordlist), "-b", ap.bssid, str(cap)]
        self._emit("Cracking: " + " ".join(cmd))

        buffer: list[str] = []

        def _line(line: str) -> None:
            buffer.append(line)
            key = parsers.parse_aircrack_key(line)
            if key:
                self.state.cracked_key = key
                self._emit(f"KEY FOUND: {key}")
            if on_line:
                on_line(line)

        def _done(code: int) -> None:
            joined = "\n".join(buffer)
            if not self.state.cracked_key:
                key = parsers.parse_aircrack_key(joined)
                if key:
                    self.state.cracked_key = key
            self._emit(f"Crack process exited ({code})")
            if on_done:
                on_done(code, self.state.cracked_key)

        self._crack_runner.start(cmd, on_line=_line, on_done=_done)

    def stop_crack(self) -> None:
        if self._crack_runner.running:
            self._emit("Stopping crack...")
            self._crack_runner.stop()

    def tool_hint(self) -> str:
        missing = self.missing_binaries()
        if not missing:
            return ""
        return (
            "Missing tools: "
            + ", ".join(missing)
            + "\nInstall with: sudo apt install aircrack-ng"
        )
