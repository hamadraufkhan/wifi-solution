"""Detect Wi-Fi chipsets and install Kali monitor/injection drivers."""

from __future__ import annotations

import os
import re
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from app.core.process_runner import ProcessRunner

OnLine = Callable[[str], None]


@dataclass
class DriverProfile:
    """Known chipset → recommended Kali driver package."""

    id: str
    label: str
    usb_id_patterns: list[str]  # lowercase substrings matched in lsusb
    chipset_keywords: list[str]  # matched in airmon/lsusb text
    bad_modules: list[str]  # stock drivers that break monitor
    good_module: str  # module name after install
    apt_package: str
    blacklist_modules: list[str]
    notes: str = ""


# Profiles ordered by specificity (first match wins)
PROFILES: list[DriverProfile] = [
    DriverProfile(
        id="rtl8188eus",
        label="Realtek RTL8188EUS / 8188EU (monitor + injection)",
        usb_id_patterns=["0bda:8179", "0bda:0179", "0bda:8189"],
        chipset_keywords=["rtl8188eus", "rtl8188eu", "rtl8188etv", "8188eu"],
        bad_modules=["rtl8xxxu", "r8188eu"],
        good_module="8188eu",
        apt_package="realtek-rtl8188eus-dkms",
        blacklist_modules=["r8188eu", "rtl8xxxu"],
        notes=(
            "Stock rtl8xxxu often reports monitor mode but captures 0 APs. "
            "Install realtek-rtl8188eus-dkms and blacklist rtl8xxxu."
        ),
    ),
    DriverProfile(
        id="rtl88xxau",
        label="Realtek RTL8812AU / 8814AU / 8821AU (88XXau)",
        usb_id_patterns=[
            "0bda:8812",
            "0bda:881a",
            "0bda:0821",
            "0bda:a811",
            "2357:0101",
            "2357:010d",
            "2357:011e",
            "2604:0012",
        ],
        chipset_keywords=["rtl8812", "rtl8814", "rtl8821", "88xxau", "8812au"],
        bad_modules=[],
        good_module="88XXau",
        apt_package="realtek-rtl88xxau-dkms",
        blacklist_modules=[],
        notes="Preferred for dual-band monitor/injection on Kali.",
    ),
    DriverProfile(
        id="rtl8814au",
        label="Realtek RTL8814AU",
        usb_id_patterns=["0bda:8813", "2357:0106"],
        chipset_keywords=["rtl8814au", "8814au"],
        bad_modules=[],
        good_module="8814au",
        apt_package="realtek-rtl8814au-dkms",
        blacklist_modules=[],
        notes="High-power AC adapter; use Kali DKMS package when available.",
    ),
]


@dataclass
class AdapterInfo:
    iface: str = ""
    driver: str = ""
    chipset: str = ""
    usb: str = ""
    usb_ids: str = ""
    profile: Optional[DriverProfile] = None
    status: str = "unknown"  # ok | needs_driver | unknown
    detail: str = ""


@dataclass
class DriverReport:
    adapters: list[AdapterInfo] = field(default_factory=list)
    lsusb: str = ""
    airmon: str = ""
    packages_installed: dict[str, bool] = field(default_factory=dict)
    kernel: str = ""
    is_root: bool = False


class DriverService:
    BLACKLIST_PATH = Path("/etc/modprobe.d/wifi-solution-realtek.conf")

    def __init__(self, *, log: Optional[OnLine] = None) -> None:
        self.log = log or (lambda _m: None)
        self._helper = ProcessRunner()
        self._install_runner = ProcessRunner()
        self._installing = False

    @property
    def installing(self) -> bool:
        return self._installing or self._install_runner.running

    def _emit(self, msg: str) -> None:
        self.log(msg)

    def is_root(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() == 0

    def package_installed(self, name: str) -> bool:
        code, _out = self._helper.run_capture(["dpkg", "-s", name], timeout=30)
        return code == 0

    def module_loaded(self, name: str) -> bool:
        code, out = self._helper.run_capture(["lsmod"], timeout=15)
        if code != 0:
            return False
        return bool(re.search(rf"^{re.escape(name)}\b", out or "", re.M))

    def current_driver(self, iface: str) -> str:
        # Prefer sysfs
        link = Path(f"/sys/class/net/{iface}/device/driver")
        try:
            if link.exists() or link.is_symlink():
                return link.resolve().name
        except OSError:
            pass
        code, out = self._helper.run_capture(["ethtool", "-i", iface], timeout=10)
        m = re.search(r"^driver:\s*(\S+)", out or "", re.M)
        return m.group(1) if m else ""

    def list_ifaces(self) -> list[str]:
        code, out = self._helper.run_capture(["iw", "dev"], timeout=15)
        names = re.findall(r"Interface\s+(\S+)", out or "")
        if names:
            return sorted(set(names))
        code, out = self._helper.run_capture(["iwconfig"], timeout=15)
        return sorted(set(re.findall(r"^(\S+)\s+IEEE\s+802\.11", out or "", re.M)))

    def _match_profile(self, blob: str) -> Optional[DriverProfile]:
        low = blob.lower()
        for prof in PROFILES:
            for uid in prof.usb_id_patterns:
                if uid.lower() in low:
                    return prof
            for kw in prof.chipset_keywords:
                if kw.lower() in low:
                    return prof
        return None

    def verify(self) -> DriverReport:
        report = DriverReport(
            kernel=os.uname().release if hasattr(os, "uname") else "",
            is_root=self.is_root(),
        )
        _c, report.lsusb = self._helper.run_capture(["lsusb"], timeout=20)
        _c, report.airmon = self._helper.run_capture(["airmon-ng"], timeout=30)

        for pkg in {p.apt_package for p in PROFILES}:
            report.packages_installed[pkg] = self.package_installed(pkg)

        # Build per-interface rows from airmon-ng when possible
        airmon_rows = self._parse_airmon_table(report.airmon)
        ifaces = self.list_ifaces()
        seen: set[str] = set()

        for row in airmon_rows:
            iface = row.get("iface", "")
            if not iface:
                continue
            seen.add(iface)
            chipset = row.get("chipset", "")
            driver = row.get("driver") or self.current_driver(iface)
            blob = " ".join([chipset, driver, report.lsusb, report.airmon])
            prof = self._match_profile(blob)
            info = AdapterInfo(
                iface=iface,
                driver=driver,
                chipset=chipset,
                usb=self._guess_usb_line(chipset, report.lsusb),
                profile=prof,
            )
            self._evaluate(info)
            report.adapters.append(info)

        for iface in ifaces:
            if iface in seen:
                continue
            driver = self.current_driver(iface)
            blob = " ".join([iface, driver, report.lsusb])
            prof = self._match_profile(blob)
            info = AdapterInfo(
                iface=iface,
                driver=driver,
                chipset=prof.label if prof else "",
                usb=self._guess_usb_line(driver, report.lsusb),
                profile=prof,
            )
            self._evaluate(info)
            report.adapters.append(info)

        # USB-only match (no iface yet / unplugged naming)
        if not report.adapters:
            prof = self._match_profile(report.lsusb + "\n" + report.airmon)
            if prof:
                info = AdapterInfo(
                    iface="(none up)",
                    driver="",
                    chipset=prof.label,
                    usb=self._guess_usb_line(prof.label, report.lsusb),
                    profile=prof,
                )
                self._evaluate(info)
                report.adapters.append(info)

        return report

    def _evaluate(self, info: AdapterInfo) -> None:
        prof = info.profile
        if not prof:
            info.status = "unknown"
            info.detail = (
                "No known package mapping. If scanning fails, use an Atheros/"
                "Ralink or Realtek AU adapter with Kali DKMS drivers."
            )
            return

        pkg_ok = self.package_installed(prof.apt_package)
        good_loaded = self.module_loaded(prof.good_module) or (
            info.driver.lower() == prof.good_module.lower()
        )
        bad_loaded = info.driver.lower() in [m.lower() for m in prof.bad_modules]

        if good_loaded and not bad_loaded and pkg_ok:
            info.status = "ok"
            info.detail = f"Using {info.driver or prof.good_module} — looks good for monitor/injection."
        elif bad_loaded or (prof.bad_modules and info.driver.lower() in [m.lower() for m in prof.bad_modules]):
            info.status = "needs_driver"
            info.detail = (
                f"Driver '{info.driver}' is known-bad for this chipset. "
                f"Install {prof.apt_package} (module {prof.good_module}). "
                f"{prof.notes}"
            )
        elif not pkg_ok:
            info.status = "needs_driver"
            info.detail = (
                f"Recommended package not installed: {prof.apt_package}. "
                f"{prof.notes}"
            )
        elif not good_loaded:
            info.status = "needs_driver"
            info.detail = (
                f"Package may be installed but module '{prof.good_module}' is not loaded "
                f"(current: {info.driver or 'unknown'}). Blacklist stock drivers and reload."
            )
        else:
            info.status = "ok"
            info.detail = "Profile matched; driver appears usable."

    def _parse_airmon_table(self, text: str) -> list[dict[str, str]]:
        rows: list[dict[str, str]] = []
        for line in (text or "").splitlines():
            # phy0  wlan0  rtl8xxxu  Realtek ...
            parts = re.split(r"\t+|\s{2,}", line.strip())
            if len(parts) < 3:
                continue
            if not parts[0].lower().startswith("phy"):
                continue
            rows.append(
                {
                    "phy": parts[0],
                    "iface": parts[1] if len(parts) > 1 else "",
                    "driver": parts[2] if len(parts) > 2 else "",
                    "chipset": parts[3] if len(parts) > 3 else " ".join(parts[3:]),
                }
            )
        return rows

    def _guess_usb_line(self, hint: str, lsusb: str) -> str:
        low_hint = (hint or "").lower()
        for line in (lsusb or "").splitlines():
            low = line.lower()
            if "wireless" in low or "802.11" in low or "wlan" in low or "realtek" in low:
                if not hint or any(x in low for x in low_hint.split()[:2] if len(x) > 3):
                    return line.strip()
        for line in (lsusb or "").splitlines():
            if "0bda:" in line.lower() or "2357:" in line.lower():
                return line.strip()
        return ""

    def ensure_blacklist(self, modules: list[str]) -> None:
        if not modules:
            return
        existing = ""
        if self.BLACKLIST_PATH.exists():
            existing = self.BLACKLIST_PATH.read_text(encoding="utf-8", errors="replace")
        lines = existing.splitlines()
        changed = False
        for mod in modules:
            entry = f"blacklist {mod}"
            if entry not in lines:
                lines.append(entry)
                changed = True
        if changed or not self.BLACKLIST_PATH.exists():
            self.BLACKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
            self.BLACKLIST_PATH.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
            self._emit(f"Wrote blacklist: {self.BLACKLIST_PATH}")

    def reload_modules(self, profile: DriverProfile) -> None:
        for mod in profile.bad_modules + [profile.good_module]:
            self._emit(f"rmmod {mod} (ignore errors)…")
            self._helper.run_capture(["rmmod", mod], timeout=20)
        self._emit(f"modprobe {profile.good_module}")
        code, out = self._helper.run_capture(["modprobe", profile.good_module], timeout=30)
        self._emit((out or "").strip() or f"modprobe exit {code}")

    def install_profile(
        self,
        profile: DriverProfile,
        *,
        on_line: Optional[OnLine] = None,
        on_done: Optional[Callable[[int], None]] = None,
    ) -> None:
        if self.installing:
            self._emit("Install already running.")
            return
        if not self.is_root():
            self._emit("Root required. Run via ./run.sh")
            if on_done:
                on_done(1)
            return

        self._installing = True
        kernel = os.uname().release

        def _run() -> None:
            code = 1
            try:
                cmds = [
                    ["apt-get", "update"],
                    [
                        "apt-get",
                        "install",
                        "-y",
                        "dkms",
                        "build-essential",
                        f"linux-headers-{kernel}",
                        profile.apt_package,
                    ],
                ]
                for cmd in cmds:
                    self._emit("Running: " + " ".join(cmd))
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                    )
                    out = (proc.stdout or "") + (proc.stderr or "")
                    for line in out.splitlines():
                        msg = line.rstrip()
                        if msg:
                            self._emit(msg)
                            if on_line:
                                on_line(msg)
                    code = proc.returncode
                    if code != 0:
                        self._emit(f"Command failed ({code}): {' '.join(cmd)}")
                        break
                else:
                    self.ensure_blacklist(profile.blacklist_modules)
                    self.reload_modules(profile)
                    self._emit(
                        f"Installed {profile.apt_package}. "
                        "Unplug/replug the adapter (or reboot) then Verify again."
                    )
                    code = 0
            except Exception as exc:
                self._emit(f"Install error: {exc}")
                code = 1
            finally:
                self._installing = False
                if on_done:
                    on_done(code)

        threading.Thread(target=_run, daemon=True).start()

    def profiles_for_report(self, report: DriverReport) -> list[DriverProfile]:
        found: list[DriverProfile] = []
        seen: set[str] = set()
        for ad in report.adapters:
            if ad.profile and ad.profile.id not in seen:
                found.append(ad.profile)
                seen.add(ad.profile.id)
        return found
