"""Step 1 — verify / install Wi-Fi drivers for monitor + injection."""

from __future__ import annotations

from typing import Any, Optional

import customtkinter as ctk

from app.core.driver_service import AdapterInfo, DriverProfile, DriverReport, DriverService
from app.ui.widgets import PageBase, make_treeview, pack_tree_with_scroll


class DriversPage(PageBase):
    title = "1. Drivers"

    def __init__(self, master: Any, app: Any) -> None:
        super().__init__(master, app)
        self.drivers = DriverService(log=self.app.log)
        self._report: Optional[DriverReport] = None
        self._selected_profile: Optional[DriverProfile] = None

        ctk.CTkLabel(
            self,
            text="Wi-Fi drivers",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(
            self,
            text=(
                "Verify the USB adapter driver before scanning. "
                "RTL8188EUS on stock rtl8xxxu often sees 0 networks — "
                "install Kali’s realtek-rtl8188eus-dkms package instead."
            ),
            text_color="gray70",
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 8))
        ctk.CTkButton(btn_row, text="Verify adapters", width=140, command=self.verify).pack(
            side="left", padx=(0, 8)
        )
        self.btn_install = ctk.CTkButton(
            btn_row,
            text="Install recommended",
            width=160,
            command=self.install_selected,
            state="disabled",
        )
        self.btn_install.pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row,
            text="Blacklist + reload",
            width=140,
            command=self.blacklist_reload,
            state="normal",
        ).pack(side="left", padx=(0, 8))

        self.status = ctk.CTkLabel(self, text="Click Verify adapters", text_color="gray70")
        self.status.pack(anchor="w", pady=(0, 8))

        table_frame = ctk.CTkFrame(self, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, pady=4)

        self.tree = make_treeview(
            table_frame,
            [
                ("iface", "Iface", 80),
                ("driver", "Driver", 100),
                ("chipset", "Chipset", 220),
                ("status", "Status", 100),
                ("package", "Package", 180),
            ],
            height=6,
        )
        pack_tree_with_scroll(self.tree, table_frame)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self.detail = ctk.CTkTextbox(self, height=120)
        self.detail.pack(fill="x", pady=(8, 8))

        nav = ctk.CTkFrame(self, fg_color="transparent")
        nav.pack(fill="x")
        ctk.CTkButton(
            nav, text="Continue → Interface", width=180, command=lambda: app.goto_step(1)
        ).pack(side="right")

    def on_show(self) -> None:
        if self._report is None:
            self.verify()

    def verify(self) -> None:
        if getattr(self, "_verifying", False):
            self.app.log("Verify already running…")
            return
        self._verifying = True
        self.status.configure(text="Verifying… (background)")
        self.app.log("Verifying Wi-Fi adapters / drivers…")
        self.btn_install.configure(state="disabled")

        def _worker() -> None:
            try:
                report = self.drivers.verify()
                self.ui(self._apply_report, report, None)
            except Exception as exc:
                self.ui(self._apply_report, None, str(exc))

        import threading

        threading.Thread(target=_worker, daemon=True).start()

    def _apply_report(self, report: Optional[DriverReport], error: Optional[str]) -> None:
        self._verifying = False
        if error:
            self.app.log(f"Verify failed: {error}")
            self.status.configure(text=error)
            return
        assert report is not None
        self._report = report
        self._fill_table(report)
        needs = [a for a in report.adapters if a.status == "needs_driver"]
        if needs:
            self.status.configure(
                text=f"{len(needs)} adapter(s) need a better driver — select a row and Install."
            )
            self.btn_install.configure(state="normal")
        elif report.adapters:
            self.status.configure(text="Adapters look OK for monitor/injection.")
            self.btn_install.configure(state="disabled")
        else:
            self.status.configure(text="No wireless adapters found. Plug in USB Wi-Fi.")
            self.btn_install.configure(state="disabled")

        self.detail.delete("1.0", "end")
        self.detail.insert(
            "end",
            f"Kernel: {report.kernel}\nRoot: {report.is_root}\n\n"
            "lsusb (wireless-related):\n"
            + "\n".join(
                ln
                for ln in report.lsusb.splitlines()
                if any(
                    k in ln.lower()
                    for k in ("wireless", "802.11", "realtek", "ralink", "atheros", "0bda:", "2357:")
                )
            )
            or report.lsusb[:500],
        )

    def _fill_table(self, report: DriverReport) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for ad in report.adapters:
            pkg = ad.profile.apt_package if ad.profile else "—"
            self.tree.insert(
                "",
                "end",
                values=(
                    ad.iface,
                    ad.driver or "—",
                    (ad.chipset or "—")[:40],
                    ad.status,
                    pkg,
                ),
                tags=(ad.status,),
            )
        try:
            self.tree.tag_configure("ok", foreground="#3cb371")
            self.tree.tag_configure("needs_driver", foreground="#e0a800")
            self.tree.tag_configure("unknown", foreground="#aaa")
        except Exception:
            pass

    def _on_select(self, _event: Any = None) -> None:
        sel = self.tree.selection()
        if not sel or not self._report:
            return
        vals = self.tree.item(sel[0], "values")
        iface = vals[0]
        ad: Optional[AdapterInfo] = None
        for a in self._report.adapters:
            if a.iface == iface:
                ad = a
                break
        if not ad:
            return
        self._selected_profile = ad.profile
        self.detail.delete("1.0", "end")
        lines = [
            f"Interface: {ad.iface}",
            f"Driver: {ad.driver or '—'}",
            f"Chipset: {ad.chipset or '—'}",
            f"USB: {ad.usb or '—'}",
            f"Status: {ad.status}",
            "",
            ad.detail,
        ]
        if ad.profile:
            lines += [
                "",
                f"Recommended package: {ad.profile.apt_package}",
                f"Module: {ad.profile.good_module}",
                f"Blacklist: {', '.join(ad.profile.blacklist_modules) or '(none)'}",
            ]
            self.btn_install.configure(state="normal")
        else:
            self.btn_install.configure(state="disabled")
        self.detail.insert("end", "\n".join(lines))

    def install_selected(self) -> None:
        prof = self._selected_profile
        if not prof and self._report:
            # Prefer first needs_driver profile
            for ad in self._report.adapters:
                if ad.status == "needs_driver" and ad.profile:
                    prof = ad.profile
                    break
        if not prof:
            self.app.log("Select an adapter that has a recommended package.")
            return
        if self.drivers.installing:
            self.app.log("Install already in progress…")
            return
        self.btn_install.configure(state="disabled")
        self.status.configure(text=f"Installing {prof.apt_package}… (see log)")
        self.app.log(f"Installing driver package: {prof.apt_package}")

        def _done(code: int) -> None:
            self.ui(self._install_done, code)

        self.drivers.install_profile(prof, on_done=_done)

    def _install_done(self, code: int) -> None:
        self.btn_install.configure(state="normal")
        if code == 0:
            self.status.configure(
                text="Install finished — unplug/replug adapter (or reboot), then Verify."
            )
        else:
            self.status.configure(text=f"Install failed (exit {code}). See log.")
        self.verify()

    def blacklist_reload(self) -> None:
        prof = self._selected_profile
        if not prof and self._report:
            for ad in self._report.adapters:
                if ad.profile:
                    prof = ad.profile
                    break
        if not prof:
            self.app.log("Select an adapter first.")
            return
        try:
            self.drivers.ensure_blacklist(prof.blacklist_modules)
            self.drivers.reload_modules(prof)
            self.app.log("Blacklist written and modules reloaded. Replug USB, then Verify.")
            self.verify()
        except Exception as exc:
            self.app.log(str(exc))
