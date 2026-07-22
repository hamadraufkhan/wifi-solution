"""Step 2 — monitor mode."""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from app.ui.widgets import PageBase


class MonitorPage(PageBase):
    title = "2. Monitor"

    def __init__(self, master: Any, app: Any) -> None:
        super().__init__(master, app)

        ctk.CTkLabel(
            self,
            text="Monitor mode",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(
            self,
            text=(
                "Start monitor runs check kill automatically (stops NetworkManager). "
                "That is required on Realtek sticks or scans stay empty."
            ),
            text_color="gray70",
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(0, 16))

        self.info = ctk.CTkLabel(self, text="", justify="left")
        self.info.pack(anchor="w", pady=(0, 12))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", pady=8)

        ctk.CTkButton(
            btn_row, text="Check kill", width=140, command=self.do_check_kill
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="Start monitor", width=140, command=self.do_start
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            btn_row, text="Stop monitor", width=140, fg_color="#8B3A3A",
            hover_color="#6e2e2e", command=self.do_stop,
        ).pack(side="left", padx=(0, 8))

        self.result = ctk.CTkTextbox(self, height=180)
        self.result.pack(fill="both", expand=True, pady=(12, 8))

        nav = ctk.CTkFrame(self, fg_color="transparent")
        nav.pack(fill="x")
        ctk.CTkButton(nav, text="← Back", width=100, command=lambda: app.goto_step(0)).pack(
            side="left"
        )
        ctk.CTkButton(nav, text="Continue →", width=120, command=self.continue_next).pack(
            side="right"
        )

    def on_show(self) -> None:
        iface = self.app.session.interface or "(none)"
        mon = self.app.session.monitor_interface or "(none)"
        self.info.configure(text=f"Managed interface: {iface}\nMonitor interface: {mon}")

    def _append(self, text: str) -> None:
        self.result.insert("end", text + "\n")
        self.result.see("end")

    def do_check_kill(self) -> None:
        ok, out = self.app.service.check_kill()
        self._append(out or "(done)")
        self.app.log("airmon-ng check kill finished" + ("" if ok else " with errors"))

    def do_start(self) -> None:
        iface = self.app.session.interface
        if not iface:
            self.app.log("Select an interface first.")
            self.app.goto_step(0)
            return
        if iface.endswith("mon"):
            self.app.session.monitor_interface = iface
            self._append(f"Already a monitor interface: {iface}")
            self.on_show()
            return

        ok, out, mon = self.app.service.start_monitor(iface)
        self._append(out or "")
        if ok and mon:
            self.app.set_status(f"Monitor: {mon}")
            self.app.log(f"Monitor mode enabled on {mon}")
            if mon == iface:
                self._append(
                    f"Note: monitor is on {mon} itself (common for Realtek rtl8xxxu)."
                )
        else:
            self.app.log(
                "Failed to enable monitor mode. Adapter may lack support, "
                "or you need to run with sudo. Try: Check kill, then Start again."
            )
        self.on_show()

    def do_stop(self) -> None:
        ok, out = self.app.service.stop_monitor()
        self._append(out or "")
        self.app.set_status("Monitor stopped")
        self.on_show()

    def continue_next(self) -> None:
        if not self.app.session.monitor_interface:
            self.app.log("Enable monitor mode before scanning.")
            return
        self.app.goto_step(2)
