"""Step 1 — select wireless interface."""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from app.ui.widgets import PageBase


class InterfacePage(PageBase):
    title = "1. Interface"

    def __init__(self, master: Any, app: Any) -> None:
        super().__init__(master, app)

        ctk.CTkLabel(
            self,
            text="Wireless interface",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(
            self,
            text="Select the Wi-Fi adapter that supports monitor mode and injection.",
            text_color="gray70",
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(0, 16))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 8))

        ctk.CTkButton(btn_row, text="Refresh", width=120, command=self.refresh).pack(
            side="left", padx=(0, 8)
        )
        self.status = ctk.CTkLabel(btn_row, text="", text_color="gray70")
        self.status.pack(side="left")

        self.listbox = ctk.CTkScrollableFrame(self, height=220)
        self.listbox.pack(fill="both", expand=True, pady=(8, 8))

        self._selected = ctk.StringVar(value="")

        action = ctk.CTkFrame(self, fg_color="transparent")
        action.pack(fill="x", pady=(8, 0))
        ctk.CTkButton(
            action, text="Use selected →", command=self.use_selected
        ).pack(side="right")

    def on_show(self) -> None:
        self.refresh()

    def refresh(self) -> None:
        for child in self.listbox.winfo_children():
            child.destroy()

        try:
            ifaces = self.app.service.list_interfaces()
        except Exception as exc:
            self.status.configure(text=str(exc))
            self.app.log(f"Interface list error: {exc}")
            return

        if not ifaces:
            self.status.configure(
                text="No wireless interfaces found. Plug in an adapter or check drivers."
            )
            return

        self.status.configure(text=f"{len(ifaces)} interface(s)")
        current = self.app.session.interface or self.app.session.monitor_interface or ""

        for name in ifaces:
            row = ctk.CTkFrame(self.listbox, fg_color=("gray90", "gray20"))
            row.pack(fill="x", pady=4, padx=4)
            rb = ctk.CTkRadioButton(
                row,
                text=name,
                variable=self._selected,
                value=name,
            )
            rb.pack(side="left", padx=12, pady=10)
            if name == current or (not current and not self._selected.get()):
                self._selected.set(name)

    def use_selected(self) -> None:
        name = self._selected.get().strip()
        if not name:
            self.app.log("Select an interface first.")
            return
        self.app.session.interface = name
        # If user picked a monitor iface, keep it as monitor
        if name.endswith("mon"):
            self.app.session.monitor_interface = name
        self.app.log(f"Selected interface: {name}")
        self.app.set_status(f"Interface: {name}")
        self.app.goto_step(1)
