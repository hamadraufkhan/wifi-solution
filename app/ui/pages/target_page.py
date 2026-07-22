"""Step 4 — select AP and client."""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from app.ui.widgets import PageBase, make_treeview, pack_tree_with_scroll


class TargetPage(PageBase):
    title = "4. Target"

    def __init__(self, master: Any, app: Any) -> None:
        super().__init__(master, app)

        ctk.CTkLabel(
            self,
            text="Select target",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", pady=(0, 8))

        self.ap_label = ctk.CTkLabel(self, text="AP: (none)", justify="left")
        self.ap_label.pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(
            self,
            text="Associated clients (select one for targeted deauth, or continue without)",
            text_color="gray70",
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(0, 8))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 8))
        ctk.CTkButton(btn_row, text="Refresh clients", width=140, command=self.refresh).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(
            btn_row, text="Clear client", width=120, command=self.clear_client
        ).pack(side="left")

        table_frame = ctk.CTkFrame(self, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, pady=8)

        self.tree = make_treeview(
            table_frame,
            [
                ("mac", "Station MAC", 160),
                ("pwr", "PWR", 50),
                ("pkts", "Packets", 80),
                ("probes", "Probed ESSIDs", 220),
            ],
            height=10,
        )
        pack_tree_with_scroll(self.tree, table_frame)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        self.client_label = ctk.CTkLabel(self, text="Client: (broadcast deauth)")
        self.client_label.pack(anchor="w", pady=(4, 8))

        nav = ctk.CTkFrame(self, fg_color="transparent")
        nav.pack(fill="x")
        ctk.CTkButton(nav, text="← Back", width=100, command=lambda: app.goto_step(2)).pack(
            side="left"
        )
        ctk.CTkButton(nav, text="Capture →", width=120, command=self.goto_capture).pack(
            side="right"
        )

    def on_show(self) -> None:
        ap = self.app.state.selected_ap
        if ap:
            self.ap_label.configure(
                text=f"AP: {ap.essid or '(hidden)'}  |  {ap.bssid}  |  CH {ap.channel}  |  {ap.privacy}"
            )
        else:
            self.ap_label.configure(text="AP: (none) — go back to Scan and select one")
        self.refresh()
        self._update_client_label()

    def refresh(self) -> None:
        self.app.service.refresh_scan_results()
        ap = self.app.state.selected_ap
        for item in self.tree.get_children():
            self.tree.delete(item)
        if not ap:
            return
        stations = self.app.service.stations_for_ap(ap.bssid)
        for sta in stations:
            self.tree.insert(
                "",
                "end",
                values=(sta.station_mac, sta.power, sta.packets, sta.probed_essids),
            )

    def _on_select(self, _event: Any = None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        mac = self.tree.item(sel[0], "values")[0]
        ap = self.app.state.selected_ap
        if not ap:
            return
        for sta in self.app.service.stations_for_ap(ap.bssid):
            if sta.station_mac == mac:
                self.app.state.selected_client = sta
                self.app.log(f"Selected client: {mac}")
                break
        self._update_client_label()

    def clear_client(self) -> None:
        self.app.state.selected_client = None
        self.tree.selection_remove(self.tree.selection())
        self._update_client_label()
        self.app.log("Client cleared — deauth will target all clients on AP")

    def _update_client_label(self) -> None:
        client = self.app.state.selected_client
        if client:
            self.client_label.configure(text=f"Client: {client.station_mac}")
        else:
            self.client_label.configure(text="Client: (broadcast deauth)")

    def goto_capture(self) -> None:
        if not self.app.state.selected_ap:
            self.app.log("Select an AP first.")
            return
        # Stop scan so channel lock works cleanly
        if self.app.service.scanning:
            self.app.service.stop_scan()
        self.app.goto_step(4)
