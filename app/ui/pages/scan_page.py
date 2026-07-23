"""Step 3 — scan access points."""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from app.ui.widgets import PageBase, make_treeview, pack_tree_with_scroll


class ScanPage(PageBase):
    title = "3. Scan"

    def __init__(self, master: Any, app: Any) -> None:
        super().__init__(master, app)
        self._poll_id: str | None = None
        self._poll_ticks = 0
        self._diagnosed = False

        ctk.CTkLabel(
            self,
            text="Scan networks",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(
            self,
            text=(
                "Start scan runs check kill + monitor reset, then airodump. "
                "Wait 10–15s for APs. If still empty, click Diagnose."
            ),
            text_color="gray70",
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 8))

        self.btn_start = ctk.CTkButton(
            btn_row, text="Start scan", width=120, command=self.start_scan
        )
        self.btn_start.pack(side="left", padx=(0, 8))
        self.btn_stop = ctk.CTkButton(
            btn_row,
            text="Stop scan",
            width=120,
            fg_color="#8B3A3A",
            hover_color="#6e2e2e",
            command=self.stop_scan,
            state="disabled",
        )
        self.btn_stop.pack(side="left", padx=(0, 8))
        ctk.CTkButton(btn_row, text="Refresh table", width=120, command=self.refresh_table).pack(
            side="left", padx=(0, 8)
        )
        ctk.CTkButton(btn_row, text="Diagnose", width=100, command=self.diagnose).pack(
            side="left", padx=(0, 8)
        )
        self.scan_status = ctk.CTkLabel(btn_row, text="Idle", text_color="gray70")
        self.scan_status.pack(side="left", padx=8)

        table_frame = ctk.CTkFrame(self, fg_color="transparent")
        table_frame.pack(fill="both", expand=True, pady=8)

        self.tree = make_treeview(
            table_frame,
            [
                ("bssid", "BSSID", 140),
                ("ch", "CH", 40),
                ("pwr", "PWR", 50),
                ("enc", "ENC", 90),
                ("cipher", "CIPHER", 70),
                ("essid", "ESSID", 180),
            ],
            height=14,
        )
        pack_tree_with_scroll(self.tree, table_frame)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        nav = ctk.CTkFrame(self, fg_color="transparent")
        nav.pack(fill="x", pady=(8, 0))
        ctk.CTkButton(nav, text="← Back", width=100, command=lambda: app.goto_step(2)).pack(
            side="left"
        )
        ctk.CTkButton(nav, text="Select target →", width=140, command=self.goto_target).pack(
            side="right"
        )

    def on_show(self) -> None:
        self.refresh_table()

    def start_scan(self) -> None:
        self._poll_ticks = 0
        self._diagnosed = False
        try:
            self.app.service.start_scan(
                on_line=lambda line: self.app.log(line),
                on_done=lambda code: self.ui(self._scan_finished, code),
            )
        except Exception as exc:
            self.app.log(str(exc))
            return
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.scan_status.configure(text="Scanning…")
        self._schedule_poll()

    def diagnose(self) -> None:
        self.app.service.diagnose_empty_scan()

    def stop_scan(self) -> None:
        self.app.service.stop_scan()
        self._cancel_poll()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.scan_status.configure(text="Stopped")
        self.refresh_table()

    def _scan_finished(self, code: int) -> None:
        self._cancel_poll()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.scan_status.configure(text=f"Exited ({code})")
        self.refresh_table()
        if not self.app.session.access_points:
            self.app.service.diagnose_empty_scan()

    def _schedule_poll(self) -> None:
        self._cancel_poll()
        self._poll_id = self.after(1000, self._poll)

    def _cancel_poll(self) -> None:
        if self._poll_id is not None:
            try:
                self.after_cancel(self._poll_id)
            except Exception:
                pass
            self._poll_id = None

    def _poll(self) -> None:
        self.refresh_table()
        self._poll_ticks += 1
        if (
            not self._diagnosed
            and self._poll_ticks >= 8
            and not self.app.session.access_points
            and self.app.service.scanning
        ):
            self._diagnosed = True
            self.app.log("Still 0 APs after ~8s — running diagnostics…")
            self.app.service.diagnose_empty_scan()
        if self.app.service.scanning:
            self._poll_id = self.after(1000, self._poll)

    def refresh_table(self) -> None:
        aps, _stas = self.app.service.refresh_scan_results()
        selected = None
        sel = self.tree.selection()
        if sel:
            selected = self.tree.item(sel[0], "values")[0]

        for item in self.tree.get_children():
            self.tree.delete(item)

        for ap in aps:
            enc = " ".join(x for x in (ap.privacy, ap.auth) if x)
            iid = self.tree.insert(
                "",
                "end",
                values=(ap.bssid, ap.channel, ap.power, enc, ap.cipher, ap.essid),
            )
            if selected and ap.bssid == selected:
                self.tree.selection_set(iid)

        self.scan_status.configure(
            text=f"{len(aps)} AP(s)" + (" · scanning…" if self.app.service.scanning else "")
        )

    def _on_select(self, _event: Any = None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        bssid = self.tree.item(sel[0], "values")[0]
        for ap in self.app.session.access_points:
            if ap.bssid == bssid:
                self.app.session.selected_ap = ap
                self.app.session.selected_client = None
                self.app.log(f"Selected AP: {ap.essid or '(hidden)'} [{ap.bssid}] CH {ap.channel}")
                break

    def goto_target(self) -> None:
        if not self.app.session.selected_ap:
            self._on_select()
        if not self.app.session.selected_ap:
            self.app.log("Select an AP from the table first.")
            return
        # Prefer stopped scan before capture, but allow continue
        self.app.goto_step(4)
