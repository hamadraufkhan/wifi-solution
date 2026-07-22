"""Step 5 — capture handshake and deauth."""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from app.ui.widgets import PageBase


class CapturePage(PageBase):
    title = "5. Capture"

    def __init__(self, master: Any, app: Any) -> None:
        super().__init__(master, app)
        self._poll_id: str | None = None

        ctk.CTkLabel(
            self,
            text="Capture handshake",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", pady=(0, 8))

        self.summary = ctk.CTkLabel(self, text="", justify="left")
        self.summary.pack(anchor="w", pady=(0, 12))

        self.hs_badge = ctk.CTkLabel(
            self,
            text="Handshake: waiting",
            font=ctk.CTkFont(size=16, weight="bold"),
            text_color="#c9a227",
        )
        self.hs_badge.pack(anchor="w", pady=(0, 12))

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", pady=(0, 8))

        self.btn_start = ctk.CTkButton(
            btn_row, text="Start capture", width=140, command=self.start_capture
        )
        self.btn_start.pack(side="left", padx=(0, 8))
        self.btn_stop = ctk.CTkButton(
            btn_row,
            text="Stop capture",
            width=140,
            fg_color="#8B3A3A",
            hover_color="#6e2e2e",
            command=self.stop_capture,
            state="disabled",
        )
        self.btn_stop.pack(side="left", padx=(0, 8))

        deauth_row = ctk.CTkFrame(self, fg_color="transparent")
        deauth_row.pack(fill="x", pady=(8, 8))

        ctk.CTkLabel(deauth_row, text="Deauth bursts:").pack(side="left", padx=(0, 8))
        self.deauth_count = ctk.CTkEntry(deauth_row, width=60)
        self.deauth_count.insert(0, "5")
        self.deauth_count.pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            deauth_row, text="Send deauth", width=120, command=self.send_deauth
        ).pack(side="left", padx=(0, 8))
        ctk.CTkButton(
            deauth_row, text="Probe handshake", width=140, command=self.probe
        ).pack(side="left")

        self.cap_path_label = ctk.CTkLabel(
            self, text="Capture file: —", text_color="gray70", wraplength=640, justify="left"
        )
        self.cap_path_label.pack(anchor="w", pady=(12, 8))

        nav = ctk.CTkFrame(self, fg_color="transparent")
        nav.pack(fill="x", pady=(16, 0))
        ctk.CTkButton(nav, text="← Back", width=100, command=lambda: app.goto_step(3)).pack(
            side="left"
        )
        self.btn_crack = ctk.CTkButton(
            nav, text="Crack →", width=120, command=self.goto_crack, state="disabled"
        )
        self.btn_crack.pack(side="right")

    def on_show(self) -> None:
        ap = self.app.session.selected_ap
        client = self.app.session.selected_client
        mon = self.app.session.monitor_interface
        if ap:
            client_txt = client.station_mac if client else "(all / broadcast)"
            self.summary.configure(
                text=(
                    f"Monitor: {mon}\n"
                    f"AP: {ap.essid or '(hidden)'} [{ap.bssid}] CH {ap.channel}\n"
                    f"Client: {client_txt}"
                )
            )
        self._update_handshake_ui()
        if self.app.session.capture_cap_path:
            self.cap_path_label.configure(text=f"Capture file: {self.app.session.capture_cap_path}")

    def start_capture(self) -> None:
        try:
            path = self.app.service.start_capture(
                on_line=lambda line: self.app.log(line),
                on_done=lambda code: self.ui(self._capture_done, code),
                on_handshake=lambda: self.ui(self._on_handshake),
            )
        except Exception as exc:
            self.app.log(str(exc))
            return
        self.cap_path_label.configure(text=f"Capture file: {path}")
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.app.set_status("Capturing…")
        self._schedule_poll()

    def stop_capture(self) -> None:
        self.app.service.stop_capture()
        self._cancel_poll()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.app.service.probe_handshake()
        self._update_handshake_ui()

    def _capture_done(self, code: int) -> None:
        self._cancel_poll()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        if self.app.session.handshake_ready:
            self.app.set_status("Handshake captured — capture stopped")
        else:
            self.app.set_status(f"Capture exited ({code})")
        self._update_handshake_ui()

    def _on_handshake(self) -> None:
        self._update_handshake_ui()
        self.app.set_status("Handshake captured — stopping capture…")
        self.app.log("Handshake ready; capture will stop automatically.")

    def send_deauth(self) -> None:
        try:
            count = int(self.deauth_count.get().strip() or "5")
        except ValueError:
            count = 5
        if not self.app.service.capturing:
            self.app.log("Start capture before sending deauth (recommended).")
        try:
            self.app.service.deauth(
                count=count,
                on_done=lambda code: self.app.log(f"Deauth finished ({code})"),
            )
        except Exception as exc:
            self.app.log(str(exc))

    def probe(self) -> None:
        ready = self.app.service.probe_handshake()
        self._update_handshake_ui()
        if not ready:
            self.app.log("No handshake found in capture yet.")

    def _update_handshake_ui(self) -> None:
        if self.app.session.handshake_ready:
            self.hs_badge.configure(text="Handshake: READY", text_color="#3cb371")
            self.btn_crack.configure(state="normal")
        else:
            self.hs_badge.configure(text="Handshake: waiting", text_color="#c9a227")
            # Allow proceed anyway if user has a cap (probe may lag)
            if self.app.session.capture_cap_path and self.app.session.capture_cap_path.exists():
                self.btn_crack.configure(state="normal")
            else:
                self.btn_crack.configure(state="disabled")

    def _schedule_poll(self) -> None:
        self._cancel_poll()
        self._poll_id = self.after(2000, self._poll)

    def _cancel_poll(self) -> None:
        if self._poll_id is not None:
            try:
                self.after_cancel(self._poll_id)
            except Exception:
                pass
            self._poll_id = None

    def _poll(self) -> None:
        if not self.app.session.handshake_ready:
            if self.app.service.probe_handshake(auto_stop=True):
                self._on_handshake()
        else:
            self._update_handshake_ui()
        if self.app.service.capturing:
            self._poll_id = self.after(2000, self._poll)
        else:
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
            self._update_handshake_ui()

    def goto_crack(self) -> None:
        if self.app.service.capturing:
            self.app.service.stop_capture()
            self._cancel_poll()
            self.btn_start.configure(state="normal")
            self.btn_stop.configure(state="disabled")
        if not self.app.session.handshake_ready:
            self.app.service.probe_handshake()
        if not self.app.session.handshake_ready:
            self.app.log("Warning: handshake not confirmed — cracking may fail.")
        self.app.goto_step(5)
