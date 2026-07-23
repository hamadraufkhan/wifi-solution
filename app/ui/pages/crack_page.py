"""Step 6 — crack with wordlist."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional
from tkinter import filedialog

import customtkinter as ctk

from app.ui.widgets import PageBase


class CrackPage(PageBase):
    title = "6. Crack"

    def __init__(self, master: Any, app: Any) -> None:
        super().__init__(master, app)

        ctk.CTkLabel(
            self,
            text="Crack handshake",
            font=ctk.CTkFont(size=20, weight="bold"),
        ).pack(anchor="w", pady=(0, 8))

        ctk.CTkLabel(
            self,
            text="Choose a wordlist and run aircrack-ng against the captured handshake.",
            text_color="gray70",
            wraplength=640,
            justify="left",
        ).pack(anchor="w", pady=(0, 12))

        self.cap_label = ctk.CTkLabel(self, text="Capture: —", wraplength=640, justify="left")
        self.cap_label.pack(anchor="w", pady=(0, 4))
        self.ap_label = ctk.CTkLabel(self, text="BSSID: —")
        self.ap_label.pack(anchor="w", pady=(0, 12))

        wl_row = ctk.CTkFrame(self, fg_color="transparent")
        wl_row.pack(fill="x", pady=(0, 8))
        ctk.CTkButton(wl_row, text="Browse wordlist…", width=160, command=self.browse).pack(
            side="left", padx=(0, 8)
        )
        self.wl_label = ctk.CTkLabel(wl_row, text="No wordlist selected", text_color="gray70")
        self.wl_label.pack(side="left")

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(fill="x", pady=(8, 8))
        self.btn_start = ctk.CTkButton(
            btn_row, text="Start crack", width=140, command=self.start_crack
        )
        self.btn_start.pack(side="left", padx=(0, 8))
        self.btn_stop = ctk.CTkButton(
            btn_row,
            text="Stop",
            width=100,
            fg_color="#8B3A3A",
            hover_color="#6e2e2e",
            command=self.stop_crack,
            state="disabled",
        )
        self.btn_stop.pack(side="left")

        self.result_badge = ctk.CTkLabel(
            self,
            text="Result: —",
            font=ctk.CTkFont(size=18, weight="bold"),
        )
        self.result_badge.pack(anchor="w", pady=(16, 8))

        self.key_box = ctk.CTkEntry(self, placeholder_text="Cracked key appears here")
        self.key_box.pack(fill="x", pady=(0, 8))

        nav = ctk.CTkFrame(self, fg_color="transparent")
        nav.pack(fill="x", pady=(16, 0))
        ctk.CTkButton(nav, text="← Back", width=100, command=lambda: app.goto_step(5)).pack(
            side="left"
        )

    def on_show(self) -> None:
        cap = self.app.session.capture_cap_path
        ap = self.app.session.selected_ap
        self.cap_label.configure(text=f"Capture: {cap}" if cap else "Capture: —")
        if ap:
            self.ap_label.configure(
                text=f"BSSID: {ap.bssid}  |  ESSID: {ap.essid or '(hidden)'}"
            )
        wl = self.app.session.wordlist_path
        if wl:
            self.wl_label.configure(text=str(wl))
        if self.app.session.cracked_key:
            self._show_key(self.app.session.cracked_key)

    def browse(self) -> None:
        path = filedialog.askopenfilename(
            title="Select wordlist",
            filetypes=[
                ("Wordlists", "*.txt *.lst *.dic"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self.app.session.wordlist_path = Path(path)
            self.wl_label.configure(text=path)
            self.app.log(f"Wordlist: {path}")

    def start_crack(self) -> None:
        wl = self.app.session.wordlist_path
        if not wl:
            self.app.log("Select a wordlist first.")
            return
        self.result_badge.configure(text="Result: cracking…", text_color="#c9a227")
        self.key_box.delete(0, "end")
        try:
            self.app.service.start_crack(
                wl,
                on_line=lambda line: self.app.log(line),
                on_done=lambda code, key: self.ui(self._crack_done, code, key),
            )
        except Exception as exc:
            self.app.log(str(exc))
            return
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.app.set_status("Cracking…")

    def stop_crack(self) -> None:
        self.app.service.stop_crack()
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        self.result_badge.configure(text="Result: stopped", text_color="gray70")

    def _crack_done(self, code: int, key: Optional[str]) -> None:
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        if key:
            self._show_key(key)
            self.app.set_status(f"KEY FOUND: {key}")
        else:
            self.result_badge.configure(
                text="Result: key not found in wordlist",
                text_color="#c04040",
            )
            self.app.set_status("Crack finished — no key")

    def _show_key(self, key: str) -> None:
        self.result_badge.configure(text="Result: KEY FOUND", text_color="#3cb371")
        self.key_box.delete(0, "end")
        self.key_box.insert(0, key)
