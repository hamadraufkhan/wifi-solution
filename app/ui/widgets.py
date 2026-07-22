"""Shared UI helpers."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Any, Optional

import customtkinter as ctk


def make_treeview(
    parent: tk.Misc,
    columns: list[tuple[str, str, int]],
    *,
    height: int = 12,
) -> ttk.Treeview:
    """
    columns: list of (col_id, heading, width)
    """
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure(
        "App.Treeview",
        background="#1e1e1e",
        foreground="#e0e0e0",
        fieldbackground="#1e1e1e",
        borderwidth=0,
        rowheight=24,
    )
    style.configure(
        "App.Treeview.Heading",
        background="#2b2b2b",
        foreground="#ffffff",
        relief="flat",
    )
    style.map(
        "App.Treeview",
        background=[("selected", "#1f6aa5")],
        foreground=[("selected", "#ffffff")],
    )

    col_ids = [c[0] for c in columns]
    tree = ttk.Treeview(
        parent,
        columns=col_ids,
        show="headings",
        height=height,
        style="App.Treeview",
        selectmode="browse",
    )
    for col_id, heading, width in columns:
        tree.heading(col_id, text=heading)
        tree.column(col_id, width=width, anchor="w", stretch=True)

    return tree


def pack_tree_with_scroll(tree: ttk.Treeview, parent: tk.Misc) -> None:
    vsb = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=vsb.set)
    tree.pack(side="left", fill="both", expand=True)
    vsb.pack(side="right", fill="y")


class PageBase(ctk.CTkFrame):
    """Base class for wizard pages."""

    title = "Page"

    def __init__(self, master: Any, app: Any, **kwargs: Any) -> None:
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app = app

    def on_show(self) -> None:
        """Called when page becomes visible."""

    def ui(self, fn: Any, *args: Any, **kwargs: Any) -> None:
        """Schedule callback on the Tk UI thread."""
        self.after(0, lambda: fn(*args, **kwargs))
