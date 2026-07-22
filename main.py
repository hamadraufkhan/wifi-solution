#!/usr/bin/env python3
"""Aircrack-ng GUI wrapper — entry point."""

from __future__ import annotations

import sys


def main() -> int:
    try:
        import customtkinter  # noqa: F401
    except ImportError:
        print(
            "Missing dependency: customtkinter\n"
            "Install with: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 1

    from app.ui.main_window import MainWindow

    app = MainWindow()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
