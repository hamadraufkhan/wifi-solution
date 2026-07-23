"""Subprocess runner with line streaming and process-group cancel."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from typing import Optional


OnLine = Callable[[str], None]
OnDone = Callable[[int], None]


class ProcessRunner:
    """Run an external command, stream output, and support killpg cancel."""

    def __init__(self) -> None:
        self._proc: Optional[subprocess.Popen[str]] = None
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    @property
    def running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def start(
        self,
        cmd: list[str],
        *,
        on_line: Optional[OnLine] = None,
        on_done: Optional[OnDone] = None,
        env: Optional[dict[str, str]] = None,
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self.stop()

        popen_kwargs: dict = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.STDOUT,
            "text": True,
            "bufsize": 1,
            "cwd": cwd,
            "env": env,
        }
        if os.name == "posix":
            popen_kwargs["preexec_fn"] = os.setsid

        proc = subprocess.Popen(cmd, **popen_kwargs)

        with self._lock:
            self._proc = proc

        def _reader() -> None:
            assert proc.stdout is not None
            try:
                for line in proc.stdout:
                    if on_line:
                        on_line(line.rstrip("\n"))
            except Exception:
                pass
            code = proc.wait()
            with self._lock:
                if self._proc is proc:
                    self._proc = None
            if on_done:
                on_done(code)

        self._thread = threading.Thread(target=_reader, daemon=True)
        self._thread.start()

        if timeout is not None and timeout > 0:
            def _watchdog() -> None:
                time.sleep(timeout)
                with self._lock:
                    still = self._proc is proc and proc.poll() is None
                if still:
                    if on_line:
                        on_line(f"(timeout after {timeout:.0f}s — stopping)")
                    self.stop(force=True)

            threading.Thread(target=_watchdog, daemon=True).start()

    def run_capture(
        self,
        cmd: list[str],
        *,
        timeout: Optional[float] = 60,
        env: Optional[dict[str, str]] = None,
    ) -> tuple[int, str]:
        """Run a short command and return (exit_code, combined_output)."""
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env,
            )
            out = (completed.stdout or "") + (completed.stderr or "")
            return completed.returncode, out
        except FileNotFoundError:
            return 127, f"Command not found: {cmd[0]}"
        except subprocess.TimeoutExpired as exc:
            # Ensure child is dead (run() should kill, but be explicit)
            try:
                if exc.process is not None:
                    exc.process.kill()
                    exc.process.wait(timeout=3)
            except Exception:
                pass
            out = ""
            if exc.stdout:
                out += exc.stdout if isinstance(exc.stdout, str) else exc.stdout.decode(
                    errors="replace"
                )
            if exc.stderr:
                out += exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode(
                    errors="replace"
                )
            return 124, out or f"Command timed out after {timeout}s: {' '.join(cmd)}"

    def stop(self, *, force: bool = False) -> None:
        with self._lock:
            proc = self._proc
            self._proc = None

        if proc is None:
            return

        try:
            if os.name == "posix" and proc.pid:
                sig = signal.SIGKILL if force else signal.SIGTERM
                try:
                    os.killpg(os.getpgid(proc.pid), sig)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    proc.terminate()
            else:
                if force:
                    proc.kill()
                else:
                    proc.terminate()
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
