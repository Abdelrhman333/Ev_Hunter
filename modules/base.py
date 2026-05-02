"""
EVHunter — Module Base Class
All scanner modules inherit from ScannerModule for consistent
status reporting, timing, and result structure.
"""

import time
from abc import ABC, abstractmethod
from typing import Any

from rich.console import Console

console = Console()


class ScannerModule(ABC):
    """Base class for all EVHunter scanner modules."""

    name: str = "unknown"
    description: str = ""

    def __init__(self, timeout: int = 10, proxy: str = ""):
        self.timeout = timeout
        self.proxy   = proxy
        self._start  = 0.0

    def _status(self, msg: str, style: str = "cyan"):
        console.print(f"  [bold {style}]▸[/bold {style}] {msg}")

    def _ok(self, msg: str):
        console.print(f"  [bold green]  ✔[/bold green] {msg}")

    def _warn(self, msg: str):
        console.print(f"  [yellow]  ⚠[/yellow] {msg}")

    def _err(self, msg: str):
        console.print(f"  [red]  ✖[/red] {msg}")

    def _start_timer(self):
        self._start = time.time()

    def _elapsed(self) -> str:
        secs = time.time() - self._start
        return f"{secs:.1f}s"

    @abstractmethod
    def run(self, target: str, **kwargs) -> dict[str, Any]:
        """Execute the module and return a result dict."""
        ...

    @staticmethod
    def empty_result(**extra) -> dict:
        """Return a safe empty result."""
        return {"ok": False, "error": "not run", **extra}
