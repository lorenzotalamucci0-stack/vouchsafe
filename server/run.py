"""Launch the Vouchsafe demo on the first free port (8000, else OS-assigned).

  python run.py            # picks 8000 if free, otherwise the next free port
  PORT=9000 python run.py  # force a port

Prints the exact URL to open. Sets AP_BASE_URL so status URLs are self-consistent.
"""

from __future__ import annotations

import os
import socket


def _free_port(preferred: int) -> int:
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("::", preferred))
            return preferred
        except OSError:
            pass
    with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
        s.bind(("::", 0))
        return s.getsockname()[1]


def main() -> None:
    port = int(os.environ.get("PORT", "0")) or _free_port(8000)
    os.environ["AP_BASE_URL"] = f"http://localhost:{port}"
    print(f"\n  Vouchsafe demo →  http://localhost:{port}\n", flush=True)
    import uvicorn

    uvicorn.run("app:app", host="::", port=port, log_level="warning")


if __name__ == "__main__":
    main()
