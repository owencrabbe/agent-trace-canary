"""Run one example after installing a process-start socket egress tripwire."""

from __future__ import annotations

import runpy
import socket
import sys
from typing import Any


def denied(*_args: Any, **_kwargs: Any) -> None:
    raise RuntimeError("network attempt blocked by integration-test tripwire")


socket.create_connection = denied  # type: ignore[assignment]
socket.socket.connect = denied  # type: ignore[assignment]
socket.socket.connect_ex = denied  # type: ignore[assignment]
socket.socket.sendto = denied  # type: ignore[assignment]
if hasattr(socket.socket, "sendmsg"):
    socket.socket.sendmsg = denied  # type: ignore[assignment]
socket.getaddrinfo = denied  # type: ignore[assignment]
socket.gethostbyname = denied  # type: ignore[assignment]
socket.gethostbyaddr = denied  # type: ignore[assignment]

if len(sys.argv) != 2:
    raise SystemExit("usage: network_guard_runner.py SCRIPT")
runpy.run_path(sys.argv[1], run_name="__main__")
