"""A fake meteorcli root helper for the Go agent: answers on helper.sock and sends the work to the simulated device.

The Go agent never runs docker itself; it asks the root helper (``meteorcli helper``) over a Unix
socket, one JSON request per connection (``{"method", "params"}``), one JSON answer
(``{"ok", "result"|"error"}``). The contract suite cannot run the real helper (it needs root), so
this one plays it: each operation becomes the docker command the real helper would run, executed
by ``SimulatedDevice``. Scenarios assert on ``requests`` (what the agent asked) and on the device.
"""

from __future__ import annotations

import json
import os
import re
import socketserver
import threading
from pathlib import Path
from typing import Any

from harness.device import SimulatedDevice

INSPECT_TEMPLATE = (
    "{{.State.Running}}|{{.State.Status}}|{{.State.ExitCode}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}"
)
_LOADED = re.compile(r"Loaded image(?: ID)?:?\s*(\S+)", re.IGNORECASE)


class FakeHelper:
    def __init__(self, socket_path: Path, artifacts_dir: Path, device: SimulatedDevice) -> None:
        self.socket_path = socket_path
        self.artifacts_dir = artifacts_dir
        self.device = device
        self.requests: list[tuple[str, dict[str, Any]]] = []
        self._lock = threading.Lock()
        helper = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                line = self.rfile.readline()
                try:
                    request = json.loads(line)
                    answer = helper.answer(str(request.get("method")), request.get("params") or {})
                except (ValueError, KeyError, TypeError) as exc:
                    answer = {"ok": False, "error": {"code": "bad_request", "message": str(exc)}}
                self.wfile.write((json.dumps(answer) + "\n").encode())

        socket_path.parent.mkdir(parents=True, exist_ok=True)
        if socket_path.exists():
            socket_path.unlink()
        self._server = socketserver.ThreadingUnixStreamServer(str(socket_path), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, name="fake-helper", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    def ops(self) -> list[str]:
        with self._lock:
            return [op for op, _ in self.requests]

    def answer(self, op: str, params: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self.requests.append((op, params))
        docker = self.device.docker
        if op == "docker.load":
            result = docker(["docker", "load", "-i", str(self.artifacts_dir / params["artifact"])])
            match = _LOADED.search(result.stdout or "")
            if result.returncode != 0 or match is None:
                return _failed(result.stderr or "docker load failed")
            return {"ok": True, "result": {"image": match.group(1)}}
        if op == "docker.run":
            name = params["name"]
            docker(["docker", "rm", "-f", name])
            args = ["docker", "run", "-d", "--name", name]
            if params.get("restart"):
                args += ["--restart", params["restart"]]
            for port in params.get("ports") or []:
                args += ["-p", port]
            for key, value in (params.get("env") or {}).items():
                args += ["-e", f"{key}={value}"]
            args += [params["image"], *(params.get("command") or [])]
            result = docker(args)
            if result.returncode != 0:
                return _failed(result.stderr or "docker run failed")
            return {"ok": True, "result": {"started": True}}
        if op == "docker.inspect":
            result = docker(["docker", "inspect", "-f", INSPECT_TEMPLATE, params["name"]])
            if result.returncode != 0:
                return {"ok": True, "result": {"missing": True}}
            running, status, code, health = ((result.stdout or "").strip().split("|") + ["", "", "", ""])[:4]
            return {"ok": True, "result": {
                "missing": False, "running": running.lower() == "true", "status": status,
                "exit_code": int(code or 0), "health": health,
            }}
        return {"ok": False, "error": {"code": "unknown_method", "message": f"the fake helper has no {op}"}}


def _failed(message: str) -> dict[str, Any]:
    return {"ok": False, "error": {"code": "failed", "message": message.strip()}}
