"""Minimal stdio MCP server that runs Nuclei via the docker-compose.yml next to this file."""
import json
import os
import subprocess
import time
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

COMPOSE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docker-compose.yml")
MAX_OUTPUT = 60_000
AUDIT_LOG = os.path.join(os.path.dirname(COMPOSE_FILE), "scans.log.jsonl")
AUDIT_MAX_BYTES = 5 * 1024 * 1024  # rotate at 5 MiB, keep scans.log.jsonl.1 .. .5
AUDIT_BACKUPS = 5

mcp = FastMCP("nuclei")


def _compose(*args: str, timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, *args],
        capture_output=True, text=True, timeout=timeout,
    )


def _rotate_audit_log() -> None:
    """scans.log.jsonl -> .1 -> .2 ... -> .N (oldest dropped) once it exceeds AUDIT_MAX_BYTES."""
    if not os.path.exists(AUDIT_LOG) or os.path.getsize(AUDIT_LOG) < AUDIT_MAX_BYTES:
        return
    for i in range(AUDIT_BACKUPS - 1, 0, -1):
        if os.path.exists(f"{AUDIT_LOG}.{i}"):
            os.replace(f"{AUDIT_LOG}.{i}", f"{AUDIT_LOG}.{i + 1}")
    os.replace(AUDIT_LOG, f"{AUDIT_LOG}.1")


def _audit(args: list[str], started: float, rc: int | None, out: str) -> None:
    """Append one JSON line per run to scans.log.jsonl and mirror it to `docker logs nuclei`."""
    findings = [ln for ln in out.splitlines() if ln.startswith("{")]
    entry = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "args": args,
        "exit": rc,
        "seconds": round(time.time() - started, 1),
        "findings": len(findings),
    }
    line = json.dumps(entry)
    try:
        _rotate_audit_log()
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps({**entry, "results": findings}) + "\n")
        subprocess.run(
            ["docker", "compose", "-f", COMPOSE_FILE, "exec", "-T", "nuclei",
             "sh", "-c", "cat > /proc/1/fd/1"],
            input=line + "\n", text=True, capture_output=True, timeout=15,
        )
    except Exception:
        pass  # logging must never break a scan


def _nuclei(args: list[str], timeout: int) -> str:
    started = time.time()
    try:
        _compose("up", "-d", "--quiet-pull", timeout=120)  # no-op if already running
        p = _compose("exec", "-T", "nuclei", "nuclei", *args, timeout=timeout)
    except subprocess.TimeoutExpired:
        _audit(args, started, None, "")
        return f"nuclei timed out after {timeout}s"
    out = p.stdout.strip() or p.stderr.strip()[-4000:]
    _audit(args, started, p.returncode, p.stdout)
    if p.returncode != 0:
        out += f"\n[exit {p.returncode}]"
    return out[:MAX_OUTPUT] or "(no findings)"


@mcp.tool()
def nuclei_scan(
    target: str,
    tags: str = "",
    severity: str = "",
    templates: str = "",
    rate_limit: int = 50,
    timeout_seconds: int = 600,
) -> str:
    """Run a Nuclei scan against a target URL/host you are authorized to test.

    tags: comma-separated template tags (e.g. "cve,exposure"). severity: comma-separated
    (info,low,medium,high,critical). templates: template path/dir inside the container
    (e.g. "http/cves/2024/"). From the container, the Mac host is host.docker.internal.
    Returns JSONL findings.
    """
    args = ["-u", target, "-jsonl", "-silent", "-nc", "-omit-raw", "-rl", str(rate_limit)]
    if tags:
        args += ["-tags", tags]
    if severity:
        args += ["-severity", severity]
    if templates:
        args += ["-t", templates]
    return _nuclei(args, timeout_seconds)


@mcp.tool()
def nuclei_update_templates() -> str:
    """Download/update the Nuclei template library into the persistent volume."""
    return _nuclei(["-update-templates", "-nc"], 600)


@mcp.tool()
def nuclei_version() -> str:
    """Show the Nuclei and template versions."""
    return _nuclei(["-version", "-nc"], 60)


if __name__ == "__main__":
    mcp.run()
