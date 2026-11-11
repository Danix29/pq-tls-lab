"""Handshake throughput with `openssl s_time`, with the client restricted to one group.

s_time has no -groups option, so the group is forced through an OpenSSL config file
(`system_default` section) passed in OPENSSL_CONF. The server is restricted to the same
group, so a misconfigured client fails instead of silently negotiating something else.
"""
from __future__ import annotations

import asyncio
import os
import re
from dataclasses import dataclass
from pathlib import Path

from .handshake import HOST, TLSServer
from .openssl import OpenSSL, OpenSSLError

_NEW_RE = re.compile(
    r"(\d+) connections in ([\d.]+)s; ([\d.]+) connections/user sec.*?\n"
    r"(\d+) connections in (\d+) real seconds",
    re.S,
)


@dataclass(frozen=True)
class Throughput:
    connections: int
    # s_time only reports whole real seconds, so wall time is measured around the process
    # (it includes process start-up, a few ms over a multi-second run).
    wall_seconds: float
    client_user_seconds: float

    @property
    def per_second(self) -> float:
        return self.connections / self.wall_seconds if self.wall_seconds else 0.0

    @property
    def client_cpu_ms_per_handshake(self) -> float:
        return 1000 * self.client_user_seconds / self.connections if self.connections else 0.0


def parse_s_time(text: str) -> tuple[int, float]:
    """Return (connections, client user CPU seconds) from `s_time -new` output."""
    m = _NEW_RE.search(text)
    if not m:
        raise OpenSSLError(f"unexpected s_time output:\n{text[-1000:]}")
    connections, user_s = int(m.group(1)), float(m.group(2))
    if connections == 0:
        raise OpenSSLError("s_time completed 0 handshakes")
    return connections, user_s


def client_conf(group: str) -> str:
    return (
        "openssl_conf = pqtls\n"
        "[pqtls]\nssl_conf = pqtls_ssl\n"
        "[pqtls_ssl]\nsystem_default = pqtls_default\n"
        f"[pqtls_default]\nMinProtocol = TLSv1.3\nGroups = {group}\n"
    )


async def throughput(openssl: OpenSSL, server: TLSServer, seconds: int, workdir: Path) -> Throughput:
    """Count full (non-resumed) handshakes against `server` during `seconds` seconds."""
    conf = workdir / f"client-{server.group}.cnf"
    conf.write_text(client_conf(server.group))
    env = dict(os.environ, OPENSSL_CONF=str(conf))
    loop = asyncio.get_running_loop()
    start = loop.time()
    out = await openssl.run(
        "s_time", "-connect", f"{HOST}:{server.port}", "-new", "-time", seconds,
        env=env, timeout=seconds + 60,
    )
    wall = loop.time() - start
    connections, user_s = parse_s_time(out)
    return Throughput(connections, wall, user_s)
