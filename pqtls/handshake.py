"""Run a local TLS 1.3 server and client with a fixed key-exchange group and parse the handshake."""
from __future__ import annotations

import asyncio
import re
import socket
from dataclasses import dataclass
from types import TracebackType

from .certs import Credential
from .openssl import OpenSSL, OpenSSLError

HOST = "127.0.0.1"

_MSG_RE = re.compile(r"^(>>>|<<<) TLS [\d.]+, Handshake \[length ([0-9a-f]+)\], (\w+)", re.M)
_GROUP_RE = re.compile(r"^Negotiated TLS1\.3 group: (\S+)", re.M)
# For classical (EC)DH groups OpenSSL 3.5 prints the temporary key instead, e.g.
# "Peer Temp Key: X25519, 253 bits" or "Peer Temp Key: ECDH, prime256v1, 256 bits".
_TEMP_KEY_RE = re.compile(r"^Peer Temp Key: (?:ECDH, )?([^,\s]+),", re.M)
_CURVE_TO_GROUP = {"prime256v1": "secp256r1"}
_SIG_RE = re.compile(r"^Peer signature type: (\S+)", re.M)
_BYTES_RE = re.compile(r"^SSL handshake has read (\d+) bytes and written (\d+) bytes", re.M)
_CIPHER_RE = re.compile(r"^New, (TLSv[\d.]+), Cipher is (\S+)", re.M)

# Messages sent after the handshake completes; they are not part of its cost.
_POST_HANDSHAKE = {"NewSessionTicket", "KeyUpdate"}


@dataclass(frozen=True)
class HandshakeResult:
    group: str
    peer_signature: str
    protocol: str
    cipher: str
    bytes_read: int
    bytes_written: int
    # Handshake message name -> body length in bytes, as reported by `s_client -msg`.
    sent: dict[str, int]
    received: dict[str, int]


def parse_s_client(text: str) -> HandshakeResult:
    """Parse the output of `openssl s_client -msg` for one TLS 1.3 connection."""
    def need(rx: re.Pattern[str], what: str) -> re.Match[str]:
        m = rx.search(text)
        if not m:
            raise OpenSSLError(f"s_client output has no {what}; handshake probably failed")
        return m

    sent: dict[str, int] = {}
    received: dict[str, int] = {}
    for direction, length, name in _MSG_RE.findall(text):
        if name in _POST_HANDSHAKE:
            continue
        target = sent if direction == ">>>" else received
        if name in target:
            # e.g. a HelloRetryRequest produces a second ClientHello; the per-message sizes
            # would then no longer describe a single 1-RTT handshake.
            raise OpenSSLError(f"handshake message {name} seen twice; not a plain 1-RTT handshake")
        target[name] = int(length, 16)
    read, written = need(_BYTES_RE, "byte counters").groups()
    protocol, cipher = need(_CIPHER_RE, "cipher line").groups()
    if m := _GROUP_RE.search(text):
        group = m.group(1)
    else:
        curve = need(_TEMP_KEY_RE, "negotiated group").group(1)
        group = _CURVE_TO_GROUP.get(curve, curve)
    return HandshakeResult(
        group=group,
        peer_signature=need(_SIG_RE, "peer signature type").group(1),
        protocol=protocol,
        cipher=cipher,
        bytes_read=int(read),
        bytes_written=int(written),
        sent=sent,
        received=received,
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, 0))
        return s.getsockname()[1]


class TLSServer:
    """`openssl s_server` restricted to TLS 1.3 and one group, serving the -www status page.

    -www mode is used because s_server otherwise reads stdin, and on Windows a closed
    stdin makes it shut down after the first connection.
    """

    def __init__(self, openssl: OpenSSL, cred: Credential, group: str) -> None:
        self.openssl, self.cred, self.group = openssl, cred, group
        self.port = _free_port()
        self._proc: asyncio.subprocess.Process | None = None

    async def __aenter__(self) -> TLSServer:
        self._proc = await asyncio.create_subprocess_exec(
            str(self.openssl.path), "s_server",
            "-accept", f"{HOST}:{self.port}",
            "-cert", str(self.cred.cert), "-key", str(self.cred.key),
            "-tls1_3", "-groups", self.group, "-www", "-quiet",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await self._wait_listening(timeout=10.0)
        return self

    async def _wait_listening(self, timeout: float) -> None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            assert self._proc is not None
            if self._proc.returncode is not None:
                raise OpenSSLError(f"s_server exited early with {self._proc.returncode}")
            try:
                _, writer = await asyncio.open_connection(HOST, self.port)
            except OSError:
                await asyncio.sleep(0.05)
                continue
            writer.close()
            await writer.wait_closed()
            return
        raise OpenSSLError(f"s_server did not listen on {HOST}:{self.port} within {timeout}s")

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._proc and self._proc.returncode is None:
            self._proc.kill()
            await self._proc.wait()


async def handshake(openssl: OpenSSL, server: TLSServer) -> HandshakeResult:
    """Do one TLS 1.3 handshake against `server` offering only its group, and check the result."""
    out = await openssl.run(
        "s_client", "-connect", f"{HOST}:{server.port}",
        "-tls1_3", "-groups", server.group, "-msg", "-no-interactive",
        timeout=30,
    )
    result = parse_s_client(out)
    if result.group != server.group:
        raise OpenSSLError(f"negotiated {result.group}, expected {server.group}")
    return result
