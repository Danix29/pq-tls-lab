"""Locate an OpenSSL binary with native post-quantum support and run it asynchronously."""
from __future__ import annotations

import asyncio
import os
import re
import shutil
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

# OpenSSL 3.5 is the first release with ML-KEM, ML-DSA, SLH-DSA and the
# X25519MLKEM768 hybrid group in the default provider.
MIN_VERSION = (3, 5, 0)

_EXTRA_CANDIDATES = (
    Path(r"C:\Program Files\Git\mingw64\bin\openssl.exe"),
    Path("/opt/homebrew/opt/openssl@3/bin/openssl"),
    Path("/usr/local/opt/openssl@3/bin/openssl"),
)


class OpenSSLError(RuntimeError):
    """An openssl command failed, timed out, or no suitable binary was found."""


def parse_version(banner: str) -> tuple[int, int, int]:
    """Parse the output of `openssl version`, e.g. 'OpenSSL 3.5.6 7 Apr 2026'."""
    m = re.match(r"OpenSSL (\d+)\.(\d+)\.(\d+)", banner.strip())
    if not m:
        raise OpenSSLError(f"unrecognised version banner: {banner!r}")
    major, minor, patch = (int(g) for g in m.groups())
    return major, minor, patch


@dataclass(frozen=True)
class OpenSSL:
    path: Path
    version: str

    async def run(
        self,
        *args: object,
        env: Mapping[str, str] | None = None,
        timeout: float = 60.0,
    ) -> str:
        """Run `openssl <args>` with stdin closed and return combined stdout/stderr."""
        proc = await asyncio.create_subprocess_exec(
            str(self.path),
            *(str(a) for a in args),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=dict(env) if env is not None else None,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise OpenSSLError(f"openssl {args[0]} timed out after {timeout}s") from None
        text = out.decode("utf-8", "replace")
        if proc.returncode != 0:
            raise OpenSSLError(f"openssl {args[0]} exited with {proc.returncode}:\n{text[-2000:]}")
        return text


async def _probe(path: Path) -> OpenSSL | None:
    try:
        banner = await OpenSSL(path, "").run("version", timeout=10)
        if parse_version(banner) >= MIN_VERSION:
            return OpenSSL(path, banner.strip())
    except (OSError, OpenSSLError):
        pass
    return None


async def find_openssl() -> OpenSSL:
    """Return the first OpenSSL >= 3.5 from $PQTLS_OPENSSL, PATH or well-known locations."""
    candidates: list[Path] = []
    if env_path := os.environ.get("PQTLS_OPENSSL"):
        candidates.append(Path(env_path))
    if on_path := shutil.which("openssl"):
        candidates.append(Path(on_path))
    candidates.extend(p for p in _EXTRA_CANDIDATES if p.exists())
    for path in candidates:
        if found := await _probe(path):
            return found
    tried = ", ".join(str(p) for p in candidates) or "none"
    raise OpenSSLError(
        "OpenSSL >= 3.5 not found (tried: %s). Set PQTLS_OPENSSL to its path." % tried
    )
