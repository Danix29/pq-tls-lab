"""Measure TLS 1.3 handshake size and throughput for each (signature, key-exchange group) pair.

Usage:
    python -m pqtls.bench [--groups G1,G2] [--sigs S1,S2] [--seconds N] [--runs N] [--out FILE]
"""
from __future__ import annotations

import argparse
import asyncio
import json
import platform
import statistics
import sys
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from .certs import SIG_ALGS, make_credential
from .handshake import HandshakeResult, TLSServer, handshake
from .latency import Throughput, throughput
from .openssl import OpenSSL, find_openssl

DEFAULT_GROUPS = ("X25519", "secp256r1", "X25519MLKEM768", "SecP256r1MLKEM768", "MLKEM768")
DEFAULT_SIGS = ("ecdsa-p256", "ed25519", "rsa-2048", "mldsa44", "mldsa65", "mldsa87")


@dataclass(frozen=True)
class Measurement:
    signature: str
    group: str
    cert_der_len: int
    handshake: HandshakeResult
    runs: list[Throughput]

    @property
    def median_per_second(self) -> float:
        return statistics.median(r.per_second for r in self.runs)

    @property
    def median_client_cpu_ms(self) -> float:
        return statistics.median(r.client_cpu_ms_per_handshake for r in self.runs)


async def measure(
    openssl: OpenSSL, sigs: list[str], groups: list[str], seconds: int, runs: int, workdir: Path
) -> list[Measurement]:
    results: list[Measurement] = []
    for sig in sigs:
        cred = await make_credential(openssl, sig, workdir)
        for group in groups:
            # One combination at a time: concurrent servers would compete for the same CPU.
            async with TLSServer(openssl, cred, group) as server:
                hs = await handshake(openssl, server)
                tps = [await throughput(openssl, server, seconds, workdir) for _ in range(runs)]
            m = Measurement(sig, group, cred.cert_der_len, hs, tps)
            results.append(m)
            print(f"  {sig:<11} {group:<18} {hs.bytes_written:>6} B -> {hs.bytes_read:>6} B <-"
                  f"  {m.median_per_second:8.1f} hs/s", file=sys.stderr)
    return results


def to_markdown(results: list[Measurement]) -> str:
    head = ("| Signature | Group | ClientHello | ServerHello | Certificate | CertificateVerify "
            "| Client sent | Server sent | Handshakes/s (median) | Client CPU ms/hs (median) |\n"
            "|---|---|--:|--:|--:|--:|--:|--:|--:|--:|\n")
    rows = []
    for m in results:
        h = m.handshake
        rows.append(
            f"| {m.signature} | {m.group} | {h.sent.get('ClientHello', 0)} "
            f"| {h.received.get('ServerHello', 0)} | {h.received.get('Certificate', 0)} "
            f"| {h.received.get('CertificateVerify', 0)} | {h.bytes_written} | {h.bytes_read} "
            f"| {m.median_per_second:.1f} | {m.median_client_cpu_ms:.3f} |"
        )
    return head + "\n".join(rows) + "\n"


def environment(openssl: OpenSSL, seconds: int, runs: int) -> dict[str, object]:
    return {
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "openssl": openssl.version,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "seconds_per_run": seconds,
        "runs": runs,
    }


def _csv(value: str, allowed: tuple[str, ...] | None = None) -> list[str]:
    items = [v.strip() for v in value.split(",") if v.strip()]
    if allowed is not None:
        if bad := [v for v in items if v not in allowed]:
            raise argparse.ArgumentTypeError(f"unknown: {', '.join(bad)}")
    return items


def _positive(value: str) -> int:
    n = int(value)
    if n <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return n


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m pqtls.bench", description=__doc__.splitlines()[0])
    ap.add_argument("--groups", type=_csv, default=list(DEFAULT_GROUPS))
    ap.add_argument("--sigs", type=lambda v: _csv(v, tuple(SIG_ALGS)), default=list(DEFAULT_SIGS))
    ap.add_argument("--seconds", type=_positive, default=3, help="duration of each s_time run")
    ap.add_argument("--runs", type=_positive, default=3, help="s_time runs per combination")
    ap.add_argument("--out", type=Path, help="write JSON results here")
    args = ap.parse_args(argv)
    return asyncio.run(_main(args))


async def _main(args: argparse.Namespace) -> int:
    openssl = await find_openssl()
    print(f"Using {openssl.path} ({openssl.version})", file=sys.stderr)
    with tempfile.TemporaryDirectory(prefix="pqtls-") as tmp:
        results = await measure(openssl, args.sigs, args.groups, args.seconds, args.runs, Path(tmp))
    print(to_markdown(results))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "environment": environment(openssl, args.seconds, args.runs),
            "results": [
                {**asdict(m), "median_per_second": m.median_per_second,
                 "median_client_cpu_ms": m.median_client_cpu_ms}
                for m in results
            ],
        }
        args.out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
