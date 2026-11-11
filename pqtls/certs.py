"""Generate self-signed server credentials for each signature algorithm under test."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from pathlib import Path

from .openssl import OpenSSL

# Arguments for `openssl req -x509`. ML-DSA parameter sets are FIPS 204;
# the classical ones are the usual baselines for a TLS server certificate.
SIG_ALGS: dict[str, tuple[str, ...]] = {
    "ecdsa-p256": ("-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256"),
    "ed25519": ("-newkey", "ed25519"),
    "rsa-2048": ("-newkey", "rsa:2048"),
    "mldsa44": ("-newkey", "mldsa44"),
    "mldsa65": ("-newkey", "mldsa65"),
    "mldsa87": ("-newkey", "mldsa87"),
}


@dataclass(frozen=True)
class Credential:
    alg: str
    cert: Path
    key: Path
    cert_der_len: int


def pem_der_len(pem: str) -> int:
    """Length in bytes of the DER encoding inside the first PEM block."""
    m = re.search(r"-----BEGIN [^-]+-----(.*?)-----END [^-]+-----", pem, re.S)
    if not m:
        raise ValueError("no PEM block found")
    return len(base64.b64decode("".join(m.group(1).split())))


async def make_credential(openssl: OpenSSL, alg: str, workdir: Path) -> Credential:
    """Create a key and a self-signed certificate for CN=localhost in `workdir`."""
    if alg not in SIG_ALGS:
        raise ValueError(f"unknown signature algorithm {alg!r}; choose from {sorted(SIG_ALGS)}")
    cert, key = workdir / f"{alg}.crt", workdir / f"{alg}.key"
    await openssl.run(
        "req", "-x509", *SIG_ALGS[alg],
        "-keyout", key, "-out", cert, "-nodes",
        "-subj", "/CN=localhost", "-days", "1",
    )
    return Credential(alg, cert, key, pem_der_len(cert.read_text()))
