"""End-to-end checks against a real OpenSSL >= 3.5. Skipped if none is available.

The expected sizes come from the standards, not from previous runs:
- ML-KEM-768 encapsulation key 1184 B, ciphertext 1088 B (FIPS 203, Table 3).
- ML-DSA signatures: 44 -> 2420 B, 65 -> 3309 B, 87 -> 4627 B (FIPS 204, Table 2).
- X25519MLKEM768 key share = ML-KEM part || X25519 part (draft-ietf-tls-ecdhe-mlkem).
"""
import asyncio
import tempfile
import unittest
from pathlib import Path

from pqtls.certs import make_credential
from pqtls.handshake import TLSServer, handshake
from pqtls.latency import throughput
from pqtls.openssl import OpenSSLError, find_openssl

try:
    OPENSSL = asyncio.run(find_openssl())
except OpenSSLError:
    OPENSSL = None

MLKEM768_EK, MLKEM768_CT = 1184, 1088
EC_POINT_FORMATS_EXT = 8
MLDSA_SIG = {"mldsa44": 2420, "mldsa65": 3309, "mldsa87": 4627}
# CertificateVerify = 4 B handshake header + 2 B scheme + 2 B length + signature.
CERT_VERIFY_OVERHEAD = 8


@unittest.skipIf(OPENSSL is None, "OpenSSL >= 3.5 not available")
class Handshake(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.workdir = Path(self._tmp.name)

    async def asyncTearDown(self) -> None:
        self._tmp.cleanup()

    async def _run(self, sig: str, group: str):
        cred = await make_credential(OPENSSL, sig, self.workdir)
        async with TLSServer(OPENSSL, cred, group) as server:
            return await handshake(OPENSSL, server)

    async def test_hybrid_key_share_sizes(self) -> None:
        classic = await self._run("ecdsa-p256", "X25519")
        hybrid = await self._run("ecdsa-p256", "X25519MLKEM768")
        self.assertEqual(hybrid.group, "X25519MLKEM768")
        # OpenSSL only sends ec_point_formats (4 B header + 4 B body) when a pure ECDHE group
        # is offered, so offering X25519MLKEM768 alone drops those 8 bytes (seen with -trace).
        self.assertEqual(
            hybrid.sent["ClientHello"] - classic.sent["ClientHello"],
            MLKEM768_EK - EC_POINT_FORMATS_EXT,
        )
        self.assertEqual(
            hybrid.received["ServerHello"] - classic.received["ServerHello"], MLKEM768_CT
        )

    async def test_mldsa_certificate_verify_size(self) -> None:
        for sig, sig_len in MLDSA_SIG.items():
            with self.subTest(sig=sig):
                r = await self._run(sig, "X25519MLKEM768")
                self.assertEqual(r.peer_signature, sig)
                self.assertEqual(r.received["CertificateVerify"], sig_len + CERT_VERIFY_OVERHEAD)

    async def test_s_time_is_forced_to_server_group(self) -> None:
        cred = await make_credential(OPENSSL, "ed25519", self.workdir)
        async with TLSServer(OPENSSL, cred, "X25519MLKEM768") as server:
            t = await throughput(OPENSSL, server, 1, self.workdir)
            self.assertGreater(t.connections, 0)
            # Negative control: a client limited to X25519 must not complete any handshake.
            server.group = "X25519"
            with self.assertRaises(OpenSSLError):
                await throughput(OPENSSL, server, 1, self.workdir)


if __name__ == "__main__":
    unittest.main()
