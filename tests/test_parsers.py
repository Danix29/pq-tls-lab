"""Unit tests for the s_client / s_time output parsers (no OpenSSL needed)."""
import unittest

from pqtls.certs import pem_der_len
from pqtls.handshake import parse_s_client
from pqtls.latency import client_conf, parse_s_time
from pqtls.openssl import OpenSSLError, parse_version

# Trimmed from a real `openssl s_client -msg` run (OpenSSL 3.5.6, X25519MLKEM768 + ML-DSA-65).
S_CLIENT = """\
CONNECTED(0000016C)
>>> TLS 1.0, RecordHeader [length 0005]
>>> TLS 1.3, Handshake [length 0573], ClientHello
<<< TLS 1.3, Handshake [length 04ba], ServerHello
<<< TLS 1.3, ChangeCipherSpec [length 0001]
<<< TLS 1.3, Handshake [length 0006], EncryptedExtensions
<<< TLS 1.3, Handshake [length 1593], Certificate
<<< TLS 1.3, Handshake [length 0cf5], CertificateVerify
<<< TLS 1.3, Handshake [length 0034], Finished
>>> TLS 1.3, Handshake [length 0034], Finished
---
Peer signature type: mldsa65
Negotiated TLS1.3 group: X25519MLKEM768
---
SSL handshake has read 10207 bytes and written 1480 bytes
Verification error: self-signed certificate
---
New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
<<< TLS 1.3, Handshake [length 00e9], NewSessionTicket
"""

S_TIME = """\
Collecting connection statistics for 2 seconds
1564 connections in 0.42s; 3723.81 connections/user sec, bytes read 0
1564 connections in 3 real seconds, 0 bytes read per connection
"""


class ParseSClient(unittest.TestCase):
    def test_fields(self) -> None:
        r = parse_s_client(S_CLIENT)
        self.assertEqual(r.group, "X25519MLKEM768")
        self.assertEqual(r.peer_signature, "mldsa65")
        self.assertEqual((r.protocol, r.cipher), ("TLSv1.3", "TLS_AES_256_GCM_SHA384"))
        self.assertEqual((r.bytes_read, r.bytes_written), (10207, 1480))

    def test_message_lengths_are_hex_and_exclude_post_handshake(self) -> None:
        r = parse_s_client(S_CLIENT)
        self.assertEqual(r.sent, {"ClientHello": 0x573, "Finished": 0x34})
        self.assertEqual(r.received["Certificate"], 0x1593)
        self.assertEqual(r.received["CertificateVerify"], 0xCF5)
        self.assertNotIn("NewSessionTicket", r.received)

    def test_classical_group_from_temp_key(self) -> None:
        base = S_CLIENT.replace("Negotiated TLS1.3 group: X25519MLKEM768\n", "")
        r = parse_s_client(base + "Peer Temp Key: X25519, 253 bits\n")
        self.assertEqual(r.group, "X25519")
        r = parse_s_client(base + "Peer Temp Key: ECDH, prime256v1, 256 bits\n")
        self.assertEqual(r.group, "secp256r1")

    def test_repeated_message_raises(self) -> None:
        hrr = S_CLIENT.replace(
            "<<< TLS 1.3, Handshake [length 04ba], ServerHello\n",
            "<<< TLS 1.3, Handshake [length 04ba], ServerHello\n"
            ">>> TLS 1.3, Handshake [length 0573], ClientHello\n",
        )
        with self.assertRaises(OpenSSLError):
            parse_s_client(hrr)

    def test_failed_handshake_raises(self) -> None:
        with self.assertRaises(OpenSSLError):
            parse_s_client("CONNECTED(00000100)\nwrite:errno=10054\n")


class ParseSTime(unittest.TestCase):
    def test_counts(self) -> None:
        self.assertEqual(parse_s_time(S_TIME), (1564, 0.42))

    def test_zero_connections_raises(self) -> None:
        with self.assertRaises(OpenSSLError):
            parse_s_time(S_TIME.replace("1564", "0"))

    def test_client_conf_forces_group_and_tls13(self) -> None:
        conf = client_conf("X25519MLKEM768")
        self.assertIn("Groups = X25519MLKEM768", conf)
        self.assertIn("MinProtocol = TLSv1.3", conf)


class Misc(unittest.TestCase):
    def test_parse_version(self) -> None:
        self.assertEqual(parse_version("OpenSSL 3.5.6 7 Apr 2026 (Library: ...)"), (3, 5, 6))
        with self.assertRaises(OpenSSLError):
            parse_version("LibreSSL 3.3.6")

    def test_pem_der_len(self) -> None:
        pem = "-----BEGIN CERTIFICATE-----\nAAECAw==\n-----END CERTIFICATE-----\n"
        self.assertEqual(pem_der_len(pem), 4)


if __name__ == "__main__":
    unittest.main()
