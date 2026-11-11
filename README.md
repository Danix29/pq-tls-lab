# pq-tls-lab

How much does a TLS 1.3 handshake grow, and how much slower does it get, when you move from
X25519 to the hybrid **X25519MLKEM768** key exchange and from ECDSA/Ed25519/RSA to **ML-DSA**
certificates?

This repository answers that with a small, reproducible harness around the OpenSSL 3.5
command-line tools, which support ML-KEM (FIPS 203) and ML-DSA (FIPS 204) natively.
It measures:

- **Bytes on the wire per handshake message** (ClientHello, ServerHello, Certificate,
  CertificateVerify) and the totals in each direction, from `openssl s_client -msg`.
- **Full-handshake throughput** on loopback with `openssl s_time -new`, plus the client's CPU
  time per handshake.

Status: early work in progress (v0.1 not yet released). See [Limitations](#limitations) before
quoting any number from here.

## Quick start

Requirements: Python 3.11+ (standard library only) and OpenSSL **3.5 or newer**.
The harness looks for `openssl` in `$PQTLS_OPENSSL`, then on `PATH`, then in a few usual
install locations (including the one bundled with Git for Windows), and refuses to run with
an older version.

```bash
python -m unittest -v                     # parser unit tests + end-to-end checks
python -m pqtls --out results/run.json    # full matrix: 6 signatures x 5 groups
python -m pqtls --sigs ecdsa-p256,mldsa65 --groups X25519,X25519MLKEM768 --seconds 1 --runs 1
```

## How it works

For every (signature algorithm, group) pair:

1. A self-signed `CN=localhost` certificate is generated with `openssl req -x509`.
2. `openssl s_server -tls1_3 -groups <group> -www` listens on a free loopback port.
3. One `openssl s_client -tls1_3 -groups <group> -msg` handshake records the size of every
   handshake message. The harness fails if the negotiated group is not the requested one.
4. `openssl s_time -new` counts full handshakes over a fixed time. `s_time` has no `-groups`
   option, so the client is pinned through an OpenSSL config file (`system_default`,
   `Groups = <group>`) in `OPENSSL_CONF`. Because the server also accepts only that group,
   a misconfigured client fails instead of measuring something else; the test suite checks
   this with a negative control. As a side effect, your own OpenSSL configuration is not
   loaded for these runs.

Pairs run one at a time so that servers do not compete for the CPU.

## What the tests check against the standards

The integration tests do not compare against previous runs; they compare against sizes fixed
by the specifications:

| Check | Expected | Source |
|---|---|---|
| ServerHello grows by the ML-KEM-768 ciphertext | +1088 B | FIPS 203, Table 3; RFC 10024 |
| ClientHello grows by the ML-KEM-768 encapsulation key | +1184 B, minus 8 B (see below) | FIPS 203, Table 3; RFC 10024 |
| CertificateVerify carries an ML-DSA signature | 2420 / 3309 / 4627 B + 8 B framing | FIPS 204, Table 2 |

The ClientHello difference is 1176 B rather than 1184 B because OpenSSL only sends the
`ec_point_formats` extension (8 B) when a pure ECDHE group is offered; the hybrid group alone
does not trigger it. This was confirmed with `s_client -trace`.

## Results

First full run: 11 Nov 2026, Windows 11 laptop (Intel, family 6 model 183), OpenSSL 3.5.6
from Git for Windows, Python 3.11.9, 3 runs of 3 s per pair. Raw data:
[`results/windows-openssl-3.5.6.json`](results/windows-openssl-3.5.6.json).
Sizes are handshake message lengths in bytes (including the 4-byte handshake header);
"Client sent" and "Server sent" are the TLS bytes in each direction until the handshake completes.

| Signature | Group | ClientHello | ServerHello | Certificate | CertificateVerify | Client sent | Server sent | Handshakes/s (median) | Client CPU ms/hs (median) |
|---|---|--:|--:|--:|--:|--:|--:|--:|--:|
| ecdsa-p256 | X25519 | 219 | 122 | 397 | 78 | 304 | 754 | 1267.2 | 0.236 |
| ecdsa-p256 | secp256r1 | 252 | 155 | 397 | 80 | 337 | 789 | 1248.0 | 0.260 |
| ecdsa-p256 | X25519MLKEM768 | 1395 | 1210 | 397 | 79 | 1480 | 1843 | 1178.0 | 0.325 |
| ecdsa-p256 | SecP256r1MLKEM768 | 1428 | 1243 | 397 | 78 | 1513 | 1875 | 845.8 | 0.419 |
| ecdsa-p256 | MLKEM768 | 1363 | 1178 | 397 | 79 | 1448 | 1811 | 1161.4 | 0.220 |
| ed25519 | X25519 | 219 | 122 | 333 | 72 | 304 | 684 | 1240.8 | 0.232 |
| ed25519 | secp256r1 | 252 | 155 | 333 | 72 | 337 | 717 | 1171.5 | 0.227 |
| ed25519 | X25519MLKEM768 | 1395 | 1210 | 333 | 72 | 1480 | 1772 | 1099.6 | 0.301 |
| ed25519 | SecP256r1MLKEM768 | 1428 | 1243 | 333 | 72 | 1513 | 1805 | 1003.5 | 0.294 |
| ed25519 | MLKEM768 | 1363 | 1178 | 333 | 72 | 1448 | 1740 | 1343.5 | 0.234 |
| rsa-2048 | X25519 | 219 | 122 | 794 | 264 | 304 | 1337 | 900.0 | 0.146 |
| rsa-2048 | secp256r1 | 252 | 155 | 794 | 264 | 337 | 1370 | 848.2 | 0.230 |
| rsa-2048 | X25519MLKEM768 | 1395 | 1210 | 794 | 264 | 1480 | 2425 | 558.8 | 0.383 |
| rsa-2048 | SecP256r1MLKEM768 | 1428 | 1243 | 794 | 264 | 1513 | 2458 | 658.7 | 0.362 |
| rsa-2048 | MLKEM768 | 1363 | 1178 | 794 | 264 | 1448 | 2393 | 738.0 | 0.236 |
| mldsa44 | X25519 | 219 | 122 | 3994 | 2428 | 304 | 6701 | 830.8 | 0.352 |
| mldsa44 | secp256r1 | 252 | 155 | 3994 | 2428 | 337 | 6734 | 810.2 | 0.369 |
| mldsa44 | X25519MLKEM768 | 1395 | 1210 | 3994 | 2428 | 1480 | 7789 | 789.2 | 0.340 |
| mldsa44 | SecP256r1MLKEM768 | 1428 | 1243 | 3994 | 2428 | 1513 | 7822 | 758.2 | 0.349 |
| mldsa44 | MLKEM768 | 1363 | 1178 | 3994 | 2428 | 1448 | 7757 | 846.5 | 0.289 |
| mldsa65 | X25519 | 219 | 122 | 5523 | 3317 | 304 | 9119 | 657.8 | 0.310 |
| mldsa65 | secp256r1 | 252 | 155 | 5523 | 3317 | 337 | 9152 | 646.0 | 0.365 |
| mldsa65 | X25519MLKEM768 | 1395 | 1210 | 5523 | 3317 | 1480 | 10207 | 625.0 | 0.391 |
| mldsa65 | SecP256r1MLKEM768 | 1428 | 1243 | 5523 | 3317 | 1513 | 10240 | 605.8 | 0.433 |
| mldsa65 | MLKEM768 | 1363 | 1178 | 5523 | 3317 | 1448 | 10175 | 657.8 | 0.404 |
| mldsa87 | X25519 | 219 | 122 | 7481 | 4635 | 304 | 12395 | 577.2 | 0.429 |
| mldsa87 | secp256r1 | 252 | 155 | 7481 | 4635 | 337 | 12428 | 638.0 | 0.415 |
| mldsa87 | X25519MLKEM768 | 1395 | 1210 | 7481 | 4635 | 1480 | 13483 | 615.2 | 0.398 |
| mldsa87 | SecP256r1MLKEM768 | 1428 | 1243 | 7481 | 4635 | 1513 | 13516 | 579.8 | 0.509 |
| mldsa87 | MLKEM768 | 1363 | 1178 | 7481 | 4635 | 1448 | 13451 | 636.0 | 0.389 |

What this run supports:

- **The key exchange cost is fixed and small in bytes.** Moving from X25519 to X25519MLKEM768
  adds 1176 B to the client's flight and 1088 B to the server's, whatever the certificate.
  These numbers are deterministic and match the standards (see the tests above).
- **Certificates dominate the size.** With a single self-signed ML-DSA-65 leaf the server sends
  9119 B with X25519 (10207 B with X25519MLKEM768), against 754 B for ECDSA P-256.
  Back-of-the-envelope, not measured: one ML-DSA-65 intermediate would add roughly another
  5.5 KB, bringing the server's flight above 14.6 KB, the 10-segment initial congestion window
  of RFC 6928 with a 1460-byte MSS. Whether that actually costs an extra round trip depends on
  the TCP stack and the network; checking it with packet captures is on the roadmap.
- **On loopback, the signature change costs more throughput than the key-exchange change.**
  Median full handshakes per second: ECDSA P-256 with X25519 1267, with X25519MLKEM768 1178
  (about -7 %), ML-DSA-65 with X25519MLKEM768 625 (about -51 %).

What it does not support: fine-grained comparisons. Run-to-run spread reaches 17 % in some
rows (for example Ed25519 with X25519MLKEM768: 978 to 1146 handshakes/s), so differences of
around 10 % or less are not meaningful in this run. The client-CPU column has the same problem
and should be read only as an order of magnitude.

## Limitations

- **Loopback, one machine.** Client and server share the same CPU and there is no network
  latency or packet loss, so throughput reflects CPU cost only. On a real network the extra
  bytes matter more (for example, when the server's first flight no longer fits in the TCP
  initial congestion window).
- **ECDSA sizes vary by a byte or two** between runs, because DER-encoded ECDSA signatures
  have variable length. ML-DSA, Ed25519 and RSA sizes are fixed.
- **Self-signed leaf only.** Real chains carry at least one intermediate certificate, so a
  real ML-DSA chain is larger than what is measured here.
- **Wall time includes process start-up.** `s_time` only reports whole seconds, so wall time
  is measured around the process. Over multi-second runs this adds a few milliseconds.
- **CPU time resolution.** The client CPU figure comes from `s_time` and inherits the OS timer
  resolution (about 15.6 ms on Windows), so treat small differences as noise.
- **Laptop measurements.** The published results come from a laptop with frequency scaling
  and background load. Compare rows within one run, not across machines.
- The CI checks that everything builds and runs; it does not make performance claims.

## References

- NIST, FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (Aug 2024).
  https://csrc.nist.gov/pubs/fips/203/final
- NIST, FIPS 204, *Module-Lattice-Based Digital Signature Standard* (Aug 2024).
  https://csrc.nist.gov/pubs/fips/204/final
- RFC 10024, *Post-Quantum Traditional (PQ/T) Hybrid Key Agreement Mechanisms for TLS 1.3*
  (formerly draft-ietf-tls-ecdhe-mlkem). https://datatracker.ietf.org/doc/rfc10024/
- draft-ietf-tls-mldsa, *Use of ML-DSA in TLS 1.3* (Internet-Draft).
  https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/
- RFC 8446, *The Transport Layer Security (TLS) Protocol Version 1.3*.
  https://www.rfc-editor.org/rfc/rfc8446
- OpenSSL 3.5 release notes (ML-KEM, ML-DSA, SLH-DSA; X25519MLKEM768 in the default key shares).
  https://github.com/openssl/openssl/blob/openssl-3.5/NEWS.md

## Roadmap

- Packet captures (pcap) of each handshake for inspection in Wireshark.
- Certificate chains with an intermediate CA.
- Latency under emulated network conditions (RTT, loss) in containers.
- A Rust client built on rustls to compare against OpenSSL.

## License

MIT, see [LICENSE](LICENSE).
