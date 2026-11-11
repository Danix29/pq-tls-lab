# Security

This is a measurement lab, not a TLS implementation. It drives the `openssl` command-line
tools on `127.0.0.1` with throwaway self-signed certificates that are deleted after each run.
Do not reuse its certificates, keys or configuration in production.

If you find a problem in the code of this repository (for example, the harness accidentally
measuring a different group than the one reported), please open an issue. For vulnerabilities
in OpenSSL itself, follow the [OpenSSL security policy](https://openssl-library.org/policies/general/security-policy/).
