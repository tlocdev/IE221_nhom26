# Security notes

## SSRF controls (implemented)

For every URL hop (initial + each redirect):

1. Allow only `http` / `https`
2. Reject embedded credentials
3. Resolve DNS
4. Reject private / loopback / link-local / metadata / reserved addresses
5. IPv6: `::1`, `fc00::/7`, `fe80::/10`, plus mapped IPv4 checks

Additional crawl limits: connect/read timeouts, max redirects (3), max body (2 MB), HTML content-type preference.

## Residual risk: DNS rebinding

A hostname may resolve to a public IP during validation and later rebind to a private IP when the HTTP client connects. Fully mitigating this requires connecting to a pinned IP with TLS SNI / Host header tricks or isolating the scanner network.

**Documented future work:** run the scanner in an isolated container/network with firewall rules denying private ranges, cloud metadata endpoints, and internal DB networks.

## TLS findings

- Missing HTTPS → low severity finding only (many phishing sites have valid HTTPS).
- Hostname validation uses OS/OpenSSL SAN matching; UI wording is “certificate hostname mismatch”, not CN-centric.
