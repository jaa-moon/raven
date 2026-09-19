# Methodology: Network & Service Security Assessment

## 1. When to Use
Activate this methodology when the target is an IP address, CIDR block, domain host, daemon, or network service (`host:port`).

## 2. Key Hypotheses
- **H-NET-01**: Insecure or cleartext management services exposed (Telnet port 23, FTP port 21).
- **H-NET-02**: In-memory datastores or databases exposed without network authentication (Redis port 6379, Memcached port 11211, MongoDB port 27017).
- **H-NET-03**: Verbose service banners leaking exact kernel, daemon, or framework versions.
- **H-NET-04**: Unauthenticated access to database listener ports (MySQL port 3306, PostgreSQL port 5432).
- **H-NET-05**: Insecure transport protocols without TLS or with self-signed/expired certificates.

## 3. Recommended Tools
- `port_scan`: Concurrent TCP port discovery on target host.
- `banner_grab`: TCP service greeting and banner extraction.
- `protocol_probe`: Protocol handshakes (Redis PING, MySQL 10, Memcached stats, SMTP EHLO).
- `default_creds_test`: Testing factory or unauthenticated access modes.

## 4. Evidence Criteria
- **Open Port**: Verified TCP connection handshake (`SYN-ACK` / connected socket).
- **Service Banner**: Verifiable raw bytes and text from the daemon handshake.
- **Unauthenticated Access**: Direct protocol response without credentials (e.g. `+PONG` or `VERSION 1.x`).
- **PoC Format**: Working `nc`, `redis-cli`, or `curl` command with exact parameters (`cli_poc`).

## 5. Common False Positives
- Port forwarding proxies or honeypots accepting all connections.
- Firewalls dropping or delaying packets, leading to false open/filtered reporting.
- Banner deception (services intentionally returning false version strings).
