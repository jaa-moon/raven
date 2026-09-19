# Network service exposure checklist
Enumerate open ports, identify services by banner and protocol handshake, flag unauthenticated Redis, Memcached, MongoDB, Elasticsearch, databases reachable from untrusted networks, Telnet and FTP cleartext services.
Exposure is confirmed by re-probing the service; whether the exposure is intended needs operator review.

# Protocol security checklist
TLS versions and ciphers, cleartext protocols, anonymous access, default credentials, protocol version disclosure.
