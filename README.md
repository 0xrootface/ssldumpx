# ssldumpx
ssldumpx is a fast and lightweight tool written in Go for extracting domains and subdomains from SSL/TLS certificates.  It connects to a list of IPs or hostnames, retrieves their certificates, and prints out Common Names (CN) and Subject Alternative Names (SAN) — including wildcard domains (e.g., *.example.com).
