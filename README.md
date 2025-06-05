# ssldumpx
#### `ssldumpx` is a fast and lightweight tool written in Go for extracting domains and subdomains from SSL/TLS certificates. 
- It connects to a list of IPs or hostnames, retrieves their certificates, and prints out Common Names (CN) and Subject Alternative Names (SAN) — including wildcard domains (e.g., *.example.com).

---
🟢 Installation
- Make sure you have `Go 1.18` or higher installed.

- To install the latest version of ssldumpx, run:
`go install github.com/0xrootface/ssldumpx@latest`

This will download, build, and install the `ssldumpx` binary to your `$GOPATH/bin` or `$HOME/go/bin` directory.
**Make sure this directory is in your system PATH so you can run ssldumpx from anywhere.**

---

✅ Features:
- Extracts domains and subdomains from SSL certificates
- Supports both Subject CN and SAN fields
- Optional filters: silent output, unique entries only
- JSON output support
- Highly concurrent (default 100 threads)
- Input from file, stdin, or arguments
- Marks wildcard domains (e.g., *.example.com (wildcard))

---
🛠️ Example usage:
`cat ips.txt | ./ssldumpx -silent -uniq`

or

`echo 1.1.1.1/19 | mapcidr -silent | ssldumpx -all -silent -threads 500 `

- install mapcidr: `go install -v github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest`

---
🧪 Sample output:
- `*.example.com (wildcard)`
- `example.com`
- `login.example.org`
- 
---
Perfect for recon, asset discovery, bug bounty, and SSL intelligence.

