# DNS_scapy - DNS File Transfer Tool

A file transfer utility that transmits files covertly over DNS protocol using Scapy. File data is embedded in the Padding layer of DNS/UDP packets on port 53.

## How It Works

```
Server (Sender)                    DNS/UDP Port 53                  Client (Receiver)
─────────────────                 ─────────────────                ──────────────────
1. Read file                                                       1. Listen for packets
2. Compute SHA-256 hash                                            2. Receive metadata
3. Split into 500-byte chunks                                      3. Receive all chunks
4. Send metadata packet ──────────> [count||hash] ──────────────> 4. Reassemble file
5. Send chunk packets ────────────> [chunk data] ───────────────> 5. Verify hash
                                                                   6. Save file
```

### Protocol

- **Transport:** UDP port 53 (DNS)
- **Payload location:** DNS Padding layer
- **Metadata format:** `chunk_count||sha256_hash`
- **Chunk size:** 500 bytes (configurable in `config.py`)
- **Integrity:** SHA-256 hash verification

## Requirements

- Python 3.6+
- Root/sudo privileges (required for raw packet access)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Sender (server.py)

```bash
sudo python3 server.py
```

You will be prompted for:
- Destination IP (receiver's IP)
- Your IP (sender's IP)
- File path to send

### Receiver (client.py)

```bash
sudo python3 client.py
```

You will be prompted for:
- Sender IP (who is sending the file)
- Your local IP (receiver's IP)
- Output filename (after successful transfer)

### Configuration

Edit `config.py` to adjust:

| Setting | Default | Description |
|---------|---------|-------------|
| `CHUNK_SIZE` | 500 | Bytes per packet |
| `DNS_PORT` | 53 | Target port |
| `HASH_ALGORITHM` | sha256 | Integrity hash |
| `MAX_RETRIES` | 5 | Client retry attempts |
| `SNIFF_TIMEOUT` | 30 | Seconds to wait per sniff |

## Project Structure

```
DNS_scapy/
├── server.py          # File sender
├── client.py          # File receiver
├── config.py          # Shared configuration
├── requirements.txt   # Python dependencies
├── .gitignore
└── README.md
```

## Disclaimer

This tool is intended for educational purposes, authorized security testing, and controlled lab environments only.
