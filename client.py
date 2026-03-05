#!/usr/bin/env python3
"""DNS File Transfer - Client (Receiver)

Sniffs DNS queries and decodes file data from subdomain labels.
Reassembles the file and verifies integrity with SHA-256.

Expected query format:
    <base32_data>.<seq_number>.<base_domain>
"""

import base64
import hashlib
import sys

from scapy.all import DNSQR, sniff

from config import (
    BASE_DOMAIN,
    DNS_PORT,
    HASH_ALGORITHM,
    MAX_RETRIES,
    METADATA_SEPARATOR,
    SNIFF_TIMEOUT,
)


def build_filter(src_ip, dst_ip):
    """Build BPF filter string for DNS traffic between two IPs."""
    return f"src {src_ip} && dst {dst_ip} && udp port {DNS_PORT}"


def decode_chunk(encoded):
    """Decode a base32-encoded DNS label back to bytes.

    Re-adds padding that was stripped for DNS compatibility.
    """
    encoded = encoded.upper()
    padding = (8 - len(encoded) % 8) % 8
    encoded += "=" * padding
    return base64.b32decode(encoded)


def parse_query_name(qname):
    """Extract encoded data and sequence number from a DNS query name.

    Format: <encoded_data>.<seq>.<base_domain>
    Returns: (encoded_data, sequence_number)
    """
    # Remove trailing dot if present (DNS FQDN)
    if qname.endswith("."):
        qname = qname[:-1]

    parts = qname.split(".")
    # parts: [encoded_data, seq, domain_parts...]
    encoded_data = parts[0]
    seq = int(parts[1])
    return encoded_data, seq


def parse_metadata(raw_metadata):
    """Parse metadata string to extract chunk count and file hash."""
    text = raw_metadata.decode()
    parts = text.split(METADATA_SEPARATOR)
    if len(parts) != 2:
        raise ValueError(f"Invalid metadata format: {text}")
    return int(parts[0]), parts[1]


def compute_hash(data):
    """Compute hash of data using the configured algorithm."""
    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update(data)
    return hasher.hexdigest()


def is_our_query(pkt):
    """Check if a packet is a DNS query targeting our base domain."""
    if not pkt.haslayer(DNSQR):
        return False
    qname = pkt[DNSQR].qname.decode()
    return qname.rstrip(".").endswith(BASE_DOMAIN)


def receive_file(src_ip, dst_ip):
    """Receive a file from DNS subdomain-encoded queries.

    1. Sniffs DNS queries matching our base domain
    2. Extracts sequence 0000 as metadata (chunk count + hash)
    3. Collects all data chunks by sequence number
    4. Reassembles and verifies integrity
    """
    bpf_filter = build_filter(src_ip, dst_ip)
    print(f"Listening: {bpf_filter}")
    print(f"Domain: {BASE_DOMAIN}")

    for attempt in range(1, MAX_RETRIES + 1):
        # Sniff metadata packet (seq 0000)
        print(f"\nWaiting for metadata... (attempt {attempt}/{MAX_RETRIES})")
        meta_pkts = sniff(
            filter=bpf_filter,
            lfilter=is_our_query,
            count=1,
            timeout=SNIFF_TIMEOUT,
        )

        if not meta_pkts:
            print("Timeout waiting for metadata.")
            continue

        qname = meta_pkts[0][DNSQR].qname.decode()
        encoded_meta, seq = parse_query_name(qname)

        if seq != 0:
            print(f"Expected metadata (seq 0), got seq {seq}. Retrying...")
            continue

        raw_meta = decode_chunk(encoded_meta)
        chunk_count, original_hash = parse_metadata(raw_meta)
        print(f"Expecting {chunk_count} chunks")
        print(f"Original hash: {original_hash}")

        # Sniff data packets
        print(f"Receiving chunks...")
        data_pkts = sniff(
            filter=bpf_filter,
            lfilter=is_our_query,
            count=chunk_count,
            timeout=SNIFF_TIMEOUT * 2,
        )

        if len(data_pkts) < chunk_count:
            print(f"Got {len(data_pkts)}/{chunk_count} chunks. Retrying...")
            continue

        # Sort by sequence number and reassemble
        chunks_by_seq = {}
        for pkt in data_pkts:
            qname = pkt[DNSQR].qname.decode()
            encoded, seq_num = parse_query_name(qname)
            chunks_by_seq[seq_num] = decode_chunk(encoded)

        received_data = b""
        for seq_num in sorted(chunks_by_seq.keys()):
            received_data += chunks_by_seq[seq_num]

        # Verify integrity
        received_hash = compute_hash(received_data)
        if received_hash == original_hash:
            print("Hash verification PASSED.")
            return received_data

        print(f"Hash mismatch!")
        print(f"  Expected: {original_hash}")
        print(f"  Got:      {received_hash}")

    print("Max retries exceeded. Transfer failed.")
    return None


def main():
    src_ip = input("Enter sender IP: ").strip()
    dst_ip = input("Enter your local IP: ").strip()

    if not src_ip or not dst_ip:
        print("Error: IP addresses cannot be empty.")
        sys.exit(1)

    data = receive_file(src_ip, dst_ip)

    if data is None:
        print("File transfer failed.")
        sys.exit(1)

    filename = input("Enter output filename: ").strip()
    with open(filename, "wb") as f:
        f.write(data)
    print(f"File saved: '{filename}' ({len(data)} bytes)")


if __name__ == "__main__":
    main()
