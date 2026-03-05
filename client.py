#!/usr/bin/env python3
"""DNS File Transfer - Client (Receiver)

Receives a file transmitted over DNS protocol by sniffing DNS packets
and reassembling the file data from the Padding layer.
"""

import hashlib
import sys

from scapy.all import Padding, sniff

from config import DNS_PORT, HASH_ALGORITHM, METADATA_SEPARATOR, MAX_RETRIES, SNIFF_TIMEOUT


def build_filter(src_ip, dst_ip):
    """Build BPF filter string for DNS traffic between two IPs."""
    return f"src {src_ip} && dst {dst_ip} && port {DNS_PORT}"


def parse_metadata(raw_metadata):
    """Parse metadata string to extract chunk count and file hash.

    Expected format: chunk_count||hash
    """
    parts = raw_metadata.split(METADATA_SEPARATOR)
    if len(parts) != 2:
        raise ValueError(f"Invalid metadata format: {raw_metadata}")

    chunk_count = int(parts[0])
    file_hash = parts[1]
    return chunk_count, file_hash


def compute_hash(data):
    """Compute hash of data using the configured algorithm."""
    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update(data)
    return hasher.hexdigest()


def receive_file(src_ip, dst_ip):
    """Receive a file over DNS packets.

    1. Sniffs the first packet for metadata (chunk count + hash)
    2. Sniffs the remaining packets containing file chunks
    3. Reassembles the file and verifies integrity
    4. Returns the reassembled data on success
    """
    bpf_filter = build_filter(src_ip, dst_ip)
    print(f"Listening with filter: {bpf_filter}")

    for attempt in range(1, MAX_RETRIES + 1):
        # Sniff metadata packet
        print("Waiting for metadata packet...")
        metadata_pkts = sniff(filter=bpf_filter, count=1, timeout=SNIFF_TIMEOUT)

        if not metadata_pkts:
            print(f"Timeout waiting for metadata (attempt {attempt}/{MAX_RETRIES})")
            continue

        raw_metadata = metadata_pkts[0].getlayer(Padding).load.decode()
        chunk_count, original_hash = parse_metadata(raw_metadata)
        print(f"Expecting {chunk_count} chunks, hash: {original_hash}")

        # Sniff data packets
        print(f"Receiving {chunk_count} chunks...")
        data_pkts = sniff(filter=bpf_filter, count=chunk_count, timeout=SNIFF_TIMEOUT * chunk_count)

        if len(data_pkts) < chunk_count:
            print(f"Received only {len(data_pkts)}/{chunk_count} chunks (attempt {attempt}/{MAX_RETRIES})")
            continue

        # Reassemble file
        received_data = b""
        for pkt in data_pkts:
            received_data += pkt[Padding].load

        print("Reassembly complete. Verifying integrity...")

        # Verify hash
        received_hash = compute_hash(received_data)
        if received_hash == original_hash:
            print("Hash verification passed.")
            return received_data
        else:
            print(f"Hash mismatch (attempt {attempt}/{MAX_RETRIES})")
            print(f"  Expected: {original_hash}")
            print(f"  Received: {received_hash}")

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
    print(f"File saved as '{filename}' ({len(data)} bytes)")


if __name__ == "__main__":
    main()
