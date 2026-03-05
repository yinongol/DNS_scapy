#!/usr/bin/env python3
"""DNS File Transfer - Server (Sender)

Sends a file covertly over DNS protocol by embedding file data
in the Padding layer of DNS packets using Scapy.
"""

import hashlib
import sys

from scapy.all import IP, UDP, DNS, Padding, send

from config import CHUNK_SIZE, DNS_PORT, HASH_ALGORITHM, METADATA_SEPARATOR


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


def build_metadata(chunk_count, file_hash):
    """Build metadata string: chunk_count||hash."""
    return f"{chunk_count}{METADATA_SEPARATOR}{file_hash}"


def build_base_packet(src_ip, dst_ip):
    """Create the base DNS packet template."""
    return IP(src=src_ip, dst=dst_ip) / UDP(dport=DNS_PORT) / DNS() / Padding(load=b"")


def send_file(src_ip, dst_ip, filepath):
    """Send a file over DNS packets.

    1. Reads the file and computes its hash
    2. Splits the file into chunks
    3. Sends a metadata packet with chunk count and hash
    4. Sends each chunk as a separate DNS packet
    """
    file_data = read_file(filepath)
    file_hash = compute_hash(file_data)
    chunks = split_into_chunks(file_data)

    print(f"File: {filepath}")
    print(f"Size: {len(file_data)} bytes")
    print(f"Chunks: {len(chunks)}")
    print(f"Hash ({HASH_ALGORITHM}): {file_hash}")

    packet = build_base_packet(src_ip, dst_ip)

    # Send metadata packet first
    metadata = build_metadata(len(chunks), file_hash)
    packet.getlayer(Padding).load = metadata.encode()
    print(f"Sending metadata: {metadata}")
    send(packet, verbose=False)

    # Send file chunks
    for i, chunk in enumerate(chunks):
        packet.getlayer(Padding).load = chunk
        send(packet, verbose=False)
        print(f"\rSending chunk {i + 1}/{len(chunks)}", end="", flush=True)

    print(f"\nTransfer complete. Sent {len(chunks)} chunks.")


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
