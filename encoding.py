"""Encoding strategies for DNS subdomain data exfiltration.

Two strategies available:
- hex_split: Split hex-encoded data across short labels with realistic prefixes
- wordlist: Map each byte to a short English word (lowest entropy)
"""

import math
from collections import Counter

# Prefixes that look like CDN/analytics URL components
HEX_PREFIXES = ["img", "css", "js", "api", "cdn", "v1", "v2", "s", "t", "p", "a", "b"]

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


def encode_hex_split(data, label_len=8):
    """Encode bytes as hex split across short DNS labels with prefixes.

    Each label: <prefix><hex_chars> (e.g., 'img3f2a1b')
    Returns list of label strings.
    """
    hex_str = data.hex()
    labels = []
    # Each label has a prefix (2-3 chars) + hex data
    # We want total label length around label_len
    prefix_idx = 0
    i = 0
    while i < len(hex_str):
        prefix = HEX_PREFIXES[prefix_idx % len(HEX_PREFIXES)]
        hex_chars = label_len - len(prefix)
        chunk = hex_str[i:i + hex_chars]
        labels.append(f"{prefix}{chunk}")
        i += hex_chars
        prefix_idx += 1
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
                # Check if we're past the alpha prefix
                if j > 0 and label[:j].isalpha():
                    hex_str += label[j:]
                    break
                elif j == 0:
                    hex_str += label
                    break
        else:
            # All alpha - skip (shouldn't happen with valid data)
            pass
    # Handle odd-length hex string (last chunk might be incomplete)
    if len(hex_str) % 2 != 0:
        hex_str = hex_str[:-1]
    return bytes.fromhex(hex_str)


def encode_wordlist(data):
    """Encode bytes using word lookup table.

    Each byte maps to one word. Returns list of word labels.
    """
    return [WORDLIST[b] for b in data]


def decode_wordlist(labels):
    """Decode word labels back to bytes."""
    return bytes([WORD_TO_BYTE[word] for word in labels])


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
