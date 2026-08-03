# DNS_scapy

Two covert-channel file transfer experiments:

1. **`client.py` / `server.py`** — file transfer tunneled inside DNS/UDP packet padding, using `scapy`.
2. **`web/` — BeamDrop** — file transfer over *light*: one device displays an animated sequence of QR codes, another device's camera captures and reconstructs the file. No WiFi, Bluetooth, or network connection between the two devices during the transfer itself.

## BeamDrop (`web/`)

Sends a file by re-encoding it as a fountain code (LT / Luby Transform) and rendering
each encoded symbol as a QR frame. The receiver's camera scans frames in any order,
tolerates dropped/blurred frames, and can join a transfer already in progress — it
just needs to see a few more distinct frames than the file has blocks.

### Run it locally

```bash
python3 -m http.server 8000 --directory web
# open http://localhost:8000/send.html and http://localhost:8000/receive.html
```

This works fine for the **sender** in any browser, and for the **receiver** in any
desktop browser. It will **not** work for the receiver on an iPhone, because iOS
Safari blocks camera access (`getUserMedia`) on insecure origins.

### Testing the receiver on a real iPhone

iOS Safari requires HTTPS (or `localhost`) for camera access. Use the bundled
self-signed HTTPS server to test over your local WiFi:

```bash
python3 tools/serve_https.py 8443
```

It prints your LAN IP. On the iPhone (same WiFi network), open Safari to:

```
https://<your-machine's-LAN-IP>:8443/receive.html
```

Accept the self-signed certificate warning once, then tap **הפעל מצלמה** (Start
camera) and point it at the sender's screen (`send.html`, open on a laptop).

### Architecture

```
web/js/prng.js        seeded PRNG (mulberry32) — sender/receiver derive identical randomness from a shared seed
web/js/soliton.js      Robust Soliton Distribution + degree/index sampling for LT codes
web/js/fountain.js     FountainEncoder / FountainDecoder (peeling decoder)
web/js/framing.js      binary frame format (metadata frame + data frame) sent inside each QR code
web/js/browser-utils.js base64, SHA-256, formatting helpers (browser-only)
web/js/send.js         file -> blocks -> fountain-encoded QR loop
web/js/receive.js      camera -> jsQR -> fountain decode -> verified download
web/vendor/            vendored qrcode (MIT) + jsQR (Apache-2.0) — no CDN dependency
tools/serve_https.py   local self-signed HTTPS server for iPhone camera testing
```

`prng.js`, `soliton.js`, `fountain.js`, and `framing.js` have no DOM dependencies,
so they're covered by a Node test suite (the actual encode/decode risk, not the UI):

```bash
npm test
```

Tests cover: exact round-trip reconstruction, resilience to 30% frame loss plus
out-of-order/duplicate delivery, and a receiver joining a transfer already in progress.

### Known scope / not included

This is a working demo of the transfer mechanism, not a multi-tenant hosted
product — there's intentionally no auth, billing, or account system. If you want
this deployed as a hosted service (custom domain + real TLS cert instead of the
local self-signed one, analytics, etc.), that's a separate scope to plan.

## DNS tunnel (`client.py` / `server.py`)

`server.py` reads a file, hashes it (MD5), splits it into 500-byte chunks, and
sends each chunk inside the `Padding` layer of a crafted `IP/UDP/DNS` packet.
`client.py` sniffs for those packets, reassembles the chunks in order, and
verifies the hash before writing the output file.

```bash
# receiver
sudo python3 client.py
# sender (same LAN, or route between the two hosts)
sudo python3 server.py
```

Both scripts prompt for source/destination IPs and (for the sender) the file to
send. Requires `scapy` and typically root/`CAP_NET_RAW` for raw packet I/O.
