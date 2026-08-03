# Vendored third-party libraries

These files are bundled locally (rather than loaded from a CDN) so the demo
works with no internet access beyond the initial page load.

- **qrcode.min.js** — built from [`qrcode`](https://github.com/soldair/node-qrcode) v1.5.3, MIT License.
  Bundled from `lib/browser.js` with esbuild into a single `window.QRCode` global (`toCanvas`, `toDataURL`, `create`, `toString`).
- **jsQR.js** — [`jsqr`](https://github.com/cozmo/jsQR) v1.4.0, Apache-2.0 License. Unmodified UMD build, exposes `window.jsQR`.
