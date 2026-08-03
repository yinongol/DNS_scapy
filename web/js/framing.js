// Binary frame layout for one QR code's worth of data.
//
// All frames: [0]='Q' [1]='F' [2]=version [3]=kind [4..7]=transferId (u32 LE)
//
// kind=1 (metadata, re-broadcast periodically so a receiver can join mid-stream):
//   [8..11]=fileSize (u32)  [12..15]=blockSize (u32)  [16..19]=k (u32)
//   [20..51]=sha256 checksum (32 bytes)
//   [52..53]=filename length (u16)  [54..]=filename (utf8)
//
// kind=0 (data symbol): [8..11]=seed (u32)  [12..]=payload (blockSize bytes)

const MAGIC0 = 0x51; // 'Q'
const MAGIC1 = 0x46; // 'F'
const VERSION = 1;
export const KIND_DATA = 0;
export const KIND_META = 1;

export function encodeMetaFrame({ transferId, fileSize, blockSize, k, checksum, filename }) {
  const nameBytes = new TextEncoder().encode(filename);
  const buf = new ArrayBuffer(54 + nameBytes.length);
  const view = new DataView(buf);
  const bytes = new Uint8Array(buf);

  bytes[0] = MAGIC0;
  bytes[1] = MAGIC1;
  bytes[2] = VERSION;
  bytes[3] = KIND_META;
  view.setUint32(4, transferId, true);
  view.setUint32(8, fileSize, true);
  view.setUint32(12, blockSize, true);
  view.setUint32(16, k, true);
  bytes.set(checksum, 20);
  view.setUint16(52, nameBytes.length, true);
  bytes.set(nameBytes, 54);
  return bytes;
}

export function encodeDataFrame({ transferId, seed, payload }) {
  const buf = new ArrayBuffer(12 + payload.length);
  const view = new DataView(buf);
  const bytes = new Uint8Array(buf);

  bytes[0] = MAGIC0;
  bytes[1] = MAGIC1;
  bytes[2] = VERSION;
  bytes[3] = KIND_DATA;
  view.setUint32(4, transferId, true);
  view.setUint32(8, seed, true);
  bytes.set(payload, 12);
  return bytes;
}

export function decodeFrame(bytes) {
  if (bytes.length < 8 || bytes[0] !== MAGIC0 || bytes[1] !== MAGIC1) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const kind = bytes[3];
  const transferId = view.getUint32(4, true);

  if (kind === KIND_META) {
    if (bytes.length < 54) return null;
    const fileSize = view.getUint32(8, true);
    const blockSize = view.getUint32(12, true);
    const k = view.getUint32(16, true);
    const checksum = bytes.slice(20, 52);
    const nameLen = view.getUint16(52, true);
    const filename = new TextDecoder().decode(bytes.slice(54, 54 + nameLen));
    return { kind: 'meta', transferId, fileSize, blockSize, k, checksum, filename };
  }

  if (kind === KIND_DATA) {
    const seed = view.getUint32(8, true);
    const payload = bytes.slice(12);
    return { kind: 'data', transferId, seed, payload };
  }

  return null;
}
