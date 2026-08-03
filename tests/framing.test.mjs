import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { encodeMetaFrame, encodeDataFrame, decodeFrame } from '../web/js/framing.js';

test('metadata frame round-trips through encode/decode', () => {
  const checksum = createHash('sha256').update('hello world').digest();
  const frame = encodeMetaFrame({
    transferId: 0xdeadbeef,
    fileSize: 123456,
    blockSize: 700,
    k: 176,
    checksum,
    filename: 'קובץ-בדיקה.jpg',
  });

  const decoded = decodeFrame(frame);
  assert.equal(decoded.kind, 'meta');
  assert.equal(decoded.transferId, 0xdeadbeef);
  assert.equal(decoded.fileSize, 123456);
  assert.equal(decoded.blockSize, 700);
  assert.equal(decoded.k, 176);
  assert.equal(Buffer.from(decoded.checksum).equals(checksum), true);
  assert.equal(decoded.filename, 'קובץ-בדיקה.jpg');
});

test('data frame round-trips through encode/decode', () => {
  const payload = new Uint8Array(randomBytes(700));
  const frame = encodeDataFrame({ transferId: 42, seed: 999, payload });

  const decoded = decodeFrame(frame);
  assert.equal(decoded.kind, 'data');
  assert.equal(decoded.transferId, 42);
  assert.equal(decoded.seed, 999);
  assert.equal(Buffer.from(decoded.payload).equals(Buffer.from(payload)), true);
});

test('decodeFrame rejects garbage input', () => {
  assert.equal(decodeFrame(new Uint8Array([1, 2, 3])), null);
  assert.equal(decodeFrame(new Uint8Array([0x00, 0x00, ...randomBytes(18)])), null);
});
