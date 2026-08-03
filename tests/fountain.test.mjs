import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomInt } from 'node:crypto';
import { FountainEncoder, FountainDecoder } from '../web/js/fountain.js';

function splitIntoBlocks(data, blockSize) {
  const k = Math.ceil(data.length / blockSize);
  const blocks = [];
  for (let i = 0; i < k; i++) {
    const block = new Uint8Array(blockSize);
    const slice = data.subarray(i * blockSize, (i + 1) * blockSize);
    block.set(slice);
    blocks.push(block);
  }
  return blocks;
}

function concatBlocks(blocks, originalSize) {
  const out = new Uint8Array(blocks.length * blocks[0].length);
  blocks.forEach((b, i) => out.set(b, i * b.length));
  return out.subarray(0, originalSize);
}

test('fountain code round-trip reconstructs the original file exactly', () => {
  const size = 50_000;
  const blockSize = 300;
  const original = new Uint8Array(randomBytes(size));
  const blocks = splitIntoBlocks(original, blockSize);
  const k = blocks.length;

  const encoder = new FountainEncoder(blocks, blockSize);
  const decoder = new FountainDecoder(k, blockSize);

  let seed = 1;
  let symbolsSent = 0;
  while (!decoder.isComplete) {
    const payload = encoder.encodeSymbol(seed);
    decoder.addSymbol(seed, payload);
    seed++;
    symbolsSent++;
    assert.ok(symbolsSent < k * 5, 'decoder should converge well before 5x overhead');
  }

  const reconstructed = concatBlocks(decoder.getBlocks(), size);
  assert.equal(Buffer.from(reconstructed).equals(Buffer.from(original)), true);
  // Fountain codes should need only a small overhead over k symbols.
  assert.ok(symbolsSent < k * 1.5, `expected < 1.5x overhead, got ${symbolsSent}/${k}`);
});

test('decoder tolerates lost frames and out-of-order / duplicate delivery', () => {
  const size = 20_000;
  const blockSize = 250;
  const original = new Uint8Array(randomBytes(size));
  const blocks = splitIntoBlocks(original, blockSize);
  const k = blocks.length;

  const encoder = new FountainEncoder(blocks, blockSize);

  // Generate a large pool of symbols, shuffle, drop 30%, and duplicate some.
  const pool = [];
  for (let seed = 1; seed <= k * 3; seed++) {
    pool.push({ seed, payload: encoder.encodeSymbol(seed) });
  }
  for (let i = pool.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }
  const delivered = pool.filter(() => Math.random() > 0.3);
  const withDuplicates = [...delivered, ...delivered.slice(0, 10)];

  const decoder = new FountainDecoder(k, blockSize);
  for (const { seed, payload } of withDuplicates) {
    decoder.addSymbol(seed, payload);
  }

  assert.equal(decoder.isComplete, true, 'decoder should still complete despite loss/reorder/dupes');
  const reconstructed = concatBlocks(decoder.getBlocks(), size);
  assert.equal(Buffer.from(reconstructed).equals(Buffer.from(original)), true);
});

test('a late joiner can reconstruct from symbols generated after it starts listening', () => {
  const size = 15_000;
  const blockSize = 200;
  const original = new Uint8Array(randomBytes(size));
  const blocks = splitIntoBlocks(original, blockSize);
  const k = blocks.length;

  const encoder = new FountainEncoder(blocks, blockSize);
  const decoder = new FountainDecoder(k, blockSize);

  // Simulate a stream already in progress: seeds 1..k/2 are "missed" because
  // the receiver joined late, only seeds from k/2 onward are observed.
  let seed = Math.floor(k / 2);
  while (!decoder.isComplete) {
    decoder.addSymbol(seed, encoder.encodeSymbol(seed));
    seed++;
    assert.ok(seed < k * 6, 'should not need an unreasonable number of symbols');
  }

  const reconstructed = concatBlocks(decoder.getBlocks(), size);
  assert.equal(Buffer.from(reconstructed).equals(Buffer.from(original)), true);
});
