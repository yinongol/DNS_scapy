// LT (Luby Transform) fountain code encoder/decoder. Pure, dependency-free,
// works identically in the browser and under Node for testing.
import { mulberry32 } from './prng.js';
import { robustSolitonCdf, sampleDegree, sampleIndices } from './soliton.js';

function xorInto(dst, src) {
  for (let i = 0; i < dst.length; i++) dst[i] ^= src[i];
}

export class FountainEncoder {
  constructor(blocks, blockSize) {
    this.blocks = blocks; // array of Uint8Array, each exactly blockSize long
    this.k = blocks.length;
    this.blockSize = blockSize;
    this.cdf = robustSolitonCdf(this.k);
  }

  // seed: uint32 chosen by the caller (random per frame). Deterministically
  // reproducible on the receiving side from the same seed.
  encodeSymbol(seed) {
    const rand = mulberry32(seed);
    const d = Math.min(this.k, sampleDegree(this.cdf, rand));
    const indices = sampleIndices(this.k, d, rand);
    const payload = new Uint8Array(this.blockSize);
    for (const idx of indices) xorInto(payload, this.blocks[idx]);
    return payload;
  }
}

// Incremental belief-propagation ("peeling") decoder. Feed it symbols in any
// order, possibly with gaps or duplicates; it resolves source blocks as soon
// as enough independent symbols have been seen.
export class FountainDecoder {
  constructor(k, blockSize) {
    this.k = k;
    this.blockSize = blockSize;
    this.cdf = robustSolitonCdf(k);
    this.blocks = new Array(k).fill(null);
    this.resolvedCount = 0;
    this.waiting = new Map(); // unresolved block index -> Set(symbolId)
    this.symbols = new Map(); // symbolId -> { indices: Set, data: Uint8Array }
    this.seenSeeds = new Set();
    this._nextSymbolId = 0;
  }

  get isComplete() {
    return this.resolvedCount === this.k;
  }

  addSymbol(seed, payload) {
    if (this.isComplete || this.seenSeeds.has(seed)) return;
    this.seenSeeds.add(seed);

    const rand = mulberry32(seed);
    const d = Math.min(this.k, sampleDegree(this.cdf, rand));
    const indices = new Set(sampleIndices(this.k, d, rand));
    const data = payload.slice();

    for (const idx of [...indices]) {
      if (this.blocks[idx]) {
        xorInto(data, this.blocks[idx]);
        indices.delete(idx);
      }
    }

    if (indices.size === 0) return; // fully redundant symbol
    if (indices.size === 1) {
      const [idx] = indices;
      this._resolve(idx, data);
      return;
    }

    const id = this._nextSymbolId++;
    this.symbols.set(id, { indices, data });
    for (const idx of indices) {
      if (!this.waiting.has(idx)) this.waiting.set(idx, new Set());
      this.waiting.get(idx).add(id);
    }
  }

  // Iterative ripple propagation (BFS, not recursive) so large cascades of
  // simultaneous resolutions can't blow the call stack.
  _resolve(startIdx, startData) {
    const queue = [[startIdx, startData]];
    let head = 0;
    while (head < queue.length) {
      const [idx, data] = queue[head++];
      if (this.blocks[idx]) continue;

      this.blocks[idx] = data;
      this.resolvedCount++;

      const dependents = this.waiting.get(idx);
      this.waiting.delete(idx);
      if (!dependents) continue;

      for (const id of dependents) {
        const sym = this.symbols.get(id);
        if (!sym) continue;
        sym.indices.delete(idx);
        xorInto(sym.data, data);
        if (sym.indices.size === 0) {
          this.symbols.delete(id);
        } else if (sym.indices.size === 1) {
          this.symbols.delete(id);
          const [nextIdx] = sym.indices;
          queue.push([nextIdx, sym.data]);
        }
      }
    }
  }

  getBlocks() {
    return this.isComplete ? this.blocks : null;
  }
}
