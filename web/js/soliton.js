// Robust Soliton Distribution (Luby, 2002) for LT fountain codes, plus
// deterministic samplers driven by a seeded PRNG (see prng.js).

export function robustSolitonCdf(k, c = 0.1, delta = 0.5) {
  if (k <= 1) return [0, 1];

  const S = c * Math.log(k / delta) * Math.sqrt(k);
  const kOverS = Math.max(1, Math.round(k / S));

  const mu = new Array(k + 1).fill(0);
  mu[1] = 1 / k;
  for (let d = 2; d <= k; d++) mu[d] = 1 / (d * (d - 1));

  for (let d = 1; d < kOverS; d++) mu[d] += S / (k * d);
  if (kOverS <= k) mu[kOverS] += (S * Math.log(S / delta)) / k;

  let z = 0;
  for (let d = 1; d <= k; d++) z += mu[d];

  const cdf = new Array(k + 1).fill(0);
  let acc = 0;
  for (let d = 1; d <= k; d++) {
    acc += mu[d] / z;
    cdf[d] = acc;
  }
  cdf[k] = 1; // guard against floating point drift
  return cdf;
}

export function sampleDegree(cdf, rand) {
  const x = rand();
  let lo = 1;
  let hi = cdf.length - 1;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (cdf[mid] >= x) hi = mid;
    else lo = mid + 1;
  }
  return lo;
}

// Picks `d` distinct indices from [0, k) using a partial Fisher-Yates shuffle
// implemented with a sparse swap map, so cost is O(d) rather than O(k).
export function sampleIndices(k, d, rand) {
  const swapped = new Map();
  const chosen = new Array(d);
  let n = k;
  for (let i = 0; i < d; i++) {
    const j = Math.floor(rand() * n);
    chosen[i] = swapped.has(j) ? swapped.get(j) : j;
    const last = n - 1;
    swapped.set(j, swapped.has(last) ? swapped.get(last) : last);
    n--;
  }
  return chosen;
}
