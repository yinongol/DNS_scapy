import { FountainEncoder } from './fountain.js';
import { encodeMetaFrame, encodeDataFrame } from './framing.js';
import { bytesToBase64, sha256, randomUint32, formatBytes, formatRate } from './browser-utils.js';

const fileInput = document.getElementById('fileInput');
const blockSizeSelect = document.getElementById('blockSize');
const fpsSlider = document.getElementById('fps');
const fpsVal = document.getElementById('fpsVal');
const qrCanvas = document.getElementById('qrCanvas');
const startBtn = document.getElementById('startBtn');
const stopBtn = document.getElementById('stopBtn');
const statusEl = document.getElementById('status');
const statFrames = document.getElementById('statFrames');
const statRate = document.getElementById('statRate');
const statTime = document.getElementById('statTime');

const METADATA_INTERVAL = 12; // re-broadcast metadata every N data frames

let transferState = null; // { encoder, transferId, meta, metaFrameBytes, k }
let timer = null;
let frameCounter = 0;
let framesSent = 0;
let startedAt = 0;

fpsSlider.addEventListener('input', () => { fpsVal.textContent = fpsSlider.value; });

fileInput.addEventListener('change', async () => {
  const file = fileInput.files[0];
  if (!file) { startBtn.disabled = true; return; }
  statusEl.textContent = `מכין "${file.name}" (${formatBytes(file.size)})...`;
  statusEl.className = 'status-line';
  await prepareTransfer(file);
  startBtn.disabled = false;
  statusEl.textContent = `מוכן לשידור — ${transferState.k} בלוקים.`;
});

async function prepareTransfer(file) {
  const blockSize = parseInt(blockSizeSelect.value, 10);
  const buf = new Uint8Array(await file.arrayBuffer());
  const checksum = await sha256(buf);

  const k = Math.max(1, Math.ceil(buf.length / blockSize));
  const blocks = [];
  for (let i = 0; i < k; i++) {
    const block = new Uint8Array(blockSize);
    block.set(buf.subarray(i * blockSize, (i + 1) * blockSize));
    blocks.push(block);
  }

  const transferId = randomUint32();
  const metaFrameBytes = encodeMetaFrame({
    transferId,
    fileSize: buf.length,
    blockSize,
    k,
    checksum,
    filename: file.name,
  });

  transferState = {
    encoder: new FountainEncoder(blocks, blockSize),
    transferId,
    metaFrameBytes,
    k,
    blockSize,
    fileSize: buf.length,
  };
}

function renderQr(bytes) {
  const text = bytesToBase64(bytes);
  window.QRCode.toCanvas(qrCanvas, text, { errorCorrectionLevel: 'L', margin: 1, width: 320 }, (err) => {
    if (err) console.error('QR render error', err);
  });
}

function tick() {
  if (!transferState) return;
  let frameBytes;
  if (frameCounter % METADATA_INTERVAL === 0) {
    frameBytes = transferState.metaFrameBytes;
  } else {
    const seed = randomUint32();
    const payload = transferState.encoder.encodeSymbol(seed);
    frameBytes = encodeDataFrame({ transferId: transferState.transferId, seed, payload });
  }
  renderQr(frameBytes);
  frameCounter++;
  framesSent++;

  const elapsedSec = (Date.now() - startedAt) / 1000;
  const bytesSent = framesSent * transferState.blockSize;
  statFrames.textContent = String(framesSent);
  statRate.textContent = formatRate(elapsedSec > 0 ? bytesSent / elapsedSec : 0);
  const mm = String(Math.floor(elapsedSec / 60)).padStart(2, '0');
  const ss = String(Math.floor(elapsedSec % 60)).padStart(2, '0');
  statTime.textContent = `${mm}:${ss}`;
}

startBtn.addEventListener('click', () => {
  if (!transferState) return;
  frameCounter = 0;
  framesSent = 0;
  startedAt = Date.now();
  const fps = parseInt(fpsSlider.value, 10);
  timer = setInterval(tick, 1000 / fps);
  startBtn.style.display = 'none';
  stopBtn.style.display = 'inline-flex';
  fileInput.disabled = true;
  blockSizeSelect.disabled = true;
  statusEl.textContent = 'משדר... (הלולאה תימשך ללא הגבלה — לחץ עצור כשהמקלט סיים)';
  statusEl.className = 'status-line ok';
});

stopBtn.addEventListener('click', () => {
  clearInterval(timer);
  timer = null;
  startBtn.style.display = 'inline-flex';
  stopBtn.style.display = 'none';
  fileInput.disabled = false;
  blockSizeSelect.disabled = false;
  statusEl.textContent = 'השידור נעצר.';
  statusEl.className = 'status-line';
});
