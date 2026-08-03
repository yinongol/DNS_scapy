import { FountainDecoder } from './fountain.js';
import { decodeFrame } from './framing.js';
import { base64ToBytes, sha256, formatBytes, formatRate } from './browser-utils.js';

const video = document.getElementById('video');
const scanCanvas = document.getElementById('scanCanvas');
const startCamBtn = document.getElementById('startCamBtn');
const stopCamBtn = document.getElementById('stopCamBtn');
const statusEl = document.getElementById('status');
const progressBar = document.getElementById('progressBar');
const statBlocks = document.getElementById('statBlocks');
const statSize = document.getElementById('statSize');
const statRate = document.getElementById('statRate');
const downloadLink = document.getElementById('downloadLink');

const ctx = scanCanvas.getContext('2d', { willReadFrequently: true });

let stream = null;
let scanning = false;
let session = null; // { transferId, decoder, meta, startedAt }

function resetSession(meta) {
  session = {
    transferId: meta.transferId,
    meta,
    decoder: new FountainDecoder(meta.k, meta.blockSize),
    startedAt: Date.now(),
  };
  statSize.textContent = formatBytes(meta.fileSize);
  statBlocks.textContent = `0/${meta.k}`;
  progressBar.style.width = '0%';
  downloadLink.style.display = 'none';
  statusEl.textContent = `זוהה שידור: "${meta.filename}" — אוסף פריימים...`;
  statusEl.className = 'status-line';
}

async function handleFrame(bytes) {
  const frame = decodeFrame(bytes);
  if (!frame) return;

  if (frame.kind === 'meta') {
    if (!session || session.transferId !== frame.transferId) {
      resetSession(frame);
    }
    return;
  }

  if (frame.kind === 'data') {
    if (!session || session.transferId !== frame.transferId) return; // wait for metadata first
    session.decoder.addSymbol(frame.seed, frame.payload);

    const { decoder, meta } = session;
    statBlocks.textContent = `${decoder.resolvedCount}/${meta.k}`;
    progressBar.style.width = `${Math.min(100, (decoder.resolvedCount / meta.k) * 100)}%`;

    const elapsedSec = (Date.now() - session.startedAt) / 1000;
    const bytesResolved = decoder.resolvedCount * meta.blockSize;
    statRate.textContent = formatRate(elapsedSec > 0 ? bytesResolved / elapsedSec : 0);

    if (decoder.isComplete) {
      await finishTransfer();
    }
  }
}

async function finishTransfer() {
  const { decoder, meta } = session;
  scanning = false;
  stopCamera();

  const full = new Uint8Array(meta.k * meta.blockSize);
  decoder.getBlocks().forEach((b, i) => full.set(b, i * meta.blockSize));
  const trimmed = full.subarray(0, meta.fileSize);

  const checksum = await sha256(trimmed);
  const checksumHex = Array.from(checksum).map((b) => b.toString(16).padStart(2, '0')).join('');
  const expectedHex = Array.from(meta.checksum).map((b) => b.toString(16).padStart(2, '0')).join('');

  if (checksumHex !== expectedHex) {
    statusEl.textContent = 'שגיאה: ה-checksum לא תואם. הקובץ עלול להיות פגום — נסה שוב.';
    statusEl.className = 'status-line err';
    return;
  }

  const blob = new Blob([trimmed]);
  const url = URL.createObjectURL(blob);
  downloadLink.href = url;
  downloadLink.download = meta.filename || 'received-file';
  downloadLink.textContent = `הורד: ${meta.filename} (${formatBytes(trimmed.length)})`;
  downloadLink.style.display = 'inline-flex';

  statusEl.textContent = `הקובץ התקבל ואומת בהצלחה (SHA-256 תואם)!`;
  statusEl.className = 'status-line ok';
}

function scanLoop() {
  if (!scanning) return;
  if (video.readyState === video.HAVE_ENOUGH_DATA) {
    const w = (scanCanvas.width = Math.min(640, video.videoWidth));
    const h = (scanCanvas.height = Math.round(w * (video.videoHeight / video.videoWidth)));
    ctx.drawImage(video, 0, 0, w, h);
    const imageData = ctx.getImageData(0, 0, w, h);
    const code = window.jsQR(imageData.data, w, h);
    if (code && code.data) {
      try {
        handleFrame(base64ToBytes(code.data));
      } catch (e) {
        // ignore malformed / non-BeamDrop QR codes in frame
      }
    }
  }
  requestAnimationFrame(scanLoop);
}

function stopCamera() {
  if (stream) {
    stream.getTracks().forEach((t) => t.stop());
    stream = null;
  }
  startCamBtn.style.display = 'inline-flex';
  stopCamBtn.style.display = 'none';
}

startCamBtn.addEventListener('click', async () => {
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: 'environment' } },
      audio: false,
    });
    video.srcObject = stream;
    await video.play();
    scanning = true;
    startCamBtn.style.display = 'none';
    stopCamBtn.style.display = 'inline-flex';
    statusEl.textContent = 'סורק... כוון את המצלמה למסך השולח.';
    requestAnimationFrame(scanLoop);
  } catch (err) {
    statusEl.textContent = `לא ניתן לגשת למצלמה: ${err.message}. ודא שאתה משתמש ב-HTTPS או localhost.`;
    statusEl.className = 'status-line err';
  }
});

stopCamBtn.addEventListener('click', () => {
  scanning = false;
  stopCamera();
  statusEl.textContent = 'הסריקה נעצרה.';
  statusEl.className = 'status-line';
});
