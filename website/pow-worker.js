const te = new TextEncoder();
const CHUNK = 250;

function b64urlDecode(s) {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64urlEncode(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).split('+').join('-').split('/').join('_').replace(/=+$/g, '');
}

function concat(a, b, c) {
  const out = new Uint8Array(a.length + b.length + c.length);
  out.set(a, 0);
  out.set(b, a.length);
  out.set(c, a.length + b.length);
  return out;
}

function leadingZeroBits(bytes, bits) {
  const full = Math.floor(bits / 8);
  const rem = bits % 8;
  for (let i = 0; i < full; i++) if (bytes[i] !== 0) return false;
  if (rem === 0) return true;
  const mask = 0xFF << (8 - rem);
  return (bytes[full] & mask) === 0;
}

async function sha256(data) {
  const digest = await crypto.subtle.digest('SHA-256', data);
  return new Uint8Array(digest);
}

async function payloadHashCreate(ttl, blob) {
  const ttlBytes = new Uint8Array(8);
  const view = new DataView(ttlBytes.buffer);
  const high = Math.floor(ttl / 0x100000000);
  const low = ttl >>> 0;
  view.setUint32(0, high, false);
  view.setUint32(4, low, false);
  const blobBytes = te.encode(blob);
  const all = new Uint8Array(ttlBytes.length + blobBytes.length);
  all.set(ttlBytes, 0);
  all.set(blobBytes, ttlBytes.length);
  return sha256(all);
}

async function payloadHashView(nid) {
  return sha256(te.encode('view:' + nid));
}

function nonceFromCounter(counter) {
  const n = new Uint8Array(8);
  const v = new DataView(n.buffer);
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  v.setUint32(0, low, true);
  v.setUint32(4, high, true);
  return n;
}

onmessage = async (event) => {
  try {
    const { challenge, bits, mode, ttl, blob, nid } = event.data;
    const challengeBytes = b64urlDecode(challenge);
    let pHash;
    if (mode === 'view') {
      pHash = await payloadHashView(nid);
    } else {
      pHash = await payloadHashCreate(ttl, blob);
    }
    let counter = 0;

    while (true) {
      for (let i = 0; i < CHUNK; i++) {
        const nonce = nonceFromCounter(counter++);
        const candidate = concat(challengeBytes, nonce, pHash);
        const digest = await sha256(candidate);
        if (leadingZeroBits(digest, bits)) {
          postMessage({ ok: true, nonce: b64urlEncode(nonce) });
          return;
        }
      }
      postMessage({ ok: false, progress: counter });
    }
  } catch (e) {
    postMessage({ ok: false, fatal: true, message: String(e && e.message ? e.message : e) });
  }
};
