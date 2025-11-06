// decryptor.js - use Web Crypto to derive key and decrypt AES-GCM payload
function b64ToArr(b64) {
  const bin = atob(b64.replace(/\s/g,''));
  const len = bin.length;
  const arr = new Uint8Array(len);
  for (let i = 0; i < len; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}
function arrToStr(buf) { return new TextDecoder().decode(buf); }

async function deriveKeyFromPassphrase(passphrase, salt='fixed-salt-for-app-please-change') {
  const enc = new TextEncoder();
  const passKey = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({
    name: 'PBKDF2',
    salt: enc.encode(salt),
    iterations: 150000,
    hash: 'SHA-256'
  }, passKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
  return key;
}

async function decryptPayloadWithPassphrase(passphrase) {
  if (typeof ENCRYPTED_PAYLOAD === 'undefined') throw new Error('ENCRYPTED_PAYLOAD not found. Generate secrets.enc.js using encrypt.js locally.');
  const iv = new Uint8Array(b64ToArr(ENCRYPTED_PAYLOAD.iv));
  const ciphertext = b64ToArr(ENCRYPTED_PAYLOAD.ciphertext);
  const key = await deriveKeyFromPassphrase(passphrase);
  try {
    const plain = await crypto.subtle.decrypt({
      name: 'AES-GCM',
      iv: iv,
      tagLength: ENCRYPTED_PAYLOAD.tagLength || 128
    }, key, ciphertext);
    const jsonStr = arrToStr(plain);
    return JSON.parse(jsonStr);
  } catch (e) {
    console.error('Decrypt error', e);
    throw new Error('Failed to decrypt payload. Wrong passphrase or corrupted payload.');
  }
}

// Public API
window.loadSecrets = async function(passphrase) {
  return await decryptPayloadWithPassphrase(passphrase);
};
