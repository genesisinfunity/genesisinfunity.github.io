const ALGORITHM_LABEL = 'RSA-OAEP-256+A256GCM';
const PREFIX = `[${ALGORITHM_LABEL}] string:`;
const PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA20TYKgSh2p9V3cKfGNMv
tpgZh8AiSYQjtDF8sutZDrko9EfgvCKxP9onYeAuHb1hBmFgwMFO8WEIHSr9pazR
rhl7XBx3DcsNNpXW/LuZJ2Fji5GBhfPm7C7QWfhvw8cTnLinIfQuv5pTF++T8O9I
15XhpQ8+O02vS1vwtDNKNogTbX7FqQknkdvCj0htBk4+D4TX5/Ht9e8ke0M8UEtJ
roC3zTzwtORpnCEdgQausTlCVek0Ch+W2GSd+sKEZ2LX2hgGaMN6/8hKS845V60W
VcCRdKSKc4jRHR5LwKzlXcIP1BD/Xs6qRFWnUeO1l/+mJps6LImnUJ4GquP3lfKn
/VecGTqZYSWL7IEFBZifpMeHCC5JDdf7Hiho8gKK0GR+4n6Cmer/1Iey9sLmVbm0
QguZn4KhIo7tA4+6SlB0nVHe0X0PwfONDT8COpk+JNU5aZedn2U4RhjwqXT4gsdb
wb96W6ZGgYMqJQnYhdd73Vv5R3AcCF99YYWSpCE7OhTxAgMBAAE=
-----END PUBLIC KEY-----`;
const KEY_FINGERPRINT = '87ac12997860b0b2';

const secretInput = document.getElementById('secret-input');
const output = document.getElementById('payload-output');
const statusEl = document.getElementById('status');
const encryptCopyBtn = document.getElementById('encrypt-copy');
const clearBtn = document.getElementById('clear-btn');
const kidBadge = document.getElementById('kid-badge');

kidBadge.textContent = `key ${KEY_FINGERPRINT.slice(0, 16)}`;

function setStatus(message, kind = 'subtle') {
  statusEl.textContent = message;
  statusEl.className = `status ${kind}`;
}

function base64UrlFromArrayBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function pemToArrayBuffer(pem) {
  const body = pem.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
  const binary = atob(body);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

async function importPublicKey() {
  return crypto.subtle.importKey(
    'spki',
    pemToArrayBuffer(PUBLIC_KEY_PEM),
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );
}

async function encryptString(plaintext) {
  const encoder = new TextEncoder();
  const rsaKey = await importPublicKey();
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt'],
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = encoder.encode(plaintext);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, plaintextBytes);
  const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);
  const encryptedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaKey, rawAesKey);
  const encryptedBytes = new Uint8Array(encrypted);
  const tag = encryptedBytes.slice(encryptedBytes.length - 16);
  const ciphertext = encryptedBytes.slice(0, encryptedBytes.length - 16);
  const payload = {
    v: 1,
    alg: ALGORITHM_LABEL,
    kid: KEY_FINGERPRINT,
    ek: base64UrlFromArrayBuffer(encryptedKey),
    iv: base64UrlFromArrayBuffer(iv.buffer),
    ct: base64UrlFromArrayBuffer(ciphertext.buffer),
    tag: base64UrlFromArrayBuffer(tag.buffer),
  };
  const compact = base64UrlFromArrayBuffer(new TextEncoder().encode(JSON.stringify(payload)).buffer);
  return `${PREFIX}${compact}`;
}

async function copyText(value) {
  await navigator.clipboard.writeText(value);
}

encryptCopyBtn.addEventListener('click', async () => {
  const secret = secretInput.value;
  if (!secret.trim()) {
    setStatus('Paste a secret first.', 'error');
    return;
  }
  encryptCopyBtn.disabled = true;
  setStatus('Encrypting…');
  try {
    const payload = await encryptString(secret);
    output.value = payload;
    await copyText(payload);
    setStatus('Encrypted and copied to clipboard. Paste it into Telegram exactly as-is.', 'success');
  } catch (error) {
    console.error(error);
    setStatus(`Encryption failed: ${error?.message ?? String(error)}`, 'error');
  } finally {
    encryptCopyBtn.disabled = false;
  }
});

clearBtn.addEventListener('click', () => {
  secretInput.value = '';
  output.value = '';
  setStatus('');
  secretInput.focus();
});
