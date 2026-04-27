const WRAPPER_VERSION = 'genesis-enc-v1';
const ALGORITHM_LABEL = 'RSA-OAEP-256+A256GCM';
const PREFIX = `[${WRAPPER_VERSION}] [${ALGORITHM_LABEL}] string:`;
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

const CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
const AUTHORIZE_URL = 'https://auth.openai.com/oauth/authorize';
const REDIRECT_URI = 'http://localhost:1455/auth/callback';
const SCOPE = 'openid profile email offline_access';
const SOFT_STALE_MINUTES = 10;

const mintButton = document.getElementById('mint-link-btn');
const oauthUrlEl = document.getElementById('oauth-url');
const stateHintEl = document.getElementById('state-hint');
const codeVerifierEl = document.getElementById('code-verifier');
const callbackUrlInput = document.getElementById('callback-url-input');
const buildCliProxyBtn = document.getElementById('build-cliproxy-btn');
const buildOpenClawBtn = document.getElementById('build-openclaw-btn');
const encryptedOutputEl = document.getElementById('encrypted-output');
const payloadPreviewEl = document.getElementById('payload-preview');
const callbackStateEl = document.getElementById('callback-state');
const callbackCodePresentEl = document.getElementById('callback-code-present');
const mintAgeEl = document.getElementById('mint-age');
const validationResultEl = document.getElementById('validation-result');
const statusEl = document.getElementById('status');
const kidBadge = document.getElementById('kid-badge');

kidBadge.textContent = `key ${KEY_FINGERPRINT.slice(0, 16)}`;

let latestPackage = null;

function setStatus(text, kind = 'subtle') {
  statusEl.textContent = text;
  statusEl.className = `status ${kind}`;
}

function base64urlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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
  const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
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
    ek: base64urlEncode(new Uint8Array(encryptedKey)),
    iv: base64urlEncode(iv),
    ct: base64urlEncode(ciphertext),
    tag: base64urlEncode(tag),
  };
  const compact = base64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  return `${PREFIX}${compact}`;
}

async function copyText(text) {
  await navigator.clipboard.writeText(text);
}

function randomHex(bytes = 16) {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Array.from(data, byte => byte.toString(16).padStart(2, '0')).join('');
}

async function generatePKCE() {
  const verifierBytes = new Uint8Array(32);
  crypto.getRandomValues(verifierBytes);
  const verifier = base64urlEncode(verifierBytes);
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = base64urlEncode(new Uint8Array(hash));
  return { verifier, challenge };
}

async function mintPortablePackage() {
  const { verifier, challenge } = await generatePKCE();
  const state = randomHex(16);
  const mintedAt = new Date().toISOString();
  const url = new URL(AUTHORIZE_URL);
  url.searchParams.set('response_type', 'code');
  url.searchParams.set('client_id', CLIENT_ID);
  url.searchParams.set('redirect_uri', REDIRECT_URI);
  url.searchParams.set('scope', SCOPE);
  url.searchParams.set('code_challenge', challenge);
  url.searchParams.set('code_challenge_method', 'S256');
  url.searchParams.set('state', state);
  url.searchParams.set('id_token_add_organizations', 'true');
  url.searchParams.set('codex_cli_simplified_flow', 'true');
  url.searchParams.set('originator', 'genesis-web');

  return {
    version: 3,
    kind: 'openai-oauth-portable-flow',
    sourceLane: 'genesis-web',
    requestedBy: 'user',
    mintedAt,
    oauthUrl: url.toString(),
    stateHint: state,
    codeVerifier: verifier,
    redirectUri: REDIRECT_URI,
    clientId: CLIENT_ID,
  };
}

function resetOutputs() {
  encryptedOutputEl.value = '';
  payloadPreviewEl.value = '';
  callbackStateEl.value = '';
  callbackCodePresentEl.value = '';
  mintAgeEl.value = '';
  validationResultEl.value = '';
}

function parseCallbackUrl(raw) {
  const value = raw.trim();
  if (!value) throw new Error('Paste the localhost callback URL first.');
  const url = new URL(value);
  const query = Object.fromEntries(url.searchParams.entries());
  return {
    raw: value,
    origin: url.origin,
    path: url.pathname,
    code: query.code || null,
    state: query.state || null,
    error: query.error || null,
    query,
  };
}

function minutesBetween(isoA, isoB) {
  const a = new Date(isoA).getTime();
  const b = new Date(isoB).getTime();
  if (!Number.isFinite(a) || !Number.isFinite(b)) return null;
  return Math.max(0, Math.round((b - a) / 60000));
}

function formatAge(minutes) {
  if (minutes === null) return 'unknown';
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function requireMint() {
  if (latestPackage) return latestPackage;
  const stateHint = stateHintEl.value.trim();
  const codeVerifier = codeVerifierEl.value.trim();
  if (!stateHint || !codeVerifier) throw new Error('Mint first.');
  return {
    version: 3,
    kind: 'openai-oauth-portable-flow',
    sourceLane: 'genesis-web',
    requestedBy: 'user',
    mintedAt: null,
    oauthUrl: oauthUrlEl.value.trim() || null,
    stateHint,
    codeVerifier,
    redirectUri: REDIRECT_URI,
    clientId: CLIENT_ID,
  };
}

function validate(pkg, callback) {
  const ageMinutes = pkg.mintedAt ? minutesBetween(pkg.mintedAt, new Date().toISOString()) : null;
  const hasCode = Boolean(callback.code);
  const stateMatches = callback.state === pkg.stateHint;
  const hasExpectedOrigin = callback.origin === REDIRECT_URI.replace('/auth/callback', '');
  const softStale = ageMinutes !== null && ageMinutes > SOFT_STALE_MINUTES;
  let result = 'valid';
  if (!hasCode) result = 'missing_code';
  else if (!stateMatches) result = 'state_mismatch';
  else if (!hasExpectedOrigin) result = 'unexpected_origin';
  else if (softStale) result = 'stale_warning';
  return { result, ageMinutes, hasCode, stateMatches, hasExpectedOrigin };
}

function buildTargetPayload(target) {
  const pkg = requireMint();
  const callback = parseCallbackUrl(callbackUrlInput.value);
  const validation = validate(pkg, callback);

  callbackStateEl.value = callback.state || '';
  callbackCodePresentEl.value = validation.hasCode ? 'yes' : 'no';
  mintAgeEl.value = formatAge(validation.ageMinutes);
  validationResultEl.value = validation.result;

  const payload = {
    version: 1,
    kind: target === 'cliproxyapi' ? 'genesis-openai-oauth-cliproxyapi-import' : 'genesis-openai-oauth-openclaw-import',
    target,
    envelope: {
      encrypted: true,
      wrapper: WRAPPER_VERSION,
      algorithm: ALGORITHM_LABEL,
      kid: KEY_FINGERPRINT,
      source: 'genesisinfunity.github.io/openai-oauth',
      createdAt: new Date().toISOString(),
    },
    validation: {
      result: validation.result,
      ageMinutes: validation.ageMinutes,
      softStaleAfterMinutes: SOFT_STALE_MINUTES,
      stateMatches: validation.stateMatches,
      expectedOrigin: REDIRECT_URI.replace('/auth/callback', ''),
      actualOrigin: callback.origin,
    },
    oauth: {
      clientId: pkg.clientId,
      redirectUri: pkg.redirectUri,
      mintedAt: pkg.mintedAt,
      sourceLane: pkg.sourceLane,
      stateHint: pkg.stateHint,
      callbackUrl: callback.raw,
      authorizationCode: callback.code,
      codeVerifier: pkg.codeVerifier,
      scope: callback.query.scope || SCOPE,
    },
  };

  if (target === 'cliproxyapi') {
    payload.cliproxyapi = {
      expectedAuthType: 'codex',
      expectedFieldsAfterExchange: ['access_token', 'refresh_token', 'id_token', 'account_id', 'email', 'type', 'expired', 'last_refresh'],
    };
  } else {
    payload.openclaw = {
      expectedMode: 'oauth',
      expectedProvider: 'openai-codex',
    };
  }

  return payload;
}

async function buildAndCopy(target) {
  buildCliProxyBtn.disabled = true;
  buildOpenClawBtn.disabled = true;
  setStatus(`Building ${target} package…`);
  try {
    const payload = buildTargetPayload(target);
    payloadPreviewEl.value = JSON.stringify(payload, null, 2);
    const encrypted = await encryptString(JSON.stringify(payload));
    encryptedOutputEl.value = encrypted;
    await copyText(encrypted);
    const kind = payload.validation.result === 'valid' ? 'success' : payload.validation.result === 'stale_warning' ? 'subtle' : 'error';
    setStatus(`${target} package encrypted and copied.`, kind);
  } catch (error) {
    console.error(error);
    setStatus(`Build failed: ${error?.message || String(error)}`, 'error');
  } finally {
    buildCliProxyBtn.disabled = false;
    buildOpenClawBtn.disabled = false;
  }
}

mintButton.addEventListener('click', async () => {
  mintButton.disabled = true;
  resetOutputs();
  setStatus('Minting locally…');
  try {
    latestPackage = await mintPortablePackage();
    oauthUrlEl.value = latestPackage.oauthUrl;
    stateHintEl.value = latestPackage.stateHint;
    codeVerifierEl.value = latestPackage.codeVerifier;
    await copyText(latestPackage.oauthUrl);
    setStatus('Login link copied.', 'success');
  } catch (error) {
    console.error(error);
    setStatus(`Mint failed: ${error?.message || String(error)}`, 'error');
  } finally {
    mintButton.disabled = false;
  }
});

buildCliProxyBtn.addEventListener('click', async () => buildAndCopy('cliproxyapi'));
buildOpenClawBtn.addEventListener('click', async () => buildAndCopy('openclaw'));
