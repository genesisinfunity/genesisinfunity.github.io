const mintButton = document.getElementById('mint-link-btn');
const statusEl = document.getElementById('status');
const oauthUrlEl = document.getElementById('oauth-url');
const stateHintEl = document.getElementById('state-hint');
const codeVerifierEl = document.getElementById('code-verifier');
const packageOutput = document.getElementById('package-output');
const copyLinkBtn = document.getElementById('copy-link-btn');
const copyPackageBtn = document.getElementById('copy-package-btn');
const finalizePackageInput = document.getElementById('finalize-package-input');
const callbackUrlInput = document.getElementById('callback-url-input');
const finalizeBtn = document.getElementById('finalize-btn');
const copyHandoffBtn = document.getElementById('copy-handoff-btn');
const callbackStateEl = document.getElementById('callback-state');
const callbackCodePresentEl = document.getElementById('callback-code-present');
const mintAgeEl = document.getElementById('mint-age');
const validationResultEl = document.getElementById('validation-result');
const handoffOutput = document.getElementById('handoff-output');

const CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
const AUTHORIZE_URL = 'https://auth.openai.com/oauth/authorize';
const REDIRECT_URI = 'http://localhost:1455/auth/callback';
const SCOPE = 'openid profile email offline_access';
const SOFT_STALE_MINUTES = 10;

let latestPackage = null;
let latestHandoff = null;

function setStatus(text, kind = 'subtle') {
  statusEl.textContent = text;
  statusEl.className = `status ${kind}`;
}

async function copyText(text) {
  await navigator.clipboard.writeText(text);
}

function base64urlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
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
    finalizeHints: {
      softStaleAfterMinutes: SOFT_STALE_MINUTES,
      expectedCallbackHost: 'localhost:1455',
      requiredQueryKeys: ['code', 'state'],
    },
  };
}

function resetMintOutput() {
  latestPackage = null;
  oauthUrlEl.value = '';
  stateHintEl.value = '';
  codeVerifierEl.value = '';
  packageOutput.value = '';
  copyLinkBtn.disabled = true;
  copyPackageBtn.disabled = true;
}

function resetFinalizeOutput() {
  latestHandoff = null;
  callbackStateEl.value = '';
  callbackCodePresentEl.value = '';
  mintAgeEl.value = '';
  validationResultEl.value = '';
  handoffOutput.value = '';
  copyHandoffBtn.disabled = true;
}

function parseJson(text) {
  return JSON.parse(text);
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function parseCallbackUrl(raw) {
  const url = new URL(raw.trim());
  const query = Object.fromEntries(url.searchParams.entries());
  return {
    raw: raw.trim(),
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
  return Math.max(0, Math.round((b - a) / 60000));
}

function formatAge(minutes) {
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function buildHandoff(pkg, callback) {
  const ageMinutes = minutesBetween(pkg.mintedAt, new Date().toISOString());
  const hasCode = Boolean(callback.code);
  const stateMatches = callback.state === pkg.stateHint;
  const hasExpectedOrigin = callback.origin === 'http://localhost:1455';
  const softStale = ageMinutes > SOFT_STALE_MINUTES;

  let validation = 'valid';
  if (!hasCode) validation = 'missing_code';
  else if (!stateMatches) validation = 'state_mismatch';
  else if (!hasExpectedOrigin) validation = 'unexpected_origin';
  else if (softStale) validation = 'stale_warning';

  const normalized = {
    version: 1,
    kind: 'openai-oauth-finalize-handoff',
    mintedPackage: {
      kind: pkg.kind,
      version: pkg.version,
      mintedAt: pkg.mintedAt,
      clientId: pkg.clientId,
      redirectUri: pkg.redirectUri,
      stateHint: pkg.stateHint,
      codeVerifier: pkg.codeVerifier,
      sourceLane: pkg.sourceLane,
    },
    callback: {
      rawUrl: callback.raw,
      origin: callback.origin,
      path: callback.path,
      state: callback.state,
      hasCode,
      code: callback.code,
      error: callback.error,
      query: callback.query,
    },
    validation: {
      result: validation,
      ageMinutes,
      softStaleAfterMinutes: SOFT_STALE_MINUTES,
      stateMatches,
      expectedOrigin: 'http://localhost:1455',
      actualOrigin: callback.origin,
    },
    exportHints: {
      openclaw: {
        expectedUse: 'trusted runtime completes token exchange and persists auth into requested lane',
      },
      cliproxyapi: {
        expectedUse: 'trusted runtime completes token exchange then writes CLIProxyAPI auth JSON',
      },
    },
  };

  return {
    normalized,
    summary: {
      validation,
      ageMinutes,
      hasCode,
      callbackState: callback.state || '',
    },
  };
}

mintButton.addEventListener('click', async () => {
  mintButton.disabled = true;
  resetMintOutput();
  setStatus('Minting locally…');
  try {
    latestPackage = await mintPortablePackage();
    oauthUrlEl.value = latestPackage.oauthUrl;
    stateHintEl.value = latestPackage.stateHint;
    codeVerifierEl.value = latestPackage.codeVerifier;
    packageOutput.value = JSON.stringify(latestPackage, null, 2);
    finalizePackageInput.value = packageOutput.value;
    copyLinkBtn.disabled = false;
    copyPackageBtn.disabled = false;
    setStatus('Mint ready.', 'success');
  } catch (error) {
    console.error(error);
    setStatus(`Mint failed: ${error?.message || String(error)}`, 'error');
  } finally {
    mintButton.disabled = false;
  }
});

finalizeBtn.addEventListener('click', async () => {
  resetFinalizeOutput();
  finalizeBtn.disabled = true;
  setStatus('Validating callback locally…');
  try {
    const pkg = parseJson(finalizePackageInput.value.trim());
    const callback = parseCallbackUrl(callbackUrlInput.value.trim());
    const result = buildHandoff(pkg, callback);
    latestHandoff = result.normalized;
    callbackStateEl.value = result.summary.callbackState;
    callbackCodePresentEl.value = result.summary.hasCode ? 'yes' : 'no';
    mintAgeEl.value = formatAge(result.summary.ageMinutes);
    validationResultEl.value = result.summary.validation;
    handoffOutput.value = JSON.stringify(result.normalized, null, 2);
    copyHandoffBtn.disabled = false;
    const kind = result.summary.validation === 'valid' ? 'success' : result.summary.validation === 'stale_warning' ? 'subtle' : 'error';
    setStatus(`Finalize ${result.summary.validation}.`, kind);
  } catch (error) {
    console.error(error);
    setStatus(`Finalize failed: ${error?.message || String(error)}`, 'error');
  } finally {
    finalizeBtn.disabled = false;
  }
});

copyLinkBtn.addEventListener('click', async () => {
  if (!oauthUrlEl.value) return;
  await copyText(oauthUrlEl.value);
  setStatus('OAuth link copied.', 'success');
});

copyPackageBtn.addEventListener('click', async () => {
  if (!packageOutput.value) return;
  await copyText(packageOutput.value);
  setStatus('Package copied.', 'success');
});

copyHandoffBtn.addEventListener('click', async () => {
  if (!handoffOutput.value) return;
  await copyText(handoffOutput.value);
  setStatus('Handoff JSON copied.', 'success');
});
