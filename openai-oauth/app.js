const mintButton = document.getElementById('mint-link-btn');
const statusEl = document.getElementById('status');
const oauthUrlEl = document.getElementById('oauth-url');
const stateHintEl = document.getElementById('state-hint');
const codeVerifierEl = document.getElementById('code-verifier');
const packageOutput = document.getElementById('package-output');
const copyLinkBtn = document.getElementById('copy-link-btn');
const copyPackageBtn = document.getElementById('copy-package-btn');

const CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
const AUTHORIZE_URL = 'https://auth.openai.com/oauth/authorize';
const REDIRECT_URI = 'http://localhost:1455/auth/callback';
const SCOPE = 'openid profile email offline_access';

let latestPackage = null;

function setStatus(text, kind = 'subtle') {
  statusEl.textContent = text;
  statusEl.className = `status ${kind}`;
}

async function copyText(text) {
  await navigator.clipboard.writeText(text);
}

function base64urlEncode(bytes) {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
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
    version: 2,
    kind: 'openai-oauth-portable-flow',
    sourceLane: 'genesis-web',
    requestedBy: 'user',
    mintedAt,
    oauthUrl: url.toString(),
    stateHint: state,
    codeVerifier: verifier,
    redirectUri: REDIRECT_URI,
    clientId: CLIENT_ID,
    applyInstructions: {
      userWillProvide: [
        'portable flow package',
        'callback URL',
        'requested target agent/lane',
      ],
      agentMustDo: [
        'use the supplied codeVerifier and callback URL to complete the code exchange',
        'persist auth in the requested target lane',
        'verify the auth actually landed there',
      ],
    },
    notes: [
      'This package was minted entirely in the browser; no broker/backend was used for minting.',
      'Later callback application still needs Genesis or another trusted runtime.',
      'The login flow may redirect to localhost after sign-in; keep the callback URL so Genesis can apply it later.',
    ],
  };
}

function resetOutput() {
  latestPackage = null;
  oauthUrlEl.value = '';
  stateHintEl.value = '';
  codeVerifierEl.value = '';
  packageOutput.value = '';
  copyLinkBtn.disabled = true;
  copyPackageBtn.disabled = true;
}

mintButton.addEventListener('click', async () => {
  mintButton.disabled = true;
  resetOutput();
  setStatus('Minting OAuth link and package locally in your browser…');
  try {
    latestPackage = await mintPortablePackage();

    oauthUrlEl.value = latestPackage.oauthUrl;
    stateHintEl.value = latestPackage.stateHint;
    codeVerifierEl.value = latestPackage.codeVerifier;
    packageOutput.value = JSON.stringify(latestPackage, null, 2);
    copyLinkBtn.disabled = false;
    copyPackageBtn.disabled = false;

    setStatus('OAuth link and package ready. Open the link locally, then send Genesis the package + callback URL in Telegram DM.', 'success');
  } catch (error) {
    console.error(error);
    setStatus(`Mint failed: ${error?.message || String(error)}`, 'error');
  } finally {
    mintButton.disabled = false;
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
  setStatus('Package copied. Send it back to Genesis with the callback URL later.', 'success');
});
