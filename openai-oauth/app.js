const apiBaseInput = document.getElementById('api-base');
const mintButton = document.getElementById('mint-link-btn');
const statusEl = document.getElementById('status');
const oauthUrlEl = document.getElementById('oauth-url');
const stateHintEl = document.getElementById('state-hint');
const packageOutput = document.getElementById('package-output');
const copyLinkBtn = document.getElementById('copy-link-btn');
const copyPackageBtn = document.getElementById('copy-package-btn');

let latestPackage = null;

function setStatus(text, kind = 'subtle') {
  statusEl.textContent = text;
  statusEl.className = `status ${kind}`;
}

async function copyText(text) {
  await navigator.clipboard.writeText(text);
}

function deriveStateHint(url) {
  try {
    return new URL(url).searchParams.get('state');
  } catch {
    return null;
  }
}

mintButton.addEventListener('click', async () => {
  const base = (apiBaseInput.value || '').trim().replace(/\/$/, '');
  if (!base) {
    setStatus('Enter a broker API base first.', 'error');
    return;
  }
  mintButton.disabled = true;
  latestPackage = null;
  oauthUrlEl.value = '';
  stateHintEl.value = '';
  packageOutput.value = '';
  copyLinkBtn.disabled = true;
  copyPackageBtn.disabled = true;
  setStatus('Minting OAuth link and package…');
  try {
    const flowResp = await fetch(`${base}/flows`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ lane: 'genesis' }),
    });
    const flowData = await flowResp.json();
    if (!flowResp.ok || !flowData?.flow?.id) {
      throw new Error(flowData?.error || 'flow creation failed');
    }

    const pkgResp = await fetch(`${base}/flows/${flowData.flow.id}/package`);
    const pkgData = await pkgResp.json();
    if (!pkgResp.ok || !pkgData?.package) {
      throw new Error(pkgData?.error || 'package export failed');
    }

    latestPackage = pkgData.package;
    const oauthUrl = pkgData.package.oauthUrl || '';
    const stateHint = pkgData.package.stateHint || deriveStateHint(oauthUrl) || '';

    oauthUrlEl.value = oauthUrl;
    stateHintEl.value = stateHint;
    packageOutput.value = JSON.stringify(pkgData.package, null, 2);
    copyLinkBtn.disabled = !oauthUrl;
    copyPackageBtn.disabled = false;

    if (oauthUrl) {
      setStatus('OAuth link and package ready. Open the link locally, then send me the package + callback URL in Telegram DM.', 'success');
    } else {
      setStatus('Package exported, but no OAuth URL was captured in this run. Check the package diagnostics.', 'error');
    }
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
