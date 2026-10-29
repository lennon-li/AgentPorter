import {canonical, strictParse, reviewProposal, createDeviceKey, publicKeyHex, signReviewed} from './protocol.mjs';
const element = id => document.getElementById(id);
let pair = null, reviewed = null, reviewedSource = '', epoch = 0;

function invalidate() {
  epoch++;
  reviewed = null;
  element('acknowledge').checked = false;
  element('acknowledge').disabled = true;
  element('approve').disabled = true;
  element('receipt').value = '';
  element('copy').disabled = true;
  element('details').replaceChildren();
  element('approve').textContent = 'Sign this exact action';
}
function updateApproval() {
  element('approve').disabled = !pair || !reviewed || !element('acknowledge').checked;
}
function database() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('agentporter-owner-device-v1', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error('Device key storage is unavailable'));
  });
}
async function loadKey() {
  const db = await database();
  try {
    return await new Promise((resolve, reject) => {
      const transaction = db.transaction('keys', 'readonly');
      const request = transaction.objectStore('keys').get('owner');
      let value;
      request.onsuccess = () => { value = request.result; };
      transaction.oncomplete = () => resolve(value);
      transaction.onabort = transaction.onerror = () => reject(new Error('Could not read the device key'));
    });
  } finally { db.close(); }
}
async function saveNewKey(key) {
  const db = await database();
  try {
    await new Promise((resolve, reject) => {
      const transaction = db.transaction('keys', 'readwrite');
      // add is create-only: another tab cannot silently replace an enrolled key.
      transaction.objectStore('keys').add(key, 'owner');
      transaction.oncomplete = resolve;
      transaction.onabort = transaction.onerror = () => reject(new Error('A device key already exists or could not be saved; reload this page'));
    });
  } finally { db.close(); }
}
async function showKey(key) {
  const publicKey = await publicKeyHex(key);
  pair = key;
  element('public-key').value = publicKey;
  element('key-status').textContent = 'This device has a private signing key.';
  element('create-key').disabled = true;
  updateApproval();
}
element('proposal').addEventListener('input', () => {
  invalidate();
  element('status').textContent = 'Proposal changed. Review it before signing.';
});
element('acknowledge').addEventListener('change', updateApproval);
element('create-key').addEventListener('click', async event => {
  if (!event.isTrusted || pair) return;
  element('create-key').disabled = true;
  try { await saveNewKey(await createDeviceKey()); await showKey(await loadKey()); }
  catch (error) { element('key-status').textContent = error.message; }
});
element('review').addEventListener('click', async () => {
  invalidate();
  const current = epoch;
  const source = element('proposal').value;
  try {
    const snapshot = await reviewProposal(source);
    if (current !== epoch || source !== element('proposal').value) return;
    const request = strictParse(snapshot.payload);
    const rows = [
      ['Operation', request.operation], ['Workspace', request.workspace_id],
      ['Repository', request.repository_path], ['Filesystem device', request.repository_device],
      ['Repository inode', request.repository_inode], ['Branch', request.branch],
      ['Current HEAD', request.expected_head], ['Staged tree', request.expected_tree],
    ];
    if (request.operation === 'commit') rows.push(
      ['Author and committer', request.parameters.author_name], ['Email', request.parameters.author_email],
      ['Commit timestamp (UTC epoch seconds)', request.parameters.timestamp], ['Message', request.parameters.message],
    );
    else if (request.operation === 'push') rows.push(
      ['Publication', 'Fast-forward-only push; no force or deletion'],
      ['Remote identity', request.parameters.remote_id], ['Remote HTTPS repository', request.parameters.remote_url],
      ['Remote branch', request.parameters.remote_ref], ['Expected remote tip (all zeros means absent)', request.parameters.old_oid],
      ['Exact published commit', request.parameters.new_oid], ['Immutable pack SHA256', request.parameters.pack_sha256],
      ['Pack bytes', request.parameters.pack_size], ['Owner policy SHA256', request.parameters.policy_sha256],
    );
    else rows.push(
      ['Fetch action', 'Acquire this exact object and update only its tracking ref'],
      ['Remote identity', request.parameters.remote_id], ['Remote HTTPS repository', request.parameters.remote_url],
      ['Remote branch', request.parameters.remote_ref], ['Advertised remote object', request.parameters.remote_oid],
      ['Local tracking ref', request.parameters.tracking_ref],
      ['Previous tracking object (all zeros means absent)', request.parameters.old_oid],
      ['Pack SHA256', request.parameters.pack_sha256], ['Pack bytes', request.parameters.pack_size],
      ['Owner policy SHA256', request.parameters.policy_sha256],
    );
    rows.push(['Exact request digest', snapshot.digest]);
    for (const [label, value] of rows) {
      const term = document.createElement('dt'); term.textContent = label;
      const definition = document.createElement('dd'); definition.textContent = canonical(value);
      element('details').append(term, definition);
    }
    reviewed = snapshot; reviewedSource = source;
    element('approve').textContent = 'Sign this exact ' + request.operation;
    element('acknowledge').disabled = false;
    element('status').textContent = 'Review every field. Quoted text uses explicit escapes so invisible characters stay visible.';
    updateApproval();
  } catch (error) { if (current === epoch) element('status').textContent = error.message; }
});
element('approve').addEventListener('click', async event => {
  if (!event.isTrusted || !pair || !reviewed || !element('acknowledge').checked) return;
  if (reviewedSource !== element('proposal').value) { invalidate(); return; }
  const snapshot = reviewed, current = epoch;
  element('approve').disabled = true;
  try {
    const receipt = await signReviewed(pair, snapshot);
    if (current !== epoch || reviewedSource !== element('proposal').value) return;
    element('receipt').value = receipt;
    element('copy').disabled = false;
    element('status').textContent = 'Signed on this device. Copy the receipt back to ChatGPT within five minutes.';
  } catch (error) { element('status').textContent = error.message; updateApproval(); }
});
element('copy').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(element('receipt').value); }
  catch { element('receipt').focus(); element('receipt').select(); element('status').textContent = 'Select and copy the receipt manually.'; }
});
function loadLinkedProposal() {
  const prefix = '#proposal=';
  if (!location.hash.startsWith(prefix)) return;
  invalidate();
  try {
    const encoded = location.hash.slice(prefix.length);
    if (!/^[A-Za-z0-9_-]+$/.test(encoded) || encoded.length > 174764) {
      throw new Error('Invalid proposal link');
    }
    const binary = atob(encoded.replaceAll('-', '+').replaceAll('_', '/'));
    const source = new TextDecoder('utf-8', {fatal: true}).decode(
      Uint8Array.from(binary, character => character.charCodeAt(0)));
    strictParse(source);
    element('proposal').value = source;
    element('status').textContent = 'Proposal loaded from link. Select Review proposal before signing.';
  } catch (error) {
    element('status').textContent = 'Could not load proposal link: ' + error.message;
  } finally {
    // Fragments stay on the device; remove the payload from the address bar.
    history.replaceState(null, '', location.pathname + location.search);
  }
}
window.addEventListener('hashchange', loadLinkedProposal);
loadLinkedProposal();
(async () => {
  try {
    if (!isSecureContext || !crypto.subtle || top !== self) throw new Error('Open the trusted owner page directly in a secure browser window');
    const key = await loadKey();
    if (key) await showKey(key);
    else {
      element('key-status').textContent = 'Set up a new signing key on this device.';
      element('create-key').disabled = false;
    }
  } catch (error) { element('key-status').textContent = error.message; }
})();
