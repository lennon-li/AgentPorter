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
    if (request.parameters.workspace_identity) {
      const p = request.parameters;
      rows.push(['Canonical parent workspace', p.workspace_identity.path],
        ['Parent device', p.workspace_identity.device], ['Parent inode', p.workspace_identity.inode],
        ['Selected repository within project', p.repository_relative]);
    }
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
    else if (request.operation === 'clone') {
      const p = request.parameters, job = p.job_context;
      rows.push(['Clone action', 'Create this exact new child repository within the identified parent workspace'],
        ['Canonical parent workspace', request.repository_path], ['Parent device', request.repository_device],
        ['Parent inode', request.repository_inode], ['New repository within parent', p.repository],
        ['Target precondition', p.target_before], ['Pinned private candidate', p.private_candidate],
        ['Remote identity', p.remote_id], ['Remote HTTPS repository', p.remote_url],
        ['Remote branch', p.remote_ref], ['Exact remote commit', p.remote_oid], ['Git object format', p.object_format],
        ['Local branch', p.local_branch], ['Exact tracking ref', p.tracking_ref],
        ['Exact fetchspec', '+' + p.remote_ref + ':' + p.tracking_ref],
        ['Pack SHA256', p.pack_sha256], ['Pack bytes', p.pack_size], ['Owner policy SHA256', p.policy_sha256],
        ['Worker job', job.job_id], ['Worker agent', job.agent], ['Original job admission token', job.admission_token],
        ['Parent private transaction', job.transaction_directory], ['Transaction device', job.transaction_device],
        ['Transaction inode', job.transaction_inode]);
    }
    else if (request.operation === 'pull') {
      const p = request.parameters;
      rows.push(
        ['Pull action', 'Acquire the exact remote commit and integrate it into this workspace'],
        ['Integration mode', p.mode], ['Git object format', p.object_format],
        ['Remote identity', p.remote_id], ['Remote HTTPS repository', p.remote_url],
        ['Remote branch', p.remote_ref], ['Exact remote commit', p.remote_oid],
        ['Local tracking ref', p.tracking_ref], ['Previous tracking object (all zeros means absent)', p.old_oid],
        ['New tracking object', p.new_oid], ['Pack SHA256', p.pack_sha256], ['Pack bytes', p.pack_size],
        ['Owner policy SHA256', p.policy_sha256], ['Git metadata device', p.metadata_device],
        ['Git metadata inode', p.metadata_inode],
      );
      if (p.job_context) {
        const job = p.job_context;
        rows.push(['Worker job', job.job_id], ['Worker agent', job.agent],
          ['Job admission token', job.admission_token], ['Private transaction', job.transaction_directory],
          ['Transaction device', job.transaction_device], ['Transaction inode', job.transaction_inode]);
      } else rows.push(['Execution scope', 'Direct workspace pull; no delegated worker job']);
      rows.push(['Private candidate baseline', p.private_state], ['Canonical workspace baseline', p.canonical_state]);
    }
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
