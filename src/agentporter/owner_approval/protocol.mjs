/* Device-side Ed25519 owner approval. No transport, storage, or DOM access. */
const encoder = new TextEncoder();
const requestDomain = 'AgentPorter Git request v1\0';
const approvalDomain = 'AgentPorter Git owner approval v1\0';

export function canonical(value) {
  if (typeof value === 'bigint') return value.toString();
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value)) throw new Error('Unsafe JSON integer');
    return String(value);
  }
  if (value === null || typeof value === 'boolean') return String(value);
  if (typeof value === 'string') {
    return JSON.stringify(value).replace(/[\u007f-\uffff]/g,
      character => '\\u' + character.charCodeAt(0).toString(16).padStart(4, '0'));
  }
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') {
    return '{' + Object.keys(value).sort().map(key => canonical(key) + ':' + canonical(value[key])).join(',') + '}';
  }
  throw new Error('Unsupported JSON value');
}

export function strictParse(text) {
  if (typeof text !== 'string' || encoder.encode(text).length > 131072) throw new Error('Proposal exceeds size limit');
  let position = 0, nodes = 0;
  const whitespace = () => { while (/[\t\n\r ]/.test(text[position] || '\0')) position++; };
  function string() {
    const start = position++;
    while (position < text.length) {
      const character = text[position++];
      if (character === '"') return JSON.parse(text.slice(start, position));
      if (character === '\\') position++;
    }
    throw new Error('Unterminated JSON string');
  }
  function value(depth) {
    if (++nodes > 4096 || depth > 16) throw new Error('Proposal nesting exceeds limit');
    whitespace();
    const character = text[position];
    if (character === '"') return string();
    if (character === '{' || character === '[') {
      position++;
      const object = character === '{';
      const result = object ? Object.create(null) : [];
      const end = object ? '}' : ']';
      whitespace();
      if (text[position] === end) { position++; return result; }
      while (true) {
        whitespace();
        if (object) {
          if (text[position] !== '"') throw new Error('Expected JSON field');
          const key = string();
          if (Object.hasOwn(result, key)) throw new Error('Duplicate JSON field');
          whitespace();
          if (text[position++] !== ':') throw new Error('Expected JSON separator');
          result[key] = value(depth + 1);
        } else result.push(value(depth + 1));
        whitespace();
        const separator = text[position++];
        if (separator === end) return result;
        if (separator !== ',') throw new Error('Invalid JSON structure');
      }
    }
    for (const [token, result] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(token, position)) { position += token.length; return result; }
    }
    const number = /^-?(?:0|[1-9][0-9]*)/.exec(text.slice(position));
    if (!number) throw new Error('Invalid JSON value');
    position += number[0].length;
    if (/[.eE]/.test(text[position] || '\0')) throw new Error('Only exact integers are supported');
    const integer = BigInt(number[0]);
    return integer <= BigInt(Number.MAX_SAFE_INTEGER) && integer >= BigInt(Number.MIN_SAFE_INTEGER)
      ? Number(integer) : integer;
  }
  const result = value(0);
  whitespace();
  if (position !== text.length) throw new Error('Trailing JSON content');
  return result;
}

function fields(value, names) {
  if (!value || Array.isArray(value) || typeof value !== 'object'
      || Object.keys(value).sort().join('\0') !== [...names].sort().join('\0')) {
    throw new Error('Unexpected proposal fields');
  }
}
function text(value, maximum) {
  return typeof value === 'string' && Array.from(value).length > 0 && Array.from(value).length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}
function integer(value, minimum) {
  return (typeof value === 'bigint' || Number.isSafeInteger(value)) && BigInt(value) >= BigInt(minimum);
}
function absolutePath(value) {
  return text(value, 4096) && value.startsWith('/') && value !== '/' && !value.startsWith('//')
    && value.slice(1).split('/').every(part => !['', '.', '..'].includes(part));
}
function exactBranch(value, nullable = false) {
  return (nullable && value === null) || (text(value, 1024) && encoder.encode(value).length <= 1024
    && value.startsWith('refs/heads/') && !/[\u0000-\u0020\u007f~^:?*\[\\]/.test(value)
    && !value.includes('..') && !value.includes('@{')
    && value.split('/').every(part => part && !part.startsWith('.') && !part.endsWith('.') && !part.endsWith('.lock')));
}
function digest(value) { return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value); }
function repositoryScope(request, names, metadata = false) {
  const p = request.parameters;
  const scoped = Object.hasOwn(p || {}, 'repository_relative') || Object.hasOwn(p || {}, 'workspace_identity');
  if (!scoped) return names;
  const relative = p.repository_relative;
  if (typeof relative !== 'string' || !/^[A-Za-z0-9._/-]{1,256}$/.test(relative)
      || relative.split('/').some(part => ['', '.', '..', '.git', '.venv'].includes(part))) {
    throw new Error('Exact canonical project-relative repository required');
  }
  const parent = p.workspace_identity;
  fields(parent, ['path', 'device', 'inode']);
  if (!absolutePath(parent.path) || !integer(parent.device, 0) || !integer(parent.inode, 1)
      || request.repository_path !== parent.path + '/' + relative) throw new Error('Selected repository differs from canonical parent workspace');
  if (metadata && (!integer(p.metadata_device, 0) || !integer(p.metadata_inode, 1))) throw new Error('Exact selected metadata identity required');
  return [...names, 'repository_relative', 'workspace_identity', ...(metadata ? ['metadata_device', 'metadata_inode'] : [])];
}
function pullParameters(request) {
  const p = request.parameters;
  const names = ['remote_id', 'remote_url', 'remote_ref', 'remote_oid', 'object_format',
    'tracking_ref', 'old_oid', 'new_oid', 'pack_sha256', 'pack_size', 'policy_sha256', 'mode',
    'metadata_device', 'metadata_inode', 'private_state', 'canonical_state'];
  const scopedNames = repositoryScope(request, names);
  fields(p, Object.hasOwn(p || {}, 'job_context') ? [...scopedNames, 'job_context'] : scopedNames);
  if (!['ff-only', 'merge', 'rebase'].includes(p.mode) || !['sha1', 'sha256'].includes(p.object_format)) {
    throw new Error('Exact pull mode and object format required');
  }
  const width = p.object_format === 'sha1' ? 40 : 64;
  const oid = (value, zero = false) => typeof value === 'string'
    && new RegExp('^[0-9a-f]{' + width + '}$').test(value) && (zero || !/^0+$/.test(value));
  if (typeof p.remote_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(p.remote_id)) throw new Error('Invalid remote identity');
  const match = typeof p.remote_url === 'string'
    && /^https:\/\/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)((?:\/[A-Za-z0-9._-]+){1,8}\.git)$/.exec(p.remote_url);
  if (!match || p.remote_url.length > 2048 || !match[1].includes('.') || match[1].includes('..')
      || match[2].split('/').some(part => ['.', '..'].includes(part))) throw new Error('One canonical HTTPS repository is required');
  if (!exactBranch(p.remote_ref) || p.tracking_ref !== 'refs/remotes/' + p.remote_id + '/' + p.remote_ref.slice(11)
      || !oid(p.remote_oid) || p.new_oid !== p.remote_oid || !oid(p.old_oid, true)) {
    throw new Error('Invalid exact pull object and tracking transition');
  }
  if (!digest(p.pack_sha256) || !digest(p.policy_sha256) || !integer(p.pack_size, 1)
      || BigInt(p.pack_size) > BigInt(64 * 1024 * 1024 - 65520)
      || !integer(p.metadata_device, 0) || !integer(p.metadata_inode, 1)) throw new Error('Invalid pull pack or metadata identity');
  for (const name of ['private_state', 'canonical_state']) {
    const state = p[name];
    fields(state, ['head', 'branch', 'tree', 'object_format', 'index_sha256', 'head_sha256',
      'stash_log_sha256', 'worktree_sha256', 'refs_sha256', 'unmerged']);
    if (!oid(state.head) || !exactBranch(state.branch, true) || state.object_format !== p.object_format
        || typeof state.unmerged !== 'boolean' || (state.unmerged ? state.tree !== null : !oid(state.tree))
        || !['index_sha256', 'head_sha256', 'worktree_sha256', 'refs_sha256'].every(key => digest(state[key]))
        || (state.stash_log_sha256 !== null && !digest(state.stash_log_sha256))) throw new Error('Invalid exact pull baseline');
  }
  if (p.private_state.unmerged || p.private_state.head !== request.expected_head
      || p.private_state.tree !== request.expected_tree || p.private_state.branch !== request.branch
      || !exactBranch(request.branch)) throw new Error('Pull private baseline differs from reviewed repository');
  if (Object.hasOwn(p, 'job_context')) {
    const job = p.job_context;
    fields(job, ['job_id', 'agent', 'admission_token', 'transaction_directory', 'transaction_device', 'transaction_inode']);
    if (typeof job.job_id !== 'string' || !/^job_[0-9a-f]{24}$/.test(job.job_id)
        || !['codex_review', 'codex_impl', 'codex_research', 'copilot_agent', 'opencode_free', 'claude_agent', 'agy_agent'].includes(job.agent)
        || typeof job.admission_token !== 'string' || !/^[0-9a-f]{32}$/.test(job.admission_token)
        || !absolutePath(job.transaction_directory) || !integer(job.transaction_device, 0)
        || !integer(job.transaction_inode, 1)) throw new Error('Invalid exact worker job binding');
  }
}
function cloneParameters(request) {
  const p = request.parameters;
  fields(p, ['identity_kind', 'repository', 'target_before', 'private_candidate', 'remote_id', 'remote_url',
    'remote_ref', 'remote_oid', 'object_format', 'tracking_ref', 'local_branch', 'pack_sha256', 'pack_size',
    'policy_sha256', 'job_context']);
  const relative = value => typeof value === 'string' && /^[A-Za-z0-9._/-]{1,256}$/.test(value)
    && value.split('/').every(part => !['', '.', '..', '.git', '.venv'].includes(part));
  if (p.identity_kind !== 'parent_workspace' || !relative(p.repository) || request.expected_head !== null
      || !exactBranch(p.local_branch) || request.branch !== p.local_branch) throw new Error('Clone requires one new child of the identified canonical parent workspace');
  if (!['sha1', 'sha256'].includes(p.object_format)) throw new Error('Unsupported clone object format');
  const width = p.object_format === 'sha1' ? 40 : 64;
  const oid = value => typeof value === 'string' && new RegExp('^[0-9a-f]{' + width + '}$').test(value) && !/^0+$/.test(value);
  const emptyTree = p.object_format === 'sha1' ? '4b825dc642cb6eb9a060e54bf8d69288fbee4904' : '6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321';
  if (!oid(p.remote_oid) || request.expected_tree !== emptyTree) throw new Error('Exact clone graph and empty parent target baseline required');
  if (typeof p.remote_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(p.remote_id)
      || !exactBranch(p.remote_ref) || p.tracking_ref !== 'refs/remotes/' + p.remote_id + '/' + p.remote_ref.slice(11)) throw new Error('Exact clone remote and tracking ref required');
  const match = typeof p.remote_url === 'string' && /^https:\/\/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)((?:\/[A-Za-z0-9._-]+){1,8}\.git)$/.exec(p.remote_url);
  if (!match || p.remote_url.length > 2048 || !match[1].includes('.') || match[1].includes('..')
      || match[2].split('/').some(part => ['.', '..'].includes(part))) throw new Error('One canonical HTTPS clone repository required');
  if (!digest(p.pack_sha256) || !digest(p.policy_sha256) || !integer(p.pack_size, 1)
      || BigInt(p.pack_size) > BigInt(64 * 1024 * 1024 - 65520)) throw new Error('Bounded exact clone pack required');
  fields(p.private_candidate, ['directory', 'device', 'inode']);
  if (!absolutePath(p.private_candidate.directory) || !integer(p.private_candidate.device, 0)
      || !integer(p.private_candidate.inode, 1)) throw new Error('Pinned private clone candidate required');
  const before = p.target_before;
  if (before.kind === 'absent') {
    fields(before, ['kind', 'first_missing', 'parent_device', 'parent_inode']);
    if (!relative(before.first_missing) || !(p.repository === before.first_missing || p.repository.startsWith(before.first_missing + '/'))
        || !integer(before.parent_device, 0) || !integer(before.parent_inode, 1)) throw new Error('Pinned absent clone target required');
  } else if (before.kind === 'empty') {
    fields(before, ['kind', 'directory']);
    const d = before.directory;
    fields(d, ['identity', 'mode', 'uid', 'gid', 'mtime_ns', 'xattrs']);
    if (!Array.isArray(d.identity) || d.identity.length !== 2 || !integer(d.identity[0], 0) || !integer(d.identity[1], 1)
        || !integer(d.mode, 0) || BigInt(d.mode) > 511n || !integer(d.uid, 0) || !integer(d.gid, 0)
        || !integer(d.mtime_ns, 0) || !d.xattrs || typeof d.xattrs !== 'object' || Array.isArray(d.xattrs)
        || Object.entries(d.xattrs).some(([key, value]) => !text(key, 1024) || typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value))) throw new Error('Exact original empty directory required');
  } else throw new Error('Clone target must be absent or originally empty');
  const job = p.job_context;
  fields(job, ['job_id', 'agent', 'admission_token', 'transaction_directory', 'transaction_device', 'transaction_inode']);
  if (typeof job.job_id !== 'string' || !/^job_[0-9a-f]{24}$/.test(job.job_id)
      || !['codex_review', 'codex_impl', 'codex_research', 'copilot_agent', 'opencode_free', 'claude_agent', 'agy_agent'].includes(job.agent)
      || typeof job.admission_token !== 'string' || !/^[0-9a-f]{32}$/.test(job.admission_token)
      || !absolutePath(job.transaction_directory) || !integer(job.transaction_device, 0) || !integer(job.transaction_inode, 1)
      || !p.private_candidate.directory.startsWith(job.transaction_directory + '/clone-prepare-')) throw new Error('Exact parent clone job and private candidate required');
}

export function hex(bytes) {
  return Array.from(new Uint8Array(bytes), value => value.toString(16).padStart(2, '0')).join('');
}
export async function reviewProposal(source) {
  const proposal = strictParse(source);
  fields(proposal, ['request', 'request_sha256']);
  const request = proposal.request;
  fields(request, ['operation', 'workspace_id', 'repository_path', 'repository_device', 'repository_inode',
    'expected_head', 'expected_tree', 'branch', 'parameters']);
  if (!['commit', 'push', 'fetch', 'pull', 'clone'].includes(request.operation)) throw new Error('Unsupported owner Git action');
  if (!text(request.workspace_id, 256) || request.workspace_id === '*') throw new Error('One workspace is required');
  const path = request.repository_path;
  if (!text(path, 4096) || !path.startsWith('/') || path === '/' || path.startsWith('//')
      || path.slice(1).split('/').some(part => ['', '.', '..'].includes(part))) throw new Error('Invalid repository path');
  if (!integer(request.repository_device, 0) || !integer(request.repository_inode, 1)) throw new Error('Invalid repository identity');
  const oid = value => typeof value === 'string' && /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(value);
  if ((request.expected_head !== null && !oid(request.expected_head)) || !oid(request.expected_tree)) throw new Error('Full Git object IDs required');
  if (!text(request.branch, 1024) || !request.branch.startsWith('refs/heads/')) throw new Error('Explicit local branch required');
  const parameters = request.parameters;
  if (request.operation === 'commit') {
    fields(parameters, ['author_name', 'author_email', 'message', 'timestamp']);
    for (const name of ['author_name', 'author_email']) {
      if (!text(parameters[name], 256) || /[<>]/.test(parameters[name])) throw new Error('Invalid protected author identity');
    }
    if (typeof parameters.message !== 'string' || !parameters.message.trim() || parameters.message.includes('\0')
        || encoder.encode(parameters.message).length > 32768 || !integer(parameters.timestamp, 1)
        || BigInt(parameters.timestamp) >= 2n ** 63n) throw new Error('Invalid commit message or timestamp');
  } else if (request.operation === 'push') {
    fields(parameters, ['remote_id', 'remote_url', 'remote_ref', 'old_oid', 'new_oid',
      'pack_sha256', 'pack_size', 'policy_sha256']);
    if (typeof parameters.remote_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(parameters.remote_id)) throw new Error('Invalid remote identity');
    const url = parameters.remote_url;
    const match = typeof url === 'string' && /^https:\/\/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)((?:\/[A-Za-z0-9._-]+){1,8}\.git)$/.exec(url);
    if (!match || url.length > 2048 || !match[1].includes('.') || match[1].includes('..')
        || match[2].split('/').some(part => ['.', '..'].includes(part))) throw new Error('One canonical HTTPS repository is required');
    const ref = parameters.remote_ref;
    if (!text(ref, 1024) || encoder.encode(ref).length > 1024 || !ref.startsWith('refs/heads/')
        || /[\u0000-\u0020\u007f~^:?*\[\\]/.test(ref) || ref.includes('..') || ref.includes('@{')
        || ref.split('/').some(part => !part || part.startsWith('.') || part.endsWith('.') || part.endsWith('.lock'))) throw new Error('One exact remote branch is required');
    if (!oid(parameters.old_oid) || !oid(parameters.new_oid) || parameters.new_oid !== request.expected_head
        || parameters.new_oid.length !== parameters.old_oid.length || request.expected_tree.length !== parameters.new_oid.length
        || /^0+$/.test(parameters.new_oid) || parameters.old_oid === parameters.new_oid) throw new Error('Invalid exact remote update');
    for (const field of ['pack_sha256', 'policy_sha256']) {
      if (typeof parameters[field] !== 'string' || !/^[0-9a-f]{64}$/.test(parameters[field])) throw new Error('Exact pack and owner policy digests required');
    }
    if (!integer(parameters.pack_size, 1) || BigInt(parameters.pack_size) > BigInt(64 * 1024 * 1024 - 65520)) throw new Error('Invalid publication pack length');
  } else if (request.operation === 'clone') {
    cloneParameters(request);
  } else if (request.operation === 'pull') {
    pullParameters(request);
  } else {
    fields(parameters, repositoryScope(request, ['remote_id', 'remote_url', 'remote_ref', 'remote_oid', 'tracking_ref',
      'old_oid', 'new_oid', 'pack_sha256', 'pack_size', 'policy_sha256'], true));
    if (typeof parameters.remote_id !== 'string' || !/^[A-Za-z0-9_-]{1,128}$/.test(parameters.remote_id)) throw new Error('Invalid remote identity');
    const url = parameters.remote_url;
    const match = typeof url === 'string' && /^https:\/\/([a-z0-9](?:[a-z0-9.-]*[a-z0-9])?)((?:\/[A-Za-z0-9._-]+){1,8}\.git)$/.exec(url);
    if (!match || url.length > 2048 || !match[1].includes('.') || match[1].includes('..')
        || match[2].split('/').some(part => ['.', '..'].includes(part))) throw new Error('One canonical HTTPS repository is required');
    const branch = value => typeof value === 'string' && encoder.encode(value).length <= 1024
      && value.startsWith('refs/heads/') && !/[\u0000-\u0020\u007f~^:?*\[\\]/.test(value)
      && !value.includes('..') && !value.includes('@{')
      && value.split('/').every(part => part && !part.startsWith('.') && !part.endsWith('.') && !part.endsWith('.lock'));
    const trackingPrefix = 'refs/remotes/' + parameters.remote_id + '/';
    if (!branch(parameters.remote_ref) || typeof parameters.tracking_ref !== 'string'
        || !parameters.tracking_ref.startsWith(trackingPrefix)
        || !branch('refs/heads/' + parameters.tracking_ref.slice(trackingPrefix.length))) throw new Error('Exact remote and tracking branches are required');
    if (!oid(parameters.remote_oid) || !oid(parameters.old_oid) || parameters.remote_oid.length !== parameters.old_oid.length
        || !oid(parameters.new_oid) || parameters.new_oid !== parameters.remote_oid
        || parameters.remote_oid.length !== request.expected_head.length
        || parameters.tracking_ref !== trackingPrefix + parameters.remote_ref.slice('refs/heads/'.length)) {
      throw new Error('Invalid exact fetched object and tracking ref');
    }
    for (const field of ['pack_sha256', 'policy_sha256']) {
      if (typeof parameters[field] !== 'string' || !/^[0-9a-f]{64}$/.test(parameters[field])) throw new Error('Exact pack and owner policy digests required');
    }
    if (!integer(parameters.pack_size, 1) || BigInt(parameters.pack_size) > BigInt(64 * 1024 * 1024 - 65520)) throw new Error('Invalid fetch pack length');
  }
  const payload = canonical(request);
  if (encoder.encode(payload).length > 65536) throw new Error('Git request exceeds size limit');
  const digest = hex(await crypto.subtle.digest('SHA-256', encoder.encode(requestDomain + payload)));
  if (proposal.request_sha256 !== digest) throw new Error('Proposal digest does not match its exact contents');
  // Persist a canonical snapshot. Callers cannot mutate the reviewed object.
  return Object.freeze({payload, digest});
}

export async function createDeviceKey() {
  return crypto.subtle.generateKey('Ed25519', false, ['sign', 'verify']);
}
export async function publicKeyHex(pair) {
  if (!pair || pair.privateKey?.type !== 'private' || pair.privateKey.extractable !== false
      || pair.privateKey.algorithm.name !== 'Ed25519' || pair.publicKey?.type !== 'public'
      || pair.publicKey.algorithm.name !== 'Ed25519') throw new Error('Invalid device signing key');
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await crypto.subtle.sign('Ed25519', pair.privateKey, challenge);
  if (!await crypto.subtle.verify('Ed25519', pair.publicKey, signature, challenge)) throw new Error('Device key pair does not match');
  return hex(await crypto.subtle.exportKey('raw', pair.publicKey));
}
export async function signReviewed(pair, reviewed, now = Math.floor(Date.now() / 1000)) {
  await publicKeyHex(pair);
  if (!Number.isSafeInteger(now) || now < 0) throw new Error('Invalid device clock');
  const digest = hex(await crypto.subtle.digest('SHA-256', encoder.encode(requestDomain + reviewed.payload)));
  if (digest !== reviewed.digest) throw new Error('Reviewed request changed');
  const claims = {version: 1, audience: 'agentporter-git',
    nonce: hex(crypto.getRandomValues(new Uint8Array(16))), issued_at: now, expires_at: now + 300,
    request_sha256: digest};
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey,
    encoder.encode(approvalDomain + canonical(claims))));
  const encoded = btoa(String.fromCharCode(...signature)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  return canonical({claims, signature: encoded});
}
