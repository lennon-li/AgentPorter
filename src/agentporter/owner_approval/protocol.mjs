/* Device-side Ed25519 owner approval. No transport, storage, or DOM access. */
const encoder = new TextEncoder();
const requestDomain = 'AgentPorter BCC Git request v1\0';
const approvalDomain = 'AgentPorter BCC Git owner approval v1\0';

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
export function hex(bytes) {
  return Array.from(new Uint8Array(bytes), value => value.toString(16).padStart(2, '0')).join('');
}
export async function reviewProposal(source) {
  const proposal = strictParse(source);
  fields(proposal, ['request', 'request_sha256']);
  const request = proposal.request;
  fields(request, ['operation', 'workspace_id', 'repository_path', 'repository_device', 'repository_inode',
    'expected_head', 'expected_tree', 'branch', 'parameters']);
  if (!['commit', 'push', 'fetch'].includes(request.operation)) throw new Error('This owner interface approves commits, pushes and fetches only');
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
  } else {
    fields(parameters, ['remote_id', 'remote_url', 'remote_ref', 'remote_oid', 'tracking_ref',
      'old_oid', 'new_oid', 'pack_sha256', 'pack_size', 'policy_sha256']);
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
  const claims = {version: 1, audience: 'agentporter-bcc-git',
    nonce: hex(crypto.getRandomValues(new Uint8Array(16))), issued_at: now, expires_at: now + 300,
    request_sha256: digest};
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', pair.privateKey,
    encoder.encode(approvalDomain + canonical(claims))));
  const encoded = btoa(String.fromCharCode(...signature)).replaceAll('+', '-').replaceAll('/', '_').replace(/=+$/, '');
  return canonical({claims, signature: encoded});
}
