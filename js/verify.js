// Browser verifier for draft-sahu-agent-action-receipts-00 logs.
// No dependencies. Uses WebCrypto Ed25519 and SHA-256.
// Same canonical form, checks, failure reasons and report shape as
// verdock_core.receipts.verify_log in Python.

const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const MAX_SAFE = 9007199254740991n;
const encoder = new TextEncoder();

function hasLoneSurrogate(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (!(n >= 0xdc00 && n <= 0xdfff)) return true;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function compareCodePoints(a, b) {
  const x = Array.from(a);
  const y = Array.from(b);
  const n = Math.min(x.length, y.length);
  for (let i = 0; i < n; i++) {
    const d = x[i].codePointAt(0) - y[i].codePointAt(0);
    if (d !== 0) return d;
  }
  return x.length - y.length;
}

function canonString(s) {
  // JSON.stringify uses the short escapes and lowercase \u00xx for other
  // control characters, the same as Python json.dumps(ensure_ascii=False).
  return JSON.stringify(s);
}

function canon(v) {
  if (v === null) return 'null';
  if (v === true) return 'true';
  if (v === false) return 'false';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'string') return canonString(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  const keys = Object.keys(v).sort(compareCodePoints);
  return '{' + keys.map((k) => canonString(k) + ':' + canon(v[k])).join(',') + '}';
}

export function canonicalBytes(r) {
  const parts = [];
  for (const name of ['step_id', 'action_id', 'params', 'success', 'ts_ms', 'actor', 'prev_hash']) {
    if (!Object.prototype.hasOwnProperty.call(r, name)) continue;
    let encoded;
    if (name === 'actor') {
      encoded = '{' + ['agent', 'user']
        .filter((k) => Object.prototype.hasOwnProperty.call(r.actor, k))
        .map((k) => canonString(k) + ':' + canonString(r.actor[k]))
        .join(',') + '}';
    } else {
      encoded = canon(r[name]);
    }
    parts.push(canonString(name) + ':' + encoded);
  }
  return encoder.encode('{' + parts.join(',') + '}');
}

// Scan number tokens in already valid JSON text. Returns a failure reason or null.
function checkNumbers(text) {
  let nonInteger = false;
  let outOfRange = false;
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      i++;
      while (i < text.length && text[i] !== '"') i += text[i] === '\\' ? 2 : 1;
      i++;
      continue;
    }
    if (c === '-' || (c >= '0' && c <= '9')) {
      let j = i + 1;
      while (j < text.length && /[0-9eE.+-]/.test(text[j])) j++;
      const token = text.slice(i, j);
      if (!/^-?(0|[1-9][0-9]*)$/.test(token)) nonInteger = true;
      else {
        const n = BigInt(token);
        if (n > MAX_SAFE || n < -MAX_SAFE) outOfRange = true;
      }
      i = j;
      continue;
    }
    i++;
  }
  if (nonInteger) return 'non-integer number';
  if (outOfRange) return 'integer out of range';
  return null;
}

function hasSurrogateDeep(v) {
  if (typeof v === 'string') return hasLoneSurrogate(v);
  if (Array.isArray(v)) return v.some(hasSurrogateDeep);
  if (v !== null && typeof v === 'object') {
    return Object.keys(v).some((k) => hasLoneSurrogate(k) || hasSurrogateDeep(v[k]));
  }
  return false;
}

const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function checkMembers(r) {
  for (const name of ['step_id', 'action_id', 'params', 'success', 'ts_ms', 'public_key', 'signature']) {
    if (!has(r, name)) return 'missing member: ' + name;
  }
  for (const name of ['step_id', 'action_id', 'public_key', 'signature']) {
    if (typeof r[name] !== 'string') return 'wrong type: ' + name;
  }
  if (typeof r.success !== 'boolean') return 'wrong type: success';
  if (typeof r.ts_ms !== 'number' || !Number.isInteger(r.ts_ms)) return 'wrong type: ts_ms';
  if (has(r, 'actor')) {
    const a = r.actor;
    if (a === null || typeof a !== 'object' || Array.isArray(a)) return 'wrong type: actor';
    for (const k of Object.keys(a)) {
      if ((k !== 'agent' && k !== 'user') || typeof a[k] !== 'string') return 'wrong type: actor';
    }
  }
  if (has(r, 'prev_hash') && typeof r.prev_hash !== 'string') return 'wrong type: prev_hash';
  return null;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(bytes) {
  return bytesToHex(await crypto.subtle.digest('SHA-256', bytes));
}

async function ed25519Verify(pubHex, message, sigHex) {
  try {
    const key = await crypto.subtle.importKey('raw', hexToBytes(pubHex), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, hexToBytes(sigHex), message);
  } catch (e) {
    return false;
  }
}

async function checkLine(line, index, prevLine, anchor) {
  if (line.length === 0) return ['empty line'];
  if (hasLoneSurrogate(line)) return ['invalid UTF-8'];
  let r;
  try {
    r = JSON.parse(line);
  } catch (e) {
    return ['invalid JSON'];
  }
  const numberProblem = checkNumbers(line);
  if (numberProblem) return [numberProblem];
  if (hasSurrogateDeep(r)) return ['invalid string'];
  if (r === null || typeof r !== 'object' || Array.isArray(r)) return ['not an object'];
  const memberProblem = checkMembers(r);
  if (memberProblem) return [memberProblem];
  const failures = [];
  const pubOk = HEX64.test(r.public_key);
  const sigOk = HEX128.test(r.signature);
  if (!pubOk) failures.push('invalid hex: public_key');
  if (!sigOk) failures.push('invalid hex: signature');
  if (has(r, 'prev_hash') && !HEX64.test(r.prev_hash)) failures.push('invalid hex: prev_hash');
  if (pubOk && sigOk) {
    if (!(await ed25519Verify(r.public_key, canonicalBytes(r), r.signature))) failures.push('signature invalid');
  }
  if (index === 0) {
    if (has(r, 'prev_hash')) failures.push('unexpected prev_hash on first line');
  } else if (!has(r, 'prev_hash')) {
    failures.push('missing prev_hash');
  } else if (r.prev_hash !== (await sha256Hex(encoder.encode(prevLine)))) {
    failures.push('chain break');
  }
  if (pubOk && r.public_key !== anchor) failures.push('untrusted public key');
  return failures;
}

// verifyLog(text, trustAnchorHex) -> {ok, count, failures: [{line, reason}]}
// text is the whole NDJSON log. Line numbers are 1 based. Every line is
// checked and reported; ok is true only when there are no failures.
export async function verifyLog(text, trustAnchorHex) {
  if (typeof text !== 'string') throw new TypeError('text must be a string');
  if (typeof trustAnchorHex !== 'string') throw new TypeError('trust anchor must be a hex string');
  const anchor = trustAnchorHex.trim().toLowerCase();
  if (!HEX64.test(anchor)) throw new TypeError('trust anchor must be 64 hex characters');
  let body = text.endsWith('\n') ? text.slice(0, -1) : text;
  const lines = body === '' ? [] : body.split('\n');
  const failures = [];
  for (let i = 0; i < lines.length; i++) {
    const reasons = await checkLine(lines[i], i, i > 0 ? lines[i - 1] : null, anchor);
    for (const reason of reasons) failures.push({ line: i + 1, reason });
  }
  return { ok: failures.length === 0, count: lines.length, failures };
}
