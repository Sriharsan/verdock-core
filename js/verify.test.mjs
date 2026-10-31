// Run with: node --test js/verify.test.mjs
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalBytes, verifyLog } from './verify.js';

const PUB = '8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c';
const SIG1 = 'ab6afa750440d38f72dc5601f45b1df918de60049b2accbb438dd909222f42755a534ee67e2eb1397f9d3ca6bd0bf67f1ec078ecc60c08c92438acd2b7dc5802';
const SIG2 = '891dc88a6dc93507faca8d52eceb0baf107f325a1b3bb5c60e3e357cac86d6ccfd2a0bcf3cee3b7237040483fe1b8c4f049fa72c6a59eb97a22d2c7e97d2cc02';
const HASH1 = '18a2a79ac5e4dcc31172783a0f33efc1518d426c5cf0ccd24982d41c9aa3ee4c';
const ACTOR = '"actor":{"agent":"claude-code","user":"alice"}';

const CANON1 = '{"step_id":"01J8Z7QX9K","action_id":"kriya.gate.decision","params":{"class":"publish","rule_id":"npm-publish","tier":"approve"},"success":true,"ts_ms":1755300000000,' + ACTOR + '}';
const CANON2 = '{"step_id":"01J8Z7QXB2","action_id":"kriya.gate.approval","params":{"approver":"alice","decision":"approved","rule_id":"npm-publish"},"success":true,"ts_ms":1755300012000,' + ACTOR + ',"prev_hash":"' + HASH1 + '"}';
const LINE1 = '{"step_id":"01J8Z7QX9K","action_id":"kriya.gate.decision","params":{"rule_id":"npm-publish","tier":"approve","class":"publish"},"success":true,"ts_ms":1755300000000,' + ACTOR + ',"public_key":"' + PUB + '","signature":"' + SIG1 + '"}';
const LINE2 = '{"step_id":"01J8Z7QXB2","action_id":"kriya.gate.approval","params":{"rule_id":"npm-publish","approver":"alice","decision":"approved"},"success":true,"ts_ms":1755300012000,' + ACTOR + ',"prev_hash":"' + HASH1 + '","public_key":"' + PUB + '","signature":"' + SIG2 + '"}';

const decode = (b) => new TextDecoder().decode(b);
const reasons = (report) => report.failures.map((f) => [f.line, f.reason]);
const log = (...lines) => lines.map((l) => l + '\n').join('');

test('vector 1 canonical bytes and hash', () => {
  assert.equal(decode(canonicalBytes(JSON.parse(LINE1))), CANON1);
  assert.equal(createHash('sha256').update(LINE1).digest('hex'), HASH1);
});

test('vector 2 canonical bytes', () => {
  assert.equal(decode(canonicalBytes(JSON.parse(LINE2))), CANON2);
});

test('vectors 1 and 2 verify', async () => {
  assert.deepEqual(await verifyLog(log(LINE1, LINE2), PUB), { ok: true, count: 2, failures: [] });
  assert.deepEqual(await verifyLog(LINE1 + '\n' + LINE2, PUB), { ok: true, count: 2, failures: [] });
});

test('vector 3: alice to mallory', async () => {
  const tampered = LINE1.replace('"user":"alice"', '"user":"mallory"');
  const report = await verifyLog(log(tampered, LINE2), PUB);
  assert.equal(report.ok, false);
  assert.deepEqual(reasons(report), [[1, 'signature invalid'], [2, 'chain break']]);
});

test('edit, delete, insert, reorder', async () => {
  const edited = LINE2.replace('"decision":"approved"', '"decision":"denied"');
  assert.deepEqual(reasons(await verifyLog(log(LINE1, edited), PUB)), [[2, 'signature invalid']]);
  assert.deepEqual(reasons(await verifyLog(log(LINE2), PUB)), [[1, 'unexpected prev_hash on first line']]);
  assert.deepEqual(reasons(await verifyLog(log(LINE1, LINE1, LINE2), PUB)),
    [[2, 'missing prev_hash']]);
  const forged = '{"step_id":"x","action_id":"y","params":{},"success":true,"ts_ms":1,"public_key":"' + PUB + '","signature":"' + SIG1 + '"}';
  assert.deepEqual(reasons(await verifyLog(log(LINE1, forged, LINE2), PUB)),
    [[2, 'signature invalid'], [2, 'missing prev_hash'], [3, 'chain break']]);
  assert.deepEqual(reasons(await verifyLog(log(LINE2, LINE1), PUB)),
    [[1, 'unexpected prev_hash on first line'], [2, 'missing prev_hash']]);
});

test('wrong trust anchor', async () => {
  const other = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
  assert.deepEqual(reasons(await verifyLog(log(LINE1, LINE2), other)),
    [[1, 'untrusted public key'], [2, 'untrusted public key']]);
  await assert.rejects(verifyLog(log(LINE1), 'abc'), TypeError);
});

test('unsigned junk and malformed lines are reported, not skipped', async () => {
  assert.deepEqual(reasons(await verifyLog(log(LINE1, 'junk', LINE2), PUB)),
    [[2, 'invalid JSON'], [3, 'chain break']]);
  const unsigned = JSON.stringify({ ...JSON.parse(LINE2), signature: undefined });
  assert.deepEqual(reasons(await verifyLog(log(LINE1, unsigned), PUB)), [[2, 'missing member: signature']]);
  assert.deepEqual(reasons(await verifyLog(log(LINE1, '', LINE2), PUB)), [[2, 'empty line'], [3, 'chain break']]);
  assert.deepEqual(reasons(await verifyLog(log('[1]'), PUB)), [[1, 'not an object']]);
  assert.deepEqual(reasons(await verifyLog(log(LINE1.replace('1755300000000', '1755300000000.0')), PUB)),
    [[1, 'non-integer number']]);
  assert.deepEqual(reasons(await verifyLog(log(LINE1.replace('1755300000000', '17553000000000000000')), PUB)),
    [[1, 'integer out of range']]);
  assert.deepEqual(reasons(await verifyLog(log(LINE1.replace('"success":true', '"success":"true"')), PUB)),
    [[1, 'wrong type: success']]);
  assert.deepEqual(reasons(await verifyLog(log(LINE1.replace(PUB, PUB.toUpperCase())), PUB)),
    [[1, 'invalid hex: public_key']]);
  assert.deepEqual(await verifyLog('', PUB), { ok: true, count: 0, failures: [] });
});

test('code point key order and escapes', () => {
  const r = { step_id: 's', action_id: 'a', params: { '\u{1F600}': 1, '\uff61': 2, 'a\nb': '\u0001\u00e9"\\/' }, success: false, ts_ms: 0 };
  assert.equal(decode(canonicalBytes(r)),
    '{"step_id":"s","action_id":"a","params":{"a\\nb":"\\u0001\u00e9\\"\\\\/","\uff61":2,"\u{1F600}":1},"success":false,"ts_ms":0}');
});
