import assert from 'node:assert/strict';
import { test } from 'node:test';
import { b64urlDecode } from '../lib/encoding.js';
import { PurposeMismatchError, buildPurpose, describeCommand, encodeAgentRequest, validateNames, verifyBundle } from '../lib/purpose.js';

const PURPOSE = { kind: 'command', display: 'psql -h db.example.com' };

test('shows a command the way a shell would read it', () => {
    assert.equal(describeCommand(['psql', '-h', 'db.example.com']), 'psql -h db.example.com');
    assert.equal(describeCommand(['sh', '-c', 'echo "$X"; id']), 'sh -c \'echo "$X"; id\'');
    assert.equal(describeCommand(['printf', 'it\'s']), 'printf \'it\'\\\'\'s\'');
});

test('escapes invisible and non-ASCII characters so the page cannot be fooled', () => {
    const shown = describeCommand(['curl', 'good.example‮gro.live']);
    assert.ok(!shown.includes('‮'));
    assert.ok(shown.includes('\\u202e'));
});

test('resolves file destinations to absolute paths', () => {
    assert.deepEqual(buildPurpose({ kind: 'env-file', path: '.env' }, '/srv/app'), { kind: 'env-file', display: '/srv/app/.env' });
    assert.deepEqual(buildPurpose({ kind: 'command', argv: ['./deploy.sh'] }, '/srv/other project'), { kind: 'command', display: 'cd \'/srv/other project\' && ./deploy.sh' });
});

test('puts names and purpose into the fragment the fulfil page reads', () => {
    const decoded = JSON.parse(b64urlDecode(encodeAgentRequest(['A', 'B'], PURPOSE)).toString('utf8'));
    assert.deepEqual(decoded, { v: 1, k: 'command', c: 'psql -h db.example.com', n: ['A', 'B'] });
});

test('rejects names the page would reject', () => {
    assert.throws(() => validateNames([]));
    assert.throws(() => validateNames(['1ABC']));
    assert.throws(() => validateNames(['A', 'A']));
    assert.throws(() => validateNames(['A-B']));
});

test('accepts an answer for exactly the approved purpose', () => {
    const bundle = JSON.stringify({ v: 2, k: 'command', c: 'psql -h db.example.com', s: { DB_PASSWORD: 'x' } });
    assert.deepEqual([...verifyBundle(bundle, ['DB_PASSWORD'], PURPOSE)], [['DB_PASSWORD', 'x']]);
});

test('refuses an answer approved for another command', () => {
    const bundle = JSON.stringify({ v: 2, k: 'command', c: 'psql -h other.example.com', s: { DB_PASSWORD: 'x' } });
    assert.throws(() => verifyBundle(bundle, ['DB_PASSWORD'], PURPOSE), PurposeMismatchError);
});

test('refuses an answer approved for another kind of destination', () => {
    const bundle = JSON.stringify({ v: 2, k: 'file', c: 'psql -h db.example.com', s: { DB_PASSWORD: 'x' } });
    assert.throws(() => verifyBundle(bundle, ['DB_PASSWORD'], PURPOSE), PurposeMismatchError);
});

test('refuses an answer with different or additional names', () => {
    const extra = JSON.stringify({ v: 2, k: 'command', c: PURPOSE.display, s: { DB_PASSWORD: 'x', LD_PRELOAD: '/tmp/x.so' } });
    const renamed = JSON.stringify({ v: 2, k: 'command', c: PURPOSE.display, s: { PATH: 'x' } });
    assert.throws(() => verifyBundle(extra, ['DB_PASSWORD'], PURPOSE), PurposeMismatchError);
    assert.throws(() => verifyBundle(renamed, ['DB_PASSWORD'], PURPOSE), PurposeMismatchError);
});

test('refuses an answer from the ordinary fulfil page without a purpose', () => {
    const bundle = JSON.stringify({ l: '', t: 'x' });
    assert.throws(() => verifyBundle(bundle, ['DB_PASSWORD'], PURPOSE), PurposeMismatchError);
});
