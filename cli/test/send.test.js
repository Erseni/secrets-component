import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { VaultClient } from '../lib/client.js';
import { CHARSETS, createSendLink, generateValue } from '../lib/send.js';
import { FakeVault, VALID_API_KEY } from './support/fake-vault.js';

let vault;

before(async () => {
    vault = await new FakeVault().start();
});

after(async () => {
    await vault.stop();
});

test('generates 32 letters and digits by default and honours length and charset', () => {
    assert.match(generateValue(), /^[A-Za-z0-9]{32}$/);
    assert.match(generateValue(64, 'hex'), /^[0-9a-f]{64}$/);
    const symbols = generateValue(4096, 'symbols');
    assert.equal(symbols.length, 4096);
    assert.ok([...symbols].every((character) => CHARSETS.symbols.includes(character)));
    assert.throws(() => generateValue(7), /between 8 and 4096/);
    assert.throws(() => generateValue(32, 'emoji'), /Unknown character set/);
});

test('two generated values differ', () => {
    assert.notEqual(generateValue(), generateValue());
});

test('the link opens the value with its label once and keeps the key out of the request', async () => {
    const client = new VaultClient({ server: vault.url });
    const sent = await createSendLink(client, { value: 'correct horse', label: '  DB_PASSWORD  ', ttlSeconds: 600 });

    assert.match(sent.link, new RegExp('^' + vault.url + '/view/[A-Za-z0-9_-]{22}#k=[A-Za-z0-9_-]{43}$'));
    const call = vault.createCalls.at(-1);
    assert.equal(call.path, '/api/secrets');
    assert.equal(call.body.ttl_seconds, 600);
    assert.ok(!JSON.stringify(call.body).includes(new URL(sent.link).hash.slice(3)));
    assert.deepEqual(vault.openLink(sent.link), { label: 'DB_PASSWORD', value: 'correct horse', ttl: 600 });
    assert.equal(vault.openLink(sent.link), null);
});

test('sends with the API key instead of a proof of work', async () => {
    const solvedBefore = vault.powSolved;
    const client = new VaultClient({ server: vault.url, apiKey: VALID_API_KEY });

    await createSendLink(client, { value: 'abc', ttlSeconds: 600 });

    assert.equal(vault.powSolved, solvedBefore);
    assert.equal(vault.createCalls.at(-1).authorization, 'Bearer ' + VALID_API_KEY);
});

test('refuses a lifetime outside the server range before contacting it', async () => {
    const callsBefore = vault.createCalls.length;
    await assert.rejects(createSendLink(new VaultClient({ server: vault.url }), { value: 'abc', ttlSeconds: 30 }), /between 60 and 604800/);
    assert.equal(vault.createCalls.length, callsBefore);
});
