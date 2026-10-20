import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { VaultClient } from '../lib/client.js';
import { VaultAskMcpServer } from '../lib/mcp.js';
import { FakeVault, VALID_API_KEY } from './support/fake-vault.js';

const VALUE = 'mcp-secret-value-7528';
let vault;
let server;
let workDirectory;

before(async () => {
    vault = await new FakeVault().start();
    workDirectory = mkdtempSync(join(tmpdir(), 'vault-ask-mcp-'));
    process.env.XDG_STATE_HOME = mkdtempSync(join(tmpdir(), 'vault-ask-mcp-state-'));
    server = new VaultAskMcpServer({ client: new VaultClient({ server: vault.url, apiKey: VALID_API_KEY }), cwd: workDirectory, waitMs: 2000 });
});

after(async () => {
    await vault.stop();
});

async function call(name, args) {
    const response = await server.handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: name, arguments: args } });
    return { text: response.result.content[0].text, isError: response.result.isError };
}

function extract(text) {
    return {
        link: text.split('\n').find((line) => line.includes('/fulfill/')),
        requestId: /request_id "([^"]+)"/.exec(text)[1],
    };
}

test('answers initialize and lists all three tools', async () => {
    const init = await server.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
    const list = await server.handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' });

    assert.equal(init.result.serverInfo.name, 'vault-ask');
    assert.deepEqual(list.result.tools.map((tool) => tool.name), ['request_secret', 'run_with_secret', 'send_secret']);
});

test('run_with_secret returns the link first and the masked output on the second call', async () => {
    const first = await call('run_with_secret', { names: ['TOKEN'], command: [process.execPath, '-e', 'console.log("token=" + process.env.TOKEN)'] });
    const { link, requestId } = extract(first.text);
    assert.equal(first.isError, false);
    assert.ok(link.startsWith(vault.url + '/fulfill/'));

    vault.fulfillFromLink(link, { TOKEN: VALUE });
    const second = await call('run_with_secret', { request_id: requestId });

    assert.equal(second.isError, false, second.text);
    assert.ok(second.text.includes('exit code: 0'));
    assert.ok(second.text.includes('token=***'));
    assert.ok(!second.text.includes(VALUE));
});

test('the second call cannot change the command that was shown', async () => {
    const first = await call('run_with_secret', { names: ['TOKEN'], command: ['true'] });
    const { link, requestId } = extract(first.text);
    vault.fulfillFromLink(link, { TOKEN: VALUE });

    const second = await call('run_with_secret', { request_id: requestId, command: ['env'] });

    assert.equal(second.isError, false, second.text);
    assert.ok(!second.text.includes(VALUE));
    assert.ok(!second.text.includes('TOKEN=***'));
});

test('request_secret writes the file and only reports the length', async () => {
    const first = await call('request_secret', { names: ['CERT'], file: 'cert.pem' });
    const { link, requestId } = extract(first.text);
    vault.fulfillFromLink(link, { CERT: VALUE });

    const second = await call('request_secret', { request_id: requestId });

    assert.equal(second.isError, false, second.text);
    assert.ok(second.text.includes('CERT received, ' + VALUE.length + ' characters'));
    assert.ok(!second.text.includes(VALUE));
    assert.equal(readFileSync(join(workDirectory, 'cert.pem'), 'utf8'), VALUE);
    assert.equal(statSync(join(workDirectory, 'cert.pem')).mode & 0o777, 0o600);
});

test('tells the agent to call again while the user has not answered', async () => {
    const first = await call('request_secret', { names: ['LATER'], env_file: '.env' });
    const { requestId } = extract(first.text);

    const second = await call('request_secret', { request_id: requestId });

    assert.equal(second.isError, false);
    assert.ok(second.text.includes('has not answered yet'));
});

test('rejects an unknown request id', async () => {
    const result = await call('run_with_secret', { request_id: 'unknown' });
    assert.equal(result.isError, true);
});

test('the initialize answer tells the agent when to use which tool before any tool is loaded', async () => {
    const init = await server.handle({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18' } });
    const instructions = init.result.instructions;

    assert.equal(typeof instructions, 'string');
    assert.ok(instructions.includes('generate a password'));
    assert.ok(instructions.includes('call send_secret'));
    assert.ok(instructions.includes('call request_secret'));
    assert.ok(instructions.includes('Never ask the user to type or paste a secret into the chat'));
});

test('every tool description starts with when to use it', async () => {
    const list = await server.handle({ jsonrpc: '2.0', id: 2, method: 'tools/list' });

    for (const tool of list.result.tools) {
        assert.ok(tool.description.startsWith('Use this whenever'), tool.name);
    }
});

function sentLink(text) {
    return text.split('\n').find((line) => line.includes('/view/'));
}

test('send_secret returns only the link and writes the same value into the env file', async () => {
    const result = await call('send_secret', { name: 'DB_PASSWORD', env_file: 'send.env' });

    assert.equal(result.isError, false, result.text);
    const opened = vault.openLink(sentLink(result.text));
    assert.match(opened.value, /^[A-Za-z0-9]{32}$/);
    assert.equal(readFileSync(join(workDirectory, 'send.env'), 'utf8'), 'DB_PASSWORD=' + opened.value + '\n');
    assert.ok(!result.text.includes(opened.value));
    assert.ok(result.text.includes('DB_PASSWORD, 32 characters, also written to'));
    assert.equal(vault.createCalls.at(-1).authorization, 'Bearer ' + VALID_API_KEY);
});

test('send_secret without a destination keeps the value only in the link', async () => {
    const result = await call('send_secret', { length: 20, charset: 'hex', label: 'Router admin' });

    assert.equal(result.isError, false, result.text);
    const opened = vault.openLink(sentLink(result.text));
    assert.match(opened.value, /^[0-9a-f]{20}$/);
    assert.equal(opened.label, 'Router admin');
    assert.ok(!result.text.includes(opened.value));
});

test('send_secret reports a failed command and masks the value in its output', async () => {
    const result = await call('send_secret', { name: 'PW', command: [process.execPath, '-e', 'console.error("pw=" + process.env.PW); process.exit(3)'] });

    assert.equal(result.isError, true);
    const opened = vault.openLink(sentLink(result.text));
    assert.ok(result.text.includes('exit code: 3'));
    assert.ok(result.text.includes('pw=***'));
    assert.ok(result.text.includes('may not have applied'));
    assert.ok(!result.text.includes(opened.value));
});

test('send_secret refuses two destinations before anything is created', async () => {
    const callsBefore = vault.createCalls.length;
    const result = await call('send_secret', { name: 'X', env_file: '.env', file: 'x' });

    assert.equal(result.isError, true);
    assert.equal(vault.createCalls.length, callsBefore);
});
