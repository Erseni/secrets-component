import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { after, before, test } from 'node:test';
import { FakeVault, VALID_API_KEY } from './support/fake-vault.js';
import { CLI, startCli } from './support/run-cli.js';

const VALUE = 'correct-horse-battery-staple-7528';
let vault;
let stateHome;

before(async () => {
    vault = await new FakeVault().start();
    stateHome = mkdtempSync(join(tmpdir(), 'vault-ask-cli-state-'));
});

after(async () => {
    await vault.stop();
});

function env(extra = {}) {
    return { VAULT_ASK_SERVER: vault.url, XDG_STATE_HOME: stateHome, ...extra };
}

test('passes the value to the command, masks its output and never prints it', async () => {
    const cli = startCli(['DB_PASSWORD', '--', process.execPath, '-e', 'console.log("got " + process.env.DB_PASSWORD); console.error(Buffer.from(process.env.DB_PASSWORD).toString("base64"))'], { env: env() });
    const link = await cli.link();
    const agentRequest = vault.fulfillFromLink(link, { DB_PASSWORD: VALUE });
    const result = await cli.exited;

    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(agentRequest.n, ['DB_PASSWORD']);
    assert.equal(agentRequest.k, 'command');
    assert.ok(agentRequest.c.includes(' -e '));
    assert.equal(result.stdout, 'got ***\n');
    assert.ok(result.stderr.includes('DB_PASSWORD received, ' + VALUE.length + ' characters, passed to the command'));
    assert.ok(!result.stderr.includes(VALUE));
    assert.ok(!result.stderr.includes(Buffer.from(VALUE).toString('base64')));
    assert.equal(vault.powSolved, 1);
});

test('refuses an answer that was approved for a different command and runs nothing', async () => {
    const marker = join(mkdtempSync(join(tmpdir(), 'vault-ask-marker-')), 'ran');
    const cli = startCli(['DB_PASSWORD', '--', 'touch', marker], { env: env() });
    const link = await cli.link();
    vault.fulfillFromLink(link, { DB_PASSWORD: VALUE }, { purpose: 'psql -h db.example.com' });
    const result = await cli.exited;

    assert.equal(result.code, 1);
    assert.ok(result.stderr.includes('different purpose'));
    assert.equal(existsSync(marker), false);
    assert.ok(!result.stderr.includes(VALUE));
});

test('writes several values into an env file with permissions 600', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'vault-ask-envfile-'));
    const cli = startCli(['API_KEY', 'API_SECRET', '--env-file', '.env'], { env: env(), cwd: directory });
    const link = await cli.link();
    const agentRequest = vault.fulfillFromLink(link, { API_KEY: 'key-123456', API_SECRET: 'secret with spaces' });
    const result = await cli.exited;

    assert.equal(result.code, 0, result.stderr);
    assert.equal(agentRequest.k, 'env-file');
    assert.equal(agentRequest.c, join(directory, '.env'));
    assert.equal(readFileSync(join(directory, '.env'), 'utf8'), "API_KEY=key-123456\nAPI_SECRET='secret with spaces'\n");
    assert.equal(statSync(join(directory, '.env')).mode & 0o777, 0o600);
    assert.ok(!result.stderr.includes('key-123456'));
    assert.ok(result.stderr.includes('vault-ask: API_KEY received, 10 characters'));
    assert.ok(result.stderr.includes('vault-ask: API_SECRET received, 18 characters'));
});

test('uses the API key instead of a proof of work', async () => {
    const solvedBefore = vault.powSolved;
    const cli = startCli(['TOKEN', '--', 'true'], { env: env({ VAULT_ASK_API_KEY: VALID_API_KEY }) });
    const link = await cli.link();
    vault.fulfillFromLink(link, { TOKEN: 'abc' });
    const result = await cli.exited;

    assert.equal(result.code, 0, result.stderr);
    assert.equal(vault.powSolved, solvedBefore);
    assert.equal(vault.createCalls.at(-1).authorization, 'Bearer ' + VALID_API_KEY);
});

test('stops with a clear message when the API key is rejected', async () => {
    const result = await startCli(['TOKEN', '--', 'true'], { env: env({ VAULT_ASK_API_KEY: 'vak_wrong' }) }).exited;

    assert.equal(result.code, 1);
    assert.ok(result.stderr.includes('API key was rejected'));
});

test('refuses to run without a destination', async () => {
    const result = await startCli(['TOKEN'], { env: env() }).exited;

    assert.equal(result.code, 2);
    assert.ok(result.stderr.includes('Choose a destination'));
});

test('still notices the answer when the live stream is unavailable', async () => {
    const offline = await new FakeVault({ sseAvailable: false }).start();
    try {
        const cli = startCli(['TOKEN', '--', 'true'], { env: { VAULT_ASK_SERVER: offline.url, XDG_STATE_HOME: stateHome } });
        const link = await cli.link();
        await cli.stderrContains('status stream interrupted (validate responded 502)');
        offline.fulfillFromLink(link, { TOKEN: 'abc' });
        const result = await cli.exited;

        assert.equal(result.code, 0, result.stderr);
    } finally {
        await offline.stop();
    }
});

function sentLink(stderr) {
    return stderr.split('\n').find((line) => line.includes('/view/')).trim();
}

test('send writes the generated value into the env file and the same value into the link', async () => {
    const directory = mkdtempSync(join(tmpdir(), 'vault-ask-send-'));
    const result = await startCli(['send', 'DB_PASSWORD', '--env-file', '.env'], { env: env(), cwd: directory }).exited;

    assert.equal(result.code, 0, result.stderr);
    const opened = vault.openLink(sentLink(result.stderr));
    assert.match(opened.value, /^[A-Za-z0-9]{32}$/);
    assert.equal(opened.label, 'DB_PASSWORD');
    assert.equal(opened.ttl, 86400);
    assert.equal(readFileSync(join(directory, '.env'), 'utf8'), 'DB_PASSWORD=' + opened.value + '\n');
    assert.equal(statSync(join(directory, '.env')).mode & 0o777, 0o600);
    assert.ok(!result.stderr.includes(opened.value));
    assert.equal(result.stdout, '');
    assert.ok(result.stderr.includes('DB_PASSWORD, 32 characters, also written to ' + join(directory, '.env')));
});

test('send passes the same value to the command and masks it there', async () => {
    const result = await startCli(['send', 'TOKEN', '--length', '40', '--', process.execPath, '-e', 'console.log("token=" + process.env.TOKEN)'], { env: env() }).exited;

    assert.equal(result.code, 0, result.stderr);
    const opened = vault.openLink(sentLink(result.stderr));
    assert.equal(opened.value.length, 40);
    assert.equal(result.stdout, 'token=***\n');
    assert.ok(!result.stderr.includes(opened.value));
});

test('send passes the exit code of a failed command through and still prints the link', async () => {
    const result = await startCli(['send', 'TOKEN', '--', process.execPath, '-e', 'process.exit(3)'], { env: env() }).exited;

    assert.equal(result.code, 3, result.stderr);
    assert.ok(result.stderr.includes('the command exited with 3'));
    const opened = vault.openLink(sentLink(result.stderr));
    assert.equal(opened.label, 'TOKEN');
    assert.ok(!result.stderr.includes(opened.value));
});

test('send takes an existing value from the environment and only reports its length', async () => {
    const result = await startCli(['send', '--from-env', 'EXISTING', '--label', 'Staging key'], { env: env({ EXISTING: VALUE }) }).exited;

    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(vault.openLink(sentLink(result.stderr)), { label: 'Staging key', value: VALUE, ttl: 86400 });
    assert.ok(result.stderr.includes(VALUE.length + ' characters, only in the link'));
    assert.ok(!result.stderr.includes(VALUE));
});

test('send refuses an env file without a name before anything is created', async () => {
    const callsBefore = vault.createCalls.length;
    const result = await startCli(['send', '--env-file', '.env'], { env: env() }).exited;

    assert.equal(result.code, 2);
    assert.ok(result.stderr.includes('Name the value'));
    assert.equal(vault.createCalls.length, callsBefore);
});

test('mcp serves the MCP tools over stdio, so npx @erseni/vault-ask mcp starts the server', async () => {
    const child = spawn(CLI, ['mcp'], { env: { ...process.env, ...env(), VAULT_ASK_API_KEY: '' }, stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    child.stdout.on('data', (chunk) => {
        stdout += chunk;
    });
    const exited = new Promise((resolveExit) => child.on('close', resolveExit));
    child.stdin.write(JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'test', version: '0' } } }) + '\n');
    child.stdin.end(JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }) + '\n');
    const code = await exited;

    const responses = stdout.trim().split('\n').map((line) => JSON.parse(line));
    assert.equal(code, 0);
    assert.equal(responses.find((response) => response.id === 1).result.serverInfo.name, 'vault-ask');
    assert.deepEqual(responses.find((response) => response.id === 2).result.tools.map((tool) => tool.name), ['request_secret', 'run_with_secret', 'send_secret']);
});
