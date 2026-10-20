import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { evaluate } from '../lib/guard.js';

const WRITTEN = ['/srv/app/.env', '/srv/app/certs/server.key'];
const GUARD = join(dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'vault-ask-guard.js');

function bash(command, cwd = '/srv/app') {
    return evaluate({ tool_name: 'Bash', tool_input: { command: command }, cwd: cwd }, WRITTEN);
}

test('blocks vault-ask with a command that only prints the value', () => {
    for (const command of ['vault-ask X -- env', 'vault-ask X -- printenv X', 'vault-ask X -- echo "$X"', 'vault-ask X -- sh -c "echo $X"', 'vault-ask X -- /bin/bash -c env', 'npx vault-ask X -- sudo env', 'vault-ask X -- sudo -u app printenv', 'vault-ask X -- timeout 5 env', 'vault-ask X -- env -i FOO=1 printenv']) {
        assert.notEqual(bash(command), null, command + ' was allowed');
    }
});

test('allows vault-ask with a real consumer', () => {
    assert.equal(bash('vault-ask DB_PASSWORD -- psql -h db.example.com'), null);
    assert.equal(bash('vault-ask TOKEN --env-file .env'), null);
});

test('blocks reading a written file from the shell, absolute or relative', () => {
    assert.notEqual(bash('cat /srv/app/.env'), null);
    assert.notEqual(bash('cat .env'), null);
    assert.notEqual(bash('grep TOKEN ./.env'), null);
    assert.notEqual(bash('base64 certs/server.key'), null);
});

test('leaves unrelated commands alone', () => {
    assert.equal(bash('cat .env.example'), null);
    assert.equal(bash('ls -la'), null);
});

test('blocks the file tools on written paths', () => {
    assert.notEqual(evaluate({ tool_name: 'Read', tool_input: { file_path: '/srv/app/.env' }, cwd: '/' }, WRITTEN), null);
    assert.notEqual(evaluate({ tool_name: 'Grep', tool_input: { pattern: 'x', path: '/srv/app/certs/server.key' }, cwd: '/' }, WRITTEN), null);
    assert.equal(evaluate({ tool_name: 'Read', tool_input: { file_path: '/srv/app/README.md' }, cwd: '/' }, WRITTEN), null);
});

function project() {
    const root = mkdtempSync(join(tmpdir(), 'vault-ask-guard-project-'));
    mkdirSync(join(root, 'certs'));
    mkdirSync(join(root, 'src'));
    writeFileSync(join(root, '.env'), 'TOKEN=secret\n');
    writeFileSync(join(root, 'certs', 'server.key'), 'key\n');
    writeFileSync(join(root, 'src', 'app.php'), '<?php\n');
    writeFileSync(join(root, 'README.md'), 'readme\n');
    return { root: root, written: [join(root, '.env'), join(root, 'certs', 'server.key')] };
}

test('blocks recursive readers on a directory above a written file', () => {
    const { root, written } = project();
    const commands = [
        'grep -rn TOKEN .',
        'grep -R TOKEN',
        'grep --recursive TOKEN ' + root,
        'rg TOKEN',
        'rg -t php TOKEN',
        'rg TOKEN certs',
        'ag TOKEN .',
        'cd certs && grep -r BEGIN .',
        'cd /tmp && grep -r TOKEN ' + root,
        'find . -type f -exec cat {} +',
        'find . -type f | xargs cat',
        'tar czf /tmp/vault-ask-guard.tgz .',
        'cp -r . /tmp/vault-ask-guard-copy',
        'cat certs/*',
        'head -n 3 .e*',
        'grep TOKEN ../' + basename(root) + '/.env',
        'vault-ask TOKEN --env-file .env && cat .env',
        'timeout 30 grep -rn TOKEN .',
        'nice -n 10 rg TOKEN',
        'sudo -u www-data grep -r TOKEN .',
        'env -i rg TOKEN',
        'rg "vault-ask|TOKEN"',
        'grep -rn -e vault-ask -e TOKEN .',
    ];
    for (const command of commands) {
        assert.notEqual(evaluate({ tool_name: 'Bash', tool_input: { command: command }, cwd: root }, written), null, command + ' was allowed');
    }
});

test('allows searches and globs that do not reach a written file', () => {
    const { root, written } = project();
    for (const command of ['grep -rn TOKEN src', 'rg TOKEN src', 'rg -t php TOKEN src README.md', 'find . -name "*.php"', 'cat *.md', 'grep TOKEN README.md', 'ls -la certs', 'vault-ask TOKEN --env-file .env', 'cp -r src /tmp/vault-ask-guard-src', 'cp -r src .', 'rsync -a src/ .', 'timeout 30 rg TOKEN src']) {
        assert.equal(evaluate({ tool_name: 'Bash', tool_input: { command: command }, cwd: root }, written), null, command + ' was blocked');
    }
});

test('the Grep tool is blocked above a written file unless its glob leaves the file out', () => {
    const { root, written } = project();
    const grep = (toolInput, cwd = root) => evaluate({ tool_name: 'Grep', tool_input: { pattern: 'TOKEN', ...toolInput }, cwd: cwd }, written);

    assert.notEqual(grep({}), null);
    assert.notEqual(grep({ path: root, output_mode: 'content' }), null);
    assert.notEqual(grep({ path: '.', output_mode: 'files_with_matches' }), null);
    assert.notEqual(grep({ path: 'certs' }), null);
    assert.notEqual(grep({ path: dirname(root) }, '/'), null);
    assert.notEqual(grep({ glob: '*' }), null);
    assert.notEqual(grep({ glob: '**/*.key' }), null);
    assert.equal(grep({ path: 'src' }), null);
    assert.equal(grep({ glob: '*.php' }), null);
    assert.equal(grep({ glob: '*.{php,md}' }), null);
    assert.notEqual(grep({ glob: '!*.lock' }), null);
    assert.notEqual(grep({ glob: '.e?v' }), null);
    assert.notEqual(grep({ glob: '[.]env' }), null);
});

test('the Glob tool only lists names and stays allowed on a parent directory', () => {
    const { root, written } = project();
    assert.equal(evaluate({ tool_name: 'Glob', tool_input: { pattern: '**/*', path: root }, cwd: root }, written), null);
});

test('blocks run_with_secret over MCP with a printing command', () => {
    assert.notEqual(evaluate({ tool_name: 'mcp__vault-ask__run_with_secret', tool_input: { command: ['env'] } }, WRITTEN), null);
    assert.equal(evaluate({ tool_name: 'mcp__vault-ask__run_with_secret', tool_input: { command: ['psql'] } }, WRITTEN), null);
});

test('blocks send_secret over MCP and vault-ask send with a printing command', () => {
    assert.notEqual(evaluate({ tool_name: 'mcp__vault-ask__send_secret', tool_input: { name: 'X', command: ['printenv', 'X'] } }, WRITTEN), null);
    assert.equal(evaluate({ tool_name: 'mcp__vault-ask__send_secret', tool_input: { name: 'X', command: ['./set-password'] } }, WRITTEN), null);
    assert.notEqual(evaluate({ tool_name: 'Bash', tool_input: { command: 'vault-ask send X -- sh -c "echo $X"' } }, WRITTEN), null);
});

test('the hook answers in the PreToolUse format and reads the recorded paths', () => {
    const stateHome = mkdtempSync(join(tmpdir(), 'vault-ask-guard-'));
    mkdirSync(join(stateHome, 'vault-ask'), { recursive: true });
    writeFileSync(join(stateHome, 'vault-ask', 'written-paths.json'), JSON.stringify(['/srv/app/.env']));
    const run = (input) => spawnSync(process.execPath, [GUARD], { input: JSON.stringify(input), env: { ...process.env, XDG_STATE_HOME: stateHome }, encoding: 'utf8' });

    const denied = run({ tool_name: 'Read', tool_input: { file_path: '/srv/app/.env' }, cwd: '/srv/app' });
    const allowed = run({ tool_name: 'Read', tool_input: { file_path: '/srv/app/other' }, cwd: '/srv/app' });

    assert.equal(denied.status, 0);
    assert.equal(JSON.parse(denied.stdout).hookSpecificOutput.permissionDecision, 'deny');
    assert.equal(allowed.status, 0);
    assert.equal(allowed.stdout, '');
});
