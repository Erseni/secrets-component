import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { Masker } from '../lib/mask.js';
import { readWrittenPaths } from '../lib/state.js';
import { mergeEnvFile, runCommand, writeEnvFile, writeSecretFile } from '../lib/targets.js';

const VALUE = 'Sup3r-Secret_Value+/=';

async function runMasked(argv) {
    const stdout = [];
    const stderr = [];
    const result = await runCommand(argv, new Map([['X', VALUE]]), new Masker([VALUE]), {
        stdin: 'ignore',
        stdout: (chunk) => stdout.push(chunk),
        stderr: (chunk) => stderr.push(chunk),
    });
    return { ...result, stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8') };
}

function assertNothingLeaks(output) {
    for (const leak of [VALUE, Buffer.from(VALUE).toString('base64'), encodeURIComponent(VALUE), Buffer.from(VALUE).toString('hex')]) {
        assert.ok(!output.includes(leak), 'leaked ' + leak + ' in ' + JSON.stringify(output));
    }
}

test('env shows the variable masked', async () => {
    const result = await runMasked(['env']);
    assert.equal(result.exitCode, 0);
    assert.ok(result.stdout.includes('X=***'));
    assertNothingLeaks(result.stdout);
});

test('echo through a shell shows the value masked', async () => {
    const result = await runMasked(['sh', '-c', 'echo "$X"; echo "$X" >&2']);
    assert.equal(result.stdout, '***\n');
    assert.equal(result.stderr, '***\n');
});

test('base64, URL and hex encodings are masked', async () => {
    const result = await runMasked([
        process.execPath,
        '-e',
        'const v = process.env.X; console.log(Buffer.from(v).toString("base64")); console.log(Buffer.from(v + "\\n").toString("base64")); console.log(encodeURIComponent(v)); console.log(Buffer.from(v).toString("hex"));',
    ]);
    assert.equal(result.exitCode, 0);
    assertNothingLeaks(result.stdout);
    assert.equal(result.stdout.split('\n').filter((line) => line.startsWith('***')).length, 4);
});

test('the exit code of the command is passed through', async () => {
    const result = await runMasked(['sh', '-c', 'exit 7']);
    assert.equal(result.exitCode, 7);
});

test('a missing command fails with a clear message', async () => {
    await assert.rejects(runMasked(['vault-ask-no-such-command-7528']), /Command not found/);
});

test('env files keep other lines and replace the requested names', () => {
    const merged = mergeEnvFile('# comment\nKEEP=1\nexport DB_PASSWORD=old\n', new Map([['DB_PASSWORD', 'new value'], ['API_KEY', 'abc']]));
    assert.equal(merged, "# comment\nKEEP=1\nDB_PASSWORD='new value'\nAPI_KEY=abc\n");
});

test('node --env-file reads every written value back unchanged', () => {
    const values = new Map([
        ['REVIEWED', 'ab$cd"ef\\gh'],
        ['SHELL_LIKE', '$(id) `id` ${HOME} \\$X'],
        ['SINGLE_QUOTE', "it's a \"test\" with $HOME"],
        ['ALL_BUT_BACKTICK', 'a\'b"c\\nd'],
        ['MULTI_LINE', '-----BEGIN KEY-----\nline two # not a comment\nNEXT=1\n-----END KEY-----'],
        ['BACKSLASH_BEFORE_BREAK', 'a\\\nb'],
        ['SPACES', '  leading and trailing  '],
        ['HASH', 'pass#word'],
        ['EMPTY', ''],
        ['SAFE', 'abc-123_/:@+=%'],
        ['TRAILING_BACKSLASH', 'ends with\\'],
        ['JSON_LINES', '{\n  "type": "service_account",\n  "key": "a\\nb"\n}'],
        ['LINES_WITH_QUOTES', 'two\nlines "quoted"'],
    ]);
    const directory = mkdtempSync(join(tmpdir(), 'vault-ask-env-'));
    const path = join(directory, '.env');
    writeFileSync(path, mergeEnvFile('KEEP=1\n', values));

    const names = JSON.stringify(['KEEP', ...values.keys()]);
    const read = spawnSync(process.execPath, ['--env-file=' + path, '-e', 'process.stdout.write(JSON.stringify(Object.fromEntries(' + names + '.map((n) => [n, process.env[n] ?? null]))))'], { encoding: 'utf8', env: {} });

    assert.equal(read.status, 0, read.stderr);
    assert.deepEqual(JSON.parse(read.stdout), { KEEP: '1', ...Object.fromEntries(values) });
});

test('a value no env file quoting keeps unchanged is refused before anything is written', () => {
    for (const value of ['a\'b"c`d', 'line\r\nbreak', 'it\'s\\', 'two\nlines\\', 'two\nlines "quoted" `ticked`', 'two\nlines \\n `ticked`']) {
        assert.throws(() => mergeEnvFile('', new Map([['TOKEN', value]])), /The value for TOKEN .*Nothing was written/, JSON.stringify(value));
    }

    const directory = mkdtempSync(join(tmpdir(), 'vault-ask-env-'));
    writeFileSync(join(directory, '.env'), 'KEEP=1\n');
    assert.throws(() => writeEnvFile('.env', new Map([['OK', 'fine'], ['TOKEN', 'a\'b"c`d']]), directory));
    assert.equal(readFileSync(join(directory, '.env'), 'utf8'), 'KEEP=1\n');
});

test('env files and secret files are written with permissions 600 and remembered for the guard', () => {
    const directory = mkdtempSync(join(tmpdir(), 'vault-ask-'));
    const stateHome = mkdtempSync(join(tmpdir(), 'vault-ask-state-'));
    const previous = process.env.XDG_STATE_HOME;
    process.env.XDG_STATE_HOME = stateHome;
    try {
        writeFileSync(join(directory, '.env'), 'OTHER=1\n', { mode: 0o644 });
        const envPath = writeEnvFile('.env', new Map([['TOKEN', 'abc']]), directory);
        const filePath = writeSecretFile('key.pem', '-----BEGIN-----\n', directory);

        assert.equal(statSync(envPath).mode & 0o777, 0o600);
        assert.equal(statSync(filePath).mode & 0o777, 0o600);
        assert.equal(readFileSync(envPath, 'utf8'), 'OTHER=1\nTOKEN=abc\n');
        assert.equal(readFileSync(filePath, 'utf8'), '-----BEGIN-----\n');
        assert.deepEqual(readWrittenPaths().sort(), [envPath, filePath].sort());
    } finally {
        if (previous === undefined) {
            delete process.env.XDG_STATE_HOME;
        } else {
            process.env.XDG_STATE_HOME = previous;
        }
    }
});

test('a command killed by a signal outside the common ones reports 128 plus its number', async () => {
    const result = await runMasked(['sh', '-c', 'kill -SEGV $$']);
    assert.equal(result.exitCode, 139);
    assert.equal(result.signal, 'SIGSEGV');
});
