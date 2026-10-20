import { spawn } from 'node:child_process';
import { chmodSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { constants } from 'node:os';
import { recordWrittenPath } from './state.js';

const SAFE_ENV_VALUE = /^[A-Za-z0-9_\-.,:/@+=%]*$/;
const SIGNALS = ['SIGINT', 'SIGTERM', 'SIGHUP'];

function writeAtomically(path, content) {
    const temporary = join(dirname(path), '.' + basename(path) + '.vault-ask-' + process.pid + '.tmp');
    writeFileSync(temporary, content, { mode: 0o600 });
    chmodSync(temporary, 0o600);
    renameSync(temporary, path);
    chmodSync(path, 0o600);
}

function unwritableEnvValue(name, reason) {
    return new Error('The value for ' + name + ' ' + reason + ', so node --env-file and dotenv would not read it back unchanged. Nothing was written. Request it again with --file or -- <command>');
}

export function formatEnvValue(value, name) {
    if (SAFE_ENV_VALUE.test(value)) {
        return value;
    }
    if (value.includes('\r')) {
        throw unwritableEnvValue(name, 'contains a carriage return');
    }
    const endsWithBackslash = value.endsWith('\\');
    if (endsWithBackslash && (value.includes("'") || value.includes('\n'))) {
        throw unwritableEnvValue(name, 'ends with a backslash and contains single quotes or several lines');
    }
    const fitsDoubleQuotes = !value.includes('"') && !/\\[nr]/.test(value) && !endsWithBackslash;
    if (value.includes('\n')) {
        if (fitsDoubleQuotes) {
            return '"' + value.replace(/\n/g, '\\n') + '"';
        }
        if (!value.includes('`')) {
            return '`' + value + '`';
        }
        throw unwritableEnvValue(name, 'has several lines and contains backticks together with double quotes or a written \\n');
    }
    if (!value.includes("'")) {
        return "'" + value + "'";
    }
    if (fitsDoubleQuotes) {
        return '"' + value + '"';
    }
    if (!value.includes('`')) {
        return '`' + value + '`';
    }
    throw unwritableEnvValue(name, 'contains single quotes, double quotes and backticks');
}

export function mergeEnvFile(existing, values) {
    const lines = existing === '' ? [] : existing.replace(/\n$/, '').split('\n');
    const pending = new Map(values);
    const merged = lines.map((line) => {
        const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
        if (match && pending.has(match[1])) {
            const name = match[1];
            const replacement = name + '=' + formatEnvValue(pending.get(name), name);
            pending.delete(name);
            return replacement;
        }
        return line;
    });
    for (const [name, value] of pending) {
        merged.push(name + '=' + formatEnvValue(value, name));
    }
    return merged.join('\n') + '\n';
}

export function writeEnvFile(path, values, cwd = process.cwd()) {
    const absolute = resolve(cwd, path);
    const existing = existsSync(absolute) ? readFileSync(absolute, 'utf8') : '';
    writeAtomically(absolute, mergeEnvFile(existing, values));
    recordWrittenPath(absolute);
    return absolute;
}

export function writeSecretFile(path, value, cwd = process.cwd()) {
    const absolute = resolve(cwd, path);
    writeAtomically(absolute, value);
    recordWrittenPath(absolute);
    return absolute;
}

function pipeMasked(source, masker, destination) {
    return new Promise((resolvePipe, rejectPipe) => {
        const masked = source.pipe(masker.createStream());
        masked.on('data', (chunk) => destination(chunk));
        masked.on('end', resolvePipe);
        masked.on('error', rejectPipe);
        source.on('error', rejectPipe);
    });
}

export function runCommand(argv, values, masker, { cwd = process.cwd(), env = process.env, stdout, stderr, stdin = 'inherit' } = {}) {
    const writeOut = stdout ?? ((chunk) => process.stdout.write(chunk));
    const writeErr = stderr ?? ((chunk) => process.stderr.write(chunk));
    const childEnv = { ...env };
    for (const [name, value] of values) {
        childEnv[name] = value;
    }

    return new Promise((resolveRun, rejectRun) => {
        let child;
        try {
            child = spawn(argv[0], argv.slice(1), { cwd: cwd, env: childEnv, stdio: [stdin, 'pipe', 'pipe'] });
        } catch (error) {
            rejectRun(error);
            return;
        }

        const forward = (signal) => child.kill(signal);
        for (const signal of SIGNALS) {
            process.on(signal, forward);
        }
        const cleanup = () => {
            for (const signal of SIGNALS) {
                process.off(signal, forward);
            }
        };

        const piped = Promise.all([
            pipeMasked(child.stdout, masker, writeOut),
            pipeMasked(child.stderr, masker, writeErr),
        ]);

        child.on('error', (error) => {
            cleanup();
            rejectRun(error.code === 'ENOENT' ? new Error('Command not found: ' + argv[0]) : error);
        });
        child.on('close', (code, signal) => {
            cleanup();
            piped.then(() => {
                if (signal) {
                    const number = constants.signals[signal];
                    if (number === undefined) {
                        rejectRun(new Error('The command ended through an unknown signal: ' + signal));
                        return;
                    }
                    resolveRun({ exitCode: 128 + number, signal: signal });
                    return;
                }
                resolveRun({ exitCode: code ?? 1, signal: null });
            }, rejectRun);
        });
    });
}

