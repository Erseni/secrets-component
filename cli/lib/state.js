import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

export function stateFile(env = process.env) {
    const base = env.XDG_STATE_HOME && env.XDG_STATE_HOME !== '' ? env.XDG_STATE_HOME : join(homedir(), '.local', 'state');
    return join(base, 'vault-ask', 'written-paths.json');
}

export function readWrittenPaths(env = process.env) {
    const file = stateFile(env);
    if (!existsSync(file)) {
        return [];
    }
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    if (!Array.isArray(parsed)) {
        throw new Error('The vault-ask state file is damaged: ' + file);
    }
    return parsed.filter((entry) => typeof entry === 'string');
}

export function recordWrittenPath(path, env = process.env) {
    const file = stateFile(env);
    const paths = new Set(readWrittenPaths(env));
    paths.add(path);
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    const temporary = file + '.' + process.pid + '.tmp';
    writeFileSync(temporary, JSON.stringify([...paths], null, 2) + '\n', { mode: 0o600 });
    chmodSync(temporary, 0o600);
    renameSync(temporary, file);
}
