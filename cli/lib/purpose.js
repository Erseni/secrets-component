import { resolve } from 'node:path';
import { b64urlEncode } from './encoding.js';

export const PURPOSE_COMMAND = 'command';
export const PURPOSE_ENV_FILE = 'env-file';
export const PURPOSE_FILE = 'file';

export const REQUEST_FORMAT_VERSION = 1;
export const BUNDLE_FORMAT_VERSION = 2;
export const MAX_PURPOSE_LENGTH = 2000;
export const MAX_NAMES = 20;

const NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;
const PLAIN_ARGUMENT = /^[A-Za-z0-9_\-.,:/@%+=]+$/;
const PRINTABLE_ASCII = /^[\x20-\x7E]*$/;

export class PurposeMismatchError extends Error {}

export function validateNames(names) {
    if (!Array.isArray(names) || names.length === 0) {
        throw new Error('Name at least one value to request, for example DB_PASSWORD');
    }
    if (names.length > MAX_NAMES) {
        throw new Error('At most ' + MAX_NAMES + ' values can be requested at once');
    }
    const seen = new Set();
    for (const name of names) {
        if (typeof name !== 'string' || !NAME_PATTERN.test(name)) {
            throw new Error('Not a valid name: ' + JSON.stringify(name) + '. Use letters, digits and underscores, starting with a letter or underscore');
        }
        if (seen.has(name)) {
            throw new Error('The name ' + name + ' is listed twice');
        }
        seen.add(name);
    }
    return [...names];
}

function quoteNonPrintable(argument) {
    let escaped = '';
    for (const character of argument) {
        const code = character.codePointAt(0);
        if (character === '\\' || character === '\'') {
            escaped += '\\' + character;
        } else if (code >= 0x20 && code <= 0x7E) {
            escaped += character;
        } else if (code <= 0xFF) {
            escaped += '\\x' + code.toString(16).padStart(2, '0');
        } else if (code <= 0xFFFF) {
            escaped += '\\u' + code.toString(16).padStart(4, '0');
        } else {
            escaped += '\\U' + code.toString(16).padStart(8, '0');
        }
    }
    return '$\'' + escaped + '\'';
}

export function quoteArgument(argument) {
    if (argument !== '' && PLAIN_ARGUMENT.test(argument)) {
        return argument;
    }
    if (!PRINTABLE_ASCII.test(argument)) {
        return quoteNonPrintable(argument);
    }
    return '\'' + argument.replace(/'/g, '\'\\\'\'') + '\'';
}

export function describeCommand(argv) {
    return argv.map(quoteArgument).join(' ');
}

export function describePath(path, cwd) {
    return quoteArgument(resolve(cwd, path));
}

export function buildPurpose(target, cwd) {
    let purpose;
    if (target.kind === PURPOSE_COMMAND) {
        if (!Array.isArray(target.argv) || target.argv.length === 0) {
            throw new Error('Name the command after --');
        }
        purpose = { kind: PURPOSE_COMMAND, display: 'cd ' + quoteArgument(resolve(cwd)) + ' && ' + describeCommand(target.argv) };
    } else if (target.kind === PURPOSE_ENV_FILE || target.kind === PURPOSE_FILE) {
        if (typeof target.path !== 'string' || target.path === '') {
            throw new Error('Name the path for ' + (target.kind === PURPOSE_FILE ? '--file' : '--env-file'));
        }
        purpose = { kind: target.kind, display: describePath(target.path, cwd) };
    } else {
        throw new Error('Unknown target: ' + target.kind);
    }
    if (purpose.display.length > MAX_PURPOSE_LENGTH) {
        throw new Error('The command or path is longer than ' + MAX_PURPOSE_LENGTH + ' characters and cannot be shown to the person who fills in the value');
    }
    return purpose;
}

export function encodeAgentRequest(names, purpose) {
    const payload = { v: REQUEST_FORMAT_VERSION, k: purpose.kind, c: purpose.display, n: names };
    return b64urlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
}

export function verifyBundle(bundleText, names, purpose) {
    let bundle;
    try {
        bundle = JSON.parse(bundleText);
    } catch {
        throw new PurposeMismatchError('The answer is not in the expected format');
    }
    if (!bundle || typeof bundle !== 'object' || bundle.v !== BUNDLE_FORMAT_VERSION) {
        throw new PurposeMismatchError('The answer was not given on a page for program requests');
    }
    if (bundle.k !== purpose.kind || bundle.c !== purpose.display) {
        throw new PurposeMismatchError('The person approved a different purpose than the one this program was started for. Nothing was passed on');
    }
    const values = bundle.s;
    if (!values || typeof values !== 'object' || Array.isArray(values)) {
        throw new PurposeMismatchError('The answer contains no values');
    }
    const answered = Object.keys(values).sort();
    const expected = [...names].sort();
    if (answered.length !== expected.length || answered.some((name, index) => name !== expected[index])) {
        throw new PurposeMismatchError('The answer contains different names than the ones requested. Nothing was passed on');
    }
    const result = new Map();
    for (const name of names) {
        if (typeof values[name] !== 'string') {
            throw new PurposeMismatchError('The value for ' + name + ' is not text');
        }
        result.set(name, values[name]);
    }
    return result;
}
