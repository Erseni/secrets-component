import { createCipheriv, randomBytes, randomInt } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { NONCE_LENGTH } from './crypto.js';
import { b64urlEncode } from './encoding.js';
import { validateTtl } from './request.js';

export const DEFAULT_SEND_TTL_SECONDS = 86400;
export const DEFAULT_LENGTH = 32;
export const MIN_LENGTH = 8;
export const MAX_LENGTH = 4096;
export const LABEL_MAX_LENGTH = 120;
export const DEFAULT_CHARSET = 'alnum';

const LETTERS_AND_DIGITS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

export const CHARSETS = {
    alnum: LETTERS_AND_DIGITS,
    symbols: LETTERS_AND_DIGITS + '!#%*+,-./:;=?@^_~',
    hex: '0123456789abcdef',
};

const KEY_LENGTH = 32;

export function generateValue(length = DEFAULT_LENGTH, charset = DEFAULT_CHARSET) {
    if (!Number.isInteger(length) || length < MIN_LENGTH || length > MAX_LENGTH) {
        throw new Error('The length must be between ' + MIN_LENGTH + ' and ' + MAX_LENGTH + ' characters');
    }
    const alphabet = CHARSETS[charset];
    if (alphabet === undefined) {
        throw new Error('Unknown character set: ' + charset + '. Choose one of ' + Object.keys(CHARSETS).join(', '));
    }
    let value = '';
    for (let index = 0; index < length; index += 1) {
        value += alphabet[randomInt(alphabet.length)];
    }
    return value;
}

export function readSourceValue(source, { env = process.env, cwd = process.cwd() } = {}) {
    if (source.kind === 'file') {
        const value = readFileSync(resolve(cwd, source.path), 'utf8');
        if (value === '') {
            throw new Error('The file ' + resolve(cwd, source.path) + ' is empty. Nothing was sent');
        }
        return value;
    }
    if (source.kind === 'env') {
        const value = env[source.name];
        if (typeof value !== 'string' || value === '') {
            throw new Error('The environment variable ' + source.name + ' is not set or empty. Nothing was sent');
        }
        return value;
    }
    throw new Error('Unknown value source: ' + source.kind);
}

export function sanitizeLabel(label) {
    if (typeof label !== 'string') {
        return '';
    }
    return label.trim().slice(0, LABEL_MAX_LENGTH);
}

export function encryptForLink(label, value) {
    const key = randomBytes(KEY_LENGTH);
    const nonce = randomBytes(NONCE_LENGTH);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    const bundle = Buffer.from(JSON.stringify({ l: sanitizeLabel(label), t: value }), 'utf8');
    const body = Buffer.concat([cipher.update(bundle), cipher.final()]);
    return { key: key, nonce: nonce, ciphertext: Buffer.concat([body, cipher.getAuthTag()]) };
}

export async function createSendLink(client, { value, label = '', ttlSeconds = DEFAULT_SEND_TTL_SECONDS }) {
    if (typeof value !== 'string' || value === '') {
        throw new Error('There is no value to send');
    }
    validateTtl(ttlSeconds);
    const encrypted = encryptForLink(label, value);
    const created = await client.createSecret(encrypted.ciphertext, encrypted.nonce, ttlSeconds);
    return {
        link: client.viewUrl(created.token) + '#k=' + b64urlEncode(encrypted.key),
        expiresAt: created.expiresAt,
    };
}

export function describeSent(name, value, destination) {
    const subject = name ? name + ', ' : '';
    return subject + [...value].length + ' characters, ' + destination;
}
