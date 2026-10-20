import { decryptFulfillment, generateRequesterKeypair } from './crypto.js';
import { b64urlEncode } from './encoding.js';
import { encodeAgentRequest, validateNames, verifyBundle } from './purpose.js';

export const DEFAULT_TTL_SECONDS = 3600;
export const MIN_TTL_SECONDS = 60;
export const MAX_TTL_SECONDS = 604800;

export function validateTtl(ttlSeconds) {
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < MIN_TTL_SECONDS || ttlSeconds > MAX_TTL_SECONDS) {
        throw new Error('The lifetime must be between ' + MIN_TTL_SECONDS + ' and ' + MAX_TTL_SECONDS + ' seconds');
    }
    return ttlSeconds;
}

export async function startRequest(client, names, purpose, ttlSeconds = DEFAULT_TTL_SECONDS) {
    const checkedNames = validateNames(names);
    validateTtl(ttlSeconds);
    const keypair = generateRequesterKeypair();
    const created = await client.createRequest(keypair.publicRaw, ttlSeconds);
    const fragment = 'rp=' + b64urlEncode(keypair.publicRaw) + '&a=' + encodeAgentRequest(checkedNames, purpose);
    return {
        token: created.token,
        expiresAt: created.expiresAt,
        link: client.fulfillUrl(created.token) + '#' + fragment,
        names: checkedNames,
        purpose: purpose,
        privateKey: keypair.privateKey,
    };
}

export async function completeRequest(client, pending, { signal, onReconnect } = {}) {
    await client.waitForFulfillment(pending.token, { expiresAt: pending.expiresAt, signal: signal, onReconnect: onReconnect });
    const fulfillment = await client.retrieveFulfillment(pending.token);
    const plaintext = decryptFulfillment(pending.privateKey, fulfillment.fillerPublicRaw, fulfillment.ciphertext, fulfillment.nonce);
    return verifyBundle(plaintext.toString('utf8'), pending.names, pending.purpose);
}

export function describeReceived(values, destination) {
    return [...values].map(([name, value]) => name + ' received, ' + [...value].length + ' characters, ' + destination).join('\n');
}
