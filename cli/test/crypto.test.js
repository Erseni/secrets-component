import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { test } from 'node:test';
import { decryptFulfillment, encryptForRequester, generateRequesterKeypair } from '../lib/crypto.js';

const subtle = webcrypto.subtle;

async function browserEncryptForRecipient(recipientPublicRaw, plaintextBytes) {
    const recipientKey = await subtle.importKey('raw', recipientPublicRaw, { name: 'X25519' }, true, []);
    const ephemeral = await subtle.generateKey({ name: 'X25519' }, true, ['deriveBits']);
    const sharedBits = await subtle.deriveBits({ name: 'X25519', public: recipientKey }, ephemeral.privateKey, 256);
    const baseKey = await subtle.importKey('raw', sharedBits, { name: 'HKDF' }, false, ['deriveKey']);
    const aesKey = await subtle.deriveKey(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(), info: new TextEncoder().encode('secrets-component:x25519-aes-gcm:v1') },
        baseKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt'],
    );
    const nonce = webcrypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, plaintextBytes);
    return {
        fillerPublicRaw: Buffer.from(await subtle.exportKey('raw', ephemeral.publicKey)),
        nonce: Buffer.from(nonce),
        ciphertext: Buffer.from(ciphertext),
    };
}

test('decrypts what the browser fulfil page encrypts with Web Crypto', async () => {
    const keypair = generateRequesterKeypair();
    const bundle = JSON.stringify({ v: 2, k: 'command', c: 'psql -h db', s: { DB_PASSWORD: 'kjh§$%&/ÄÖÜ 🙂' } });
    const encrypted = await browserEncryptForRecipient(keypair.publicRaw, new TextEncoder().encode(bundle));

    const plaintext = decryptFulfillment(keypair.privateKey, encrypted.fillerPublicRaw, encrypted.ciphertext, encrypted.nonce);

    assert.equal(plaintext.toString('utf8'), bundle);
});

test('rejects a ciphertext that was altered on the way', () => {
    const keypair = generateRequesterKeypair();
    const encrypted = encryptForRequester(keypair.publicRaw, Buffer.from('secret'));
    encrypted.ciphertext[0] ^= 0x01;

    assert.throws(() => decryptFulfillment(keypair.privateKey, encrypted.fillerPublicRaw, encrypted.ciphertext, encrypted.nonce));
});

test('cannot be decrypted with another requester key', () => {
    const keypair = generateRequesterKeypair();
    const other = generateRequesterKeypair();
    const encrypted = encryptForRequester(keypair.publicRaw, Buffer.from('secret'));

    assert.throws(() => decryptFulfillment(other.privateKey, encrypted.fillerPublicRaw, encrypted.ciphertext, encrypted.nonce));
});

test('exports a raw 32 byte public key', () => {
    assert.equal(generateRequesterKeypair().publicRaw.length, 32);
});
