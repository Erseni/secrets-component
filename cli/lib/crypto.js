import { createCipheriv, createDecipheriv, createPublicKey, diffieHellman, generateKeyPairSync, hkdfSync, randomBytes } from 'node:crypto';

export const PUBLIC_KEY_LENGTH = 32;
export const NONCE_LENGTH = 12;
const TAG_LENGTH = 16;
const HKDF_INFO = Buffer.from('secrets-component:x25519-aes-gcm:v1', 'utf8');

export function generateRequesterKeypair() {
    const { privateKey, publicKey } = generateKeyPairSync('x25519');
    return {
        privateKey: privateKey,
        publicRaw: exportPublicRaw(publicKey),
    };
}

function exportPublicRaw(publicKey) {
    const jwk = publicKey.export({ format: 'jwk' });
    return Buffer.from(jwk.x, 'base64url');
}

function importPublicRaw(raw) {
    if (!Buffer.isBuffer(raw) || raw.length !== PUBLIC_KEY_LENGTH) {
        throw new Error('The public key must be exactly 32 bytes');
    }
    return createPublicKey({
        key: { kty: 'OKP', crv: 'X25519', x: raw.toString('base64url') },
        format: 'jwk',
    });
}

function deriveAesKey(privateKey, publicKey) {
    const shared = diffieHellman({ privateKey: privateKey, publicKey: publicKey });
    return Buffer.from(hkdfSync('sha256', shared, Buffer.alloc(0), HKDF_INFO, 32));
}

function aesGcmEncrypt(key, plaintext) {
    const nonce = randomBytes(NONCE_LENGTH);
    const cipher = createCipheriv('aes-256-gcm', key, nonce);
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return { nonce: nonce, ciphertext: Buffer.concat([body, cipher.getAuthTag()]) };
}

function aesGcmDecrypt(key, nonce, ciphertextWithTag) {
    if (nonce.length !== NONCE_LENGTH) {
        throw new Error('The nonce must be exactly 12 bytes');
    }
    if (ciphertextWithTag.length <= TAG_LENGTH) {
        throw new Error('The ciphertext is too short');
    }
    const body = ciphertextWithTag.subarray(0, ciphertextWithTag.length - TAG_LENGTH);
    const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - TAG_LENGTH);
    const decipher = createDecipheriv('aes-256-gcm', key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(body), decipher.final()]);
}

export function decryptFulfillment(privateKey, fillerPublicRaw, ciphertext, nonce) {
    const key = deriveAesKey(privateKey, importPublicRaw(fillerPublicRaw));
    return aesGcmDecrypt(key, nonce, ciphertext);
}

export function encryptForRequester(requesterPublicRaw, plaintext) {
    const ephemeral = generateKeyPairSync('x25519');
    const key = deriveAesKey(ephemeral.privateKey, importPublicRaw(requesterPublicRaw));
    const encrypted = aesGcmEncrypt(key, plaintext);
    return {
        fillerPublicRaw: exportPublicRaw(ephemeral.publicKey),
        nonce: encrypted.nonce,
        ciphertext: encrypted.ciphertext,
    };
}
