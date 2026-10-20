const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export function b64urlEncode(bytes) {
    return Buffer.from(bytes).toString('base64url');
}

export function b64urlDecode(text) {
    if (typeof text !== 'string' || !BASE64URL_PATTERN.test(text)) {
        throw new Error('Invalid base64url input');
    }
    return Buffer.from(text, 'base64url');
}
