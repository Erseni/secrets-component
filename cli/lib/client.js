import { b64urlDecode, b64urlEncode } from './encoding.js';
import { solveProofOfWork } from './pow.js';

export const DEFAULT_SERVER = 'https://vault.erseni.com';
export const USER_AGENT = 'vault-ask';

const SSE_RECONNECT_BASE_MS = 2000;
const SSE_RECONNECT_MAX_MS = 60000;
const SSE_RECONNECT_MAX_ATTEMPTS = 12;
const END_STATES = new Set(['retrieved', 'expired', 'cleaned-up']);

export class VaultApiError extends Error {
    constructor(message, status) {
        super(message);
        this.status = status;
    }
}

export class RequestEndedError extends Error {}

function normaliseServer(server) {
    let url;
    try {
        url = new URL(server);
    } catch {
        throw new Error('Not a valid server URL: ' + server);
    }
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname))) {
        throw new Error('The server must be reached over https: ' + server);
    }
    return url.toString().replace(/\/+$/, '');
}

function extractError(json, status) {
    if (json && typeof json === 'object') {
        const data = json.data && typeof json.data === 'object' ? json.data : null;
        if (data && typeof data.errorMessage === 'string' && data.errorMessage !== '') {
            return data.errorMessage;
        }
        if (typeof json.errorMessage === 'string' && json.errorMessage !== '') {
            return json.errorMessage;
        }
        if (json.formErrors && typeof json.formErrors === 'object') {
            const messages = Object.entries(json.formErrors).map(([field, message]) => field + ': ' + message);
            if (messages.length > 0) {
                return messages.join(', ');
            }
        }
    }
    return 'The server answered with HTTP ' + status;
}

async function readJson(response) {
    const text = await response.text();
    if (text === '') {
        return null;
    }
    try {
        return JSON.parse(text);
    } catch {
        throw new VaultApiError('The server did not answer with JSON (HTTP ' + response.status + ')', response.status);
    }
}

function unwrap(json, status) {
    if (json && json.success === true && json.data && typeof json.data === 'object') {
        return json.data;
    }
    throw new VaultApiError(extractError(json, status), status);
}

function sleep(ms, signal) {
    return new Promise((resolveSleep, rejectSleep) => {
        const timer = setTimeout(resolveSleep, ms);
        signal?.addEventListener('abort', () => {
            clearTimeout(timer);
            rejectSleep(signal.reason);
        }, { once: true });
    });
}

export function parseSseEvents(onEvent) {
    let buffer = '';
    let eventType = 'message';
    let dataLines = [];
    return (chunk) => {
        buffer += chunk;
        let newline;
        while ((newline = buffer.search(/\r?\n/)) !== -1) {
            const line = buffer.slice(0, newline);
            buffer = buffer.slice(buffer[newline] === '\r' ? newline + 2 : newline + 1);
            if (line === '') {
                if (dataLines.length > 0) {
                    onEvent(eventType, dataLines.join('\n'));
                }
                eventType = 'message';
                dataLines = [];
                continue;
            }
            if (line.startsWith(':')) {
                continue;
            }
            const separator = line.indexOf(':');
            const field = separator === -1 ? line : line.slice(0, separator);
            const value = separator === -1 ? '' : line.slice(separator + 1).replace(/^ /, '');
            if (field === 'event') {
                eventType = value;
            } else if (field === 'data') {
                dataLines.push(value);
            }
        }
    };
}

export class VaultClient {
    constructor({ server = DEFAULT_SERVER, apiKey = null, fetchImpl = globalThis.fetch, version = '0.0.0' } = {}) {
        this.server = normaliseServer(server);
        this.apiKey = apiKey && apiKey !== '' ? apiKey : null;
        this.fetch = async (url, init) => {
            try {
                return await fetchImpl(url, init);
            } catch (error) {
                if (init && init.signal && init.signal.aborted) {
                    throw error;
                }
                const cause = error && error.cause && error.cause.code ? error.cause.code : (error && error.message ? error.message : 'unknown error');
                throw new VaultApiError('Cannot reach ' + this.server + ' (' + cause + ')', 0);
            }
        };
        this.userAgent = USER_AGENT + '/' + version;
    }

    fulfillUrl(token) {
        return this.server + '/fulfill/' + token;
    }

    viewUrl(token) {
        return this.server + '/view/' + token;
    }

    async createRequest(publicRaw, ttlSeconds) {
        const data = await this.createWithProofOfWork('/api/secrets/requests', {
            requester_pub: b64urlEncode(publicRaw),
            ttl_seconds: ttlSeconds,
            attachments_allowed: false,
        });
        return { token: data.token, expiresAt: new Date(data.expires_at) };
    }

    async createSecret(ciphertext, nonce, ttlSeconds) {
        const data = await this.createWithProofOfWork('/api/secrets', {
            ciphertext: b64urlEncode(ciphertext),
            nonce: b64urlEncode(nonce),
            ttl_seconds: ttlSeconds,
        });
        return { token: data.token, expiresAt: new Date(data.expires_at) };
    }

    async createWithProofOfWork(path, payload) {
        const body = JSON.stringify(payload);
        const headers = {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            'User-Agent': this.userAgent,
        };
        if (this.apiKey !== null) {
            headers.Authorization = 'Bearer ' + this.apiKey;
        }

        let response = await this.fetch(this.server + path, { method: 'POST', headers: headers, body: body });
        let json = await readJson(response);

        if (response.status === 428 && json && json.powRequired && json.pow) {
            const pow = json.pow;
            const counter = solveProofOfWork(pow.challenge, pow.difficulty);
            response = await this.fetch(this.server + path, {
                method: 'POST',
                headers: {
                    ...headers,
                    'X-PoW-Challenge': pow.challenge,
                    'X-PoW-Difficulty': String(pow.difficulty),
                    'X-PoW-IssuedAt': String(pow.issuedAt),
                    'X-PoW-Sig': pow.sig,
                    'X-PoW-Counter': counter,
                },
                body: body,
            });
            json = await readJson(response);
        }

        if (response.status === 401) {
            throw new VaultApiError('The API key was rejected. Check VAULT_ASK_API_KEY or create a new key in your Vault account', 401);
        }
        if (response.status === 429) {
            const retryAfter = response.headers.get('Retry-After');
            throw new VaultApiError('The request limit is reached' + (retryAfter ? ', try again in ' + retryAfter + ' seconds' : ''), 429);
        }
        if (!response.ok) {
            throw new VaultApiError(extractError(json, response.status), response.status);
        }

        const data = unwrap(json, response.status);
        if (typeof data.token !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(data.token)) {
            throw new VaultApiError('The server returned no valid token', response.status);
        }
        return data;
    }

    async getStatus(token) {
        const response = await this.fetch(this.server + '/api/secrets/requests/' + token + '/status', {
            method: 'GET',
            headers: { Accept: 'application/json', 'User-Agent': this.userAgent },
        });
        if (response.status === 404) {
            return 'cleaned-up';
        }
        const json = await readJson(response);
        if (!response.ok) {
            throw new VaultApiError(extractError(json, response.status), response.status);
        }
        const data = unwrap(json, response.status);
        return typeof data.status === 'string' ? data.status : 'waiting';
    }

    async retrieveFulfillment(token) {
        const response = await this.fetch(this.server + '/api/secrets/requests/' + token + '/fulfillment/retrieve', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Accept: 'application/json', 'User-Agent': this.userAgent },
            body: '{}',
        });
        const json = await readJson(response);
        if (response.status === 404) {
            throw new RequestEndedError('The answer is no longer on the server: it was already collected or has expired');
        }
        if (!response.ok) {
            throw new VaultApiError(extractError(json, response.status), response.status);
        }
        const data = unwrap(json, response.status);
        return {
            fillerPublicRaw: b64urlDecode(data.filler_pub),
            ciphertext: b64urlDecode(data.ciphertext),
            nonce: b64urlDecode(data.nonce),
        };
    }

    async validateChannel(channel) {
        const body = new URLSearchParams();
        body.append('channels[]', channel);
        const response = await this.fetch(this.server + '/api/sse/validate', {
            method: 'POST',
            headers: { Accept: 'application/json', 'User-Agent': this.userAgent },
            body: body,
        });
        if (!response.ok) {
            return 'validate responded ' + response.status;
        }
        const json = await readJson(response);
        const payload = json && json.data ? json.data : json;
        return payload && payload.success ? null : 'validate rejected the channel';
    }

    async streamUntilChange(channel, token, signal) {
        const response = await this.fetch(this.server + '/api/sse?channels=' + encodeURIComponent(channel), {
            method: 'GET',
            headers: { Accept: 'text/event-stream', 'User-Agent': this.userAgent },
            signal: signal,
        });
        if (!response.ok || !response.body) {
            return { status: null, reason: 'stream responded ' + response.status };
        }
        let found = null;
        let unreadable = false;
        const decoder = new TextDecoder();
        const feed = parseSseEvents((type, data) => {
            if (type !== 'status' || found !== null) {
                return;
            }
            try {
                const payload = JSON.parse(data);
                if (payload && typeof payload.status === 'string' && payload.status !== 'waiting') {
                    found = payload.status;
                }
            } catch {
                unreadable = true;
            }
        });
        const reader = response.body.getReader();
        try {
            while (found === null && !unreadable) {
                const { value, done } = await reader.read();
                if (done) {
                    break;
                }
                feed(decoder.decode(value, { stream: true }));
            }
        } finally {
            await reader.cancel();
        }
        if (unreadable) {
            return { status: null, reason: 'stream sent a status event that is not valid JSON', connected: true };
        }
        return { status: found, reason: found === null ? 'stream closed by the server' : null, connected: true };
    }

    async waitForFulfillment(token, { expiresAt, signal, onReconnect } = {}) {
        const channel = 'secret-request:' + token;
        let attempts = 0;
        while (true) {
            if (expiresAt && Date.now() >= expiresAt.getTime()) {
                throw new RequestEndedError('The request expired before anyone answered it');
            }
            const status = await this.getStatus(token);
            if (status === 'fulfilled') {
                return;
            }
            if (END_STATES.has(status)) {
                throw new RequestEndedError('The request ended without an answer (' + status + ')');
            }

            const validationProblem = await this.validateChannel(channel);
            let outcome = { status: null, reason: validationProblem };
            if (validationProblem === null) {
                const controller = new AbortController();
                const abort = () => controller.abort(signal.reason);
                signal?.addEventListener('abort', abort, { once: true });
                const remaining = expiresAt ? Math.max(0, expiresAt.getTime() - Date.now()) : null;
                const expiryTimer = remaining !== null ? setTimeout(() => controller.abort(new RequestEndedError('expired')), remaining) : null;
                try {
                    outcome = await this.streamUntilChange(channel, token, controller.signal);
                } catch (error) {
                    if (signal?.aborted) {
                        throw signal.reason;
                    }
                    outcome = { status: null, reason: 'stream failed: ' + (error && error.name ? error.name : 'unknown') };
                } finally {
                    if (expiryTimer !== null) {
                        clearTimeout(expiryTimer);
                    }
                    signal?.removeEventListener('abort', abort);
                }
                if (outcome.connected) {
                    attempts = 0;
                }
            }

            if (outcome.status === 'fulfilled') {
                return;
            }
            if (outcome.status !== null && END_STATES.has(outcome.status)) {
                throw new RequestEndedError('The request ended without an answer (' + outcome.status + ')');
            }

            const delay = Math.min(SSE_RECONNECT_BASE_MS * Math.pow(2, attempts), SSE_RECONNECT_MAX_MS);
            attempts = Math.min(attempts + 1, SSE_RECONNECT_MAX_ATTEMPTS);
            onReconnect?.(outcome.reason, delay);
            await sleep(delay, signal);
        }
    }
}
