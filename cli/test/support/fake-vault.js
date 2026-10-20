import { createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { encryptForRequester } from '../../lib/crypto.js';
import { b64urlDecode, b64urlEncode } from '../../lib/encoding.js';
import { leadingZeroBits } from '../../lib/pow.js';

const POW_DIFFICULTY = 8;
export const VALID_API_KEY = 'vak_' + 'A'.repeat(43);

function readBody(request) {
    return new Promise((resolveBody) => {
        const chunks = [];
        request.on('data', (chunk) => chunks.push(chunk));
        request.on('end', () => resolveBody(Buffer.concat(chunks).toString('utf8')));
    });
}

function sendJson(response, status, payload, headers = {}) {
    response.writeHead(status, { 'Content-Type': 'application/json', ...headers });
    response.end(JSON.stringify(payload));
}

export class FakeVault {
    constructor({ sseAvailable = true } = {}) {
        this.sseAvailable = sseAvailable;
        this.requests = new Map();
        this.secrets = new Map();
        this.streams = new Map();
        this.powSolved = 0;
        this.createCalls = [];
        this.createdWaiters = [];
        this.server = createServer((request, response) => {
            this.route(request, response).catch((error) => sendJson(response, 500, { success: false, errorMessage: error.message }));
        });
    }

    async start() {
        await new Promise((resolveListen) => this.server.listen(0, '127.0.0.1', resolveListen));
        this.url = 'http://127.0.0.1:' + this.server.address().port;
        return this;
    }

    async stop() {
        for (const streams of this.streams.values()) {
            for (const stream of streams) {
                stream.end();
            }
        }
        this.server.closeAllConnections();
        await new Promise((resolveClose) => this.server.close(resolveClose));
    }

    nextCreated() {
        return new Promise((resolveCreated) => this.createdWaiters.push(resolveCreated));
    }

    async route(request, response) {
        const url = new URL(request.url, 'http://localhost');
        const path = url.pathname;

        if (request.method === 'POST' && path === '/api/secrets/requests') {
            return this.createRequest(request, response);
        }
        if (request.method === 'POST' && path === '/api/secrets') {
            return this.createSecret(request, response);
        }
        let match = /^\/api\/secrets\/requests\/([A-Za-z0-9_-]{22})\/status$/.exec(path);
        if (request.method === 'GET' && match) {
            const entry = this.requests.get(match[1]);
            if (!entry) {
                return sendJson(response, 404, { success: false });
            }
            return sendJson(response, 200, { success: true, data: { status: entry.status } });
        }
        match = /^\/api\/secrets\/requests\/([A-Za-z0-9_-]{22})\/fulfillment\/retrieve$/.exec(path);
        if (request.method === 'POST' && match) {
            await readBody(request);
            const entry = this.requests.get(match[1]);
            if (!entry || entry.status !== 'fulfilled') {
                return sendJson(response, 404, { success: false, data: { errorMessage: 'Not found' } });
            }
            entry.status = 'retrieved';
            return sendJson(response, 200, { success: true, data: entry.fulfillment });
        }
        if (request.method === 'POST' && path === '/api/sse/validate') {
            await readBody(request);
            if (!this.sseAvailable) {
                return sendJson(response, 502, { success: false });
            }
            return sendJson(response, 200, { success: true, data: { success: true } });
        }
        if (request.method === 'GET' && path === '/api/sse') {
            if (!this.sseAvailable) {
                response.writeHead(502);
                response.end();
                return undefined;
            }
            const channel = url.searchParams.get('channels');
            response.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
            response.write(': connected\n\n');
            const list = this.streams.get(channel) ?? [];
            list.push(response);
            this.streams.set(channel, list);
            return undefined;
        }
        return sendJson(response, 404, { success: false });
    }

    admit(request, response, body) {
        const authorization = request.headers.authorization ?? null;
        this.createCalls.push({ path: request.url, authorization: authorization, body: body });

        if (authorization !== null) {
            if (authorization !== 'Bearer ' + VALID_API_KEY) {
                sendJson(response, 401, { success: false, formErrors: { api_key: 'Invalid API key' } });
                return false;
            }
            return true;
        }
        const challenge = request.headers['x-pow-challenge'];
        const counter = request.headers['x-pow-counter'];
        if (!challenge || !counter) {
            sendJson(response, 428, {
                success: false,
                powRequired: true,
                pow: { challenge: b64urlEncode(randomBytes(18)), difficulty: POW_DIFFICULTY, issuedAt: Math.floor(Date.now() / 1000), sig: 'fake' },
            });
            return false;
        }
        const hash = createHash('sha256').update(challenge + ':' + counter).digest();
        if (leadingZeroBits(hash) < POW_DIFFICULTY) {
            sendJson(response, 428, { success: false, powRequired: true, pow: null });
            return false;
        }
        this.powSolved += 1;
        return true;
    }

    async createSecret(request, response) {
        const body = JSON.parse(await readBody(request));
        if (!this.admit(request, response, body)) {
            return undefined;
        }
        const token = b64urlEncode(randomBytes(16));
        this.secrets.set(token, { ciphertext: b64urlDecode(body.ciphertext), nonce: b64urlDecode(body.nonce), ttl: body.ttl_seconds });
        return sendJson(response, 200, {
            success: true,
            data: { token: token, expires_at: new Date(Date.now() + body.ttl_seconds * 1000).toISOString() },
        });
    }

    openLink(link) {
        const url = new URL(link);
        const token = url.pathname.split('/').pop();
        const entry = this.secrets.get(token);
        if (!entry) {
            return null;
        }
        this.secrets.delete(token);
        const key = b64urlDecode(new URLSearchParams(url.hash.slice(1)).get('k'));
        const body = entry.ciphertext.subarray(0, entry.ciphertext.length - 16);
        const decipher = createDecipheriv('aes-256-gcm', key, entry.nonce);
        decipher.setAuthTag(entry.ciphertext.subarray(entry.ciphertext.length - 16));
        const bundle = JSON.parse(Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8'));
        return { label: bundle.l, value: bundle.t, ttl: entry.ttl };
    }

    async createRequest(request, response) {
        const body = JSON.parse(await readBody(request));
        if (!this.admit(request, response, body)) {
            return undefined;
        }

        const token = b64urlEncode(randomBytes(16));
        const entry = {
            token: token,
            requesterPub: b64urlDecode(body.requester_pub),
            status: 'waiting',
            fulfillment: null,
            ttl: body.ttl_seconds,
        };
        this.requests.set(token, entry);
        for (const waiter of this.createdWaiters.splice(0)) {
            waiter(entry);
        }
        return sendJson(response, 200, {
            success: true,
            data: { token: token, expires_at: new Date(Date.now() + body.ttl_seconds * 1000).toISOString(), max_attachment_bytes: 0 },
        });
    }

    fulfillFromLink(link, values, overrides = {}) {
        const url = new URL(link);
        const token = url.pathname.split('/').pop();
        const fragment = new URLSearchParams(url.hash.slice(1));
        const agentRequest = JSON.parse(b64urlDecode(fragment.get('a')).toString('utf8'));
        const bundle = {
            v: 2,
            k: overrides.kind ?? agentRequest.k,
            c: overrides.purpose ?? agentRequest.c,
            s: values,
        };
        this.fulfill(token, b64urlDecode(fragment.get('rp')), JSON.stringify(bundle));
        return agentRequest;
    }

    fulfill(token, requesterPub, bundleText) {
        const entry = this.requests.get(token);
        const encrypted = encryptForRequester(requesterPub, Buffer.from(bundleText, 'utf8'));
        entry.fulfillment = {
            filler_pub: b64urlEncode(encrypted.fillerPublicRaw),
            ciphertext: b64urlEncode(encrypted.ciphertext),
            nonce: b64urlEncode(encrypted.nonce),
        };
        entry.status = 'fulfilled';
        for (const stream of this.streams.get('secret-request:' + token) ?? []) {
            stream.write('event: status\ndata: ' + JSON.stringify({ status: 'fulfilled', kind: 'request' }) + '\n\n');
        }
    }
}
