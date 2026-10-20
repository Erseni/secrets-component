import assert from 'node:assert/strict';
import { mock, test } from 'node:test';
import { VaultClient } from '../lib/client.js';

const TOKEN = 'AAAAAAAAAAAAAAAAAAAAAA';

function json(body, status = 200) {
    return new Response(JSON.stringify(body), { status: status, headers: { 'Content-Type': 'application/json' } });
}

function fakeFetch({ fulfilledAfterStatusChecks, stream }) {
    let statusChecks = 0;
    return async (url) => {
        if (url.includes('/api/sse/validate')) {
            return json({ success: true, data: { success: true } });
        }
        if (url.includes('/api/sse?')) {
            return stream();
        }
        statusChecks += 1;
        return json({ success: true, data: { status: statusChecks > fulfilledAfterStatusChecks ? 'fulfilled' : 'waiting' } });
    };
}

async function driveTimers(promise) {
    let settled = false;
    promise.then(() => {
        settled = true;
    }, () => {
        settled = true;
    });
    for (let round = 0; round < 200 && !settled; round += 1) {
        await new Promise((resolveTick) => setImmediate(resolveTick));
        mock.timers.tick(60000);
    }
    return promise;
}

test('keeps checking the status after the live stream failed more often than the reconnect cap', async (t) => {
    mock.timers.enable({ apis: ['setTimeout'] });
    t.after(() => mock.timers.reset());
    const reasons = [];
    const client = new VaultClient({
        server: 'https://vault.example',
        fetchImpl: fakeFetch({ fulfilledAfterStatusChecks: 15, stream: () => new Response('', { status: 401 }) }),
    });

    await driveTimers(client.waitForFulfillment(TOKEN, {
        expiresAt: new Date(Date.now() + 3600 * 1000),
        onReconnect: (reason) => reasons.push(reason),
    }));

    assert.equal(reasons.length, 15);
    assert.ok(reasons.every((reason) => reason === 'stream responded 401'));
});

test('reports a status event that is not valid JSON instead of waiting silently', async (t) => {
    mock.timers.enable({ apis: ['setTimeout'] });
    t.after(() => mock.timers.reset());
    const reasons = [];
    const client = new VaultClient({
        server: 'https://vault.example',
        fetchImpl: fakeFetch({
            fulfilledAfterStatusChecks: 1,
            stream: () => new Response('event: status\ndata: {broken\n\n', { status: 200, headers: { 'Content-Type': 'text/event-stream' } }),
        }),
    });

    await driveTimers(client.waitForFulfillment(TOKEN, {
        expiresAt: new Date(Date.now() + 3600 * 1000),
        onReconnect: (reason) => reasons.push(reason),
    }));

    assert.deepEqual(reasons, ['stream sent a status event that is not valid JSON']);
});
