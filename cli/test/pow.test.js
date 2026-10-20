import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { test } from 'node:test';
import { leadingZeroBits, solveProofOfWork } from '../lib/pow.js';

test('counts leading zero bits the way the server does', () => {
    assert.equal(leadingZeroBits(Buffer.from([0x00, 0x00, 0x80])), 16);
    assert.equal(leadingZeroBits(Buffer.from([0x0F])), 4);
    assert.equal(leadingZeroBits(Buffer.from([0xFF])), 0);
});

test('finds a counter whose hash meets the difficulty', () => {
    const counter = solveProofOfWork('challenge-value', 12);
    const hash = createHash('sha256').update('challenge-value:' + counter).digest();

    assert.ok(leadingZeroBits(hash) >= 12);
});

test('refuses a difficulty no client could solve', () => {
    assert.throws(() => solveProofOfWork('challenge', 64), /unsupported proof-of-work difficulty/);
});
