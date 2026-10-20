import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Masker } from '../lib/mask.js';

const VALUE = 'pg-Pa55w0rd/with+special=chars';

function maskInChunks(masker, text, size) {
    return new Promise((resolveStream) => {
        const stream = masker.createStream();
        let output = '';
        stream.on('data', (chunk) => {
            output += chunk;
        });
        stream.on('end', () => resolveStream(output));
        const bytes = Buffer.from(text, 'utf8');
        for (let offset = 0; offset < bytes.length; offset += size) {
            stream.write(bytes.subarray(offset, offset + size));
        }
        stream.end();
    });
}

test('masks the plain value', () => {
    assert.equal(new Masker([VALUE]).maskAll('password=' + VALUE + '\n').toString(), 'password=***\n');
});

test('masks base64 with and without a trailing newline and after a prefix', () => {
    const masker = new Masker([VALUE]);
    for (const encoded of [
        Buffer.from(VALUE).toString('base64'),
        Buffer.from(VALUE + '\n').toString('base64'),
        Buffer.from('u:' + VALUE).toString('base64'),
        Buffer.from('x' + VALUE).toString('base64url'),
    ]) {
        const masked = masker.maskAll(encoded).toString();
        assert.ok(masked.includes('***'), encoded + ' was not masked');
        assert.ok(masked.length < encoded.length, encoded + ' kept too much');
    }
});

test('masks URL, form and hex encodings', () => {
    const masker = new Masker([VALUE]);
    for (const encoded of [
        encodeURIComponent(VALUE),
        new URLSearchParams({ p: VALUE }).toString().slice(2),
        Buffer.from(VALUE).toString('hex'),
        Buffer.from(VALUE).toString('hex').toUpperCase(),
    ]) {
        assert.equal(masker.maskAll(encoded).toString(), '***', encoded + ' was not masked');
    }
});

test('masks each line of a multi-line value', () => {
    const key = '-----BEGIN KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END KEY-----';
    const masked = new Masker([key]).maskAll('line: MIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n').toString();

    assert.equal(masked, 'line: ***\n');
});

test('masks a value that is split across output chunks', async () => {
    const masker = new Masker([VALUE]);
    const text = 'start ' + VALUE + ' middle ' + Buffer.from(VALUE).toString('base64') + ' end\n';
    for (const size of [1, 2, 3, 7, 64]) {
        const output = await maskInChunks(masker, text, size);
        assert.ok(!output.includes(VALUE), 'value leaked with chunk size ' + size);
        assert.ok(output.startsWith('start *** middle '), 'unexpected output with chunk size ' + size + ': ' + output);
        assert.ok(output.endsWith(' end\n'), 'lost the tail with chunk size ' + size);
    }
});

test('leaves unrelated output untouched', async () => {
    const output = await maskInChunks(new Masker([VALUE]), 'nothing secret here\n', 4);
    assert.equal(output, 'nothing secret here\n');
});

test('masks base64 output that is wrapped at 64 or 76 columns', () => {
    const token = 'ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6-long-enough-to-wrap-7528';
    const encoded = Buffer.from(token).toString('base64');
    const masker = new Masker([token]);
    for (const width of [64, 76]) {
        const wrapped = encoded.match(new RegExp('.{1,' + width + '}', 'g')).join('\n') + '\n';
        const masked = masker.maskAll(wrapped).toString();
        for (const line of wrapped.trim().split('\n').filter((line) => line.length >= 6)) {
            assert.ok(!masked.includes(line), 'line ' + line + ' leaked at width ' + width);
        }
    }
});
