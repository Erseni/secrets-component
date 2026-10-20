import { Transform } from 'node:stream';

export const MASK = Buffer.from('***', 'utf8');
const MIN_DERIVED_PATTERN_LENGTH = 6;
const BASE64_LINE_WIDTHS = [64, 76];

function stableBase64Segments(bytes, alphabet) {
    const segments = [];
    for (let offset = 0; offset < 3; offset += 1) {
        const padded = Buffer.concat([Buffer.alloc(offset), bytes]);
        const encoded = padded.toString(alphabet).replace(/=+$/, '');
        const firstStableChar = offset === 0 ? 0 : 4;
        const lastStableChar = Math.floor(padded.length / 3) * 4;
        if (lastStableChar > firstStableChar) {
            segments.push(encoded.slice(firstStableChar, lastStableChar));
        }
    }
    return segments;
}

function wrappedBase64Lines(encoded) {
    const lines = [];
    for (const width of BASE64_LINE_WIDTHS) {
        if (encoded.length <= width) {
            continue;
        }
        for (let offset = 0; offset < encoded.length; offset += width) {
            lines.push(encoded.slice(offset, offset + width));
        }
    }
    return lines;
}

function formEncode(value) {
    return new URLSearchParams({ v: value }).toString().slice(2);
}

export function derivePatterns(value) {
    const candidates = new Set();
    const bytes = Buffer.from(value, 'utf8');
    if (bytes.length === 0) {
        return [];
    }
    candidates.add(value);

    const derived = [
        ...stableBase64Segments(bytes, 'base64'),
        ...stableBase64Segments(bytes, 'base64url'),
        bytes.toString('base64'),
        ...wrappedBase64Lines(bytes.toString('base64')),
        bytes.toString('base64url'),
        bytes.toString('hex'),
        bytes.toString('hex').toUpperCase(),
        encodeURIComponent(value),
        formEncode(value),
        JSON.stringify(value).slice(1, -1),
    ];
    for (const line of value.split(/\r?\n/)) {
        derived.push(line);
    }
    for (const candidate of derived) {
        if (candidate.length >= MIN_DERIVED_PATTERN_LENGTH) {
            candidates.add(candidate);
        }
    }

    return [...candidates].map((candidate) => Buffer.from(candidate, 'utf8'));
}

export class Masker {
    constructor(values) {
        const unique = new Map();
        for (const value of values) {
            for (const pattern of derivePatterns(value)) {
                unique.set(pattern.toString('hex'), pattern);
            }
        }
        this.patterns = [...unique.values()].sort((a, b) => b.length - a.length);
        this.maxLength = this.patterns.reduce((max, pattern) => Math.max(max, pattern.length), 0);
        this.firstBytes = new Set(this.patterns.map((pattern) => pattern[0]));
    }

    matchAt(buffer, index) {
        if (!this.firstBytes.has(buffer[index])) {
            return 0;
        }
        for (const pattern of this.patterns) {
            if (index + pattern.length <= buffer.length && buffer.compare(pattern, 0, pattern.length, index, index + pattern.length) === 0) {
                return pattern.length;
            }
        }
        return 0;
    }

    scan(buffer, safeEnd) {
        const output = [];
        let plainStart = 0;
        let index = 0;
        while (index < safeEnd) {
            const matched = this.matchAt(buffer, index);
            if (matched > 0) {
                output.push(buffer.subarray(plainStart, index), MASK);
                index += matched;
                plainStart = index;
            } else {
                index += 1;
            }
        }
        output.push(buffer.subarray(plainStart, Math.max(plainStart, Math.min(index, buffer.length))));
        return { output: Buffer.concat(output), consumed: Math.max(plainStart, Math.min(index, buffer.length)) };
    }

    maskAll(input) {
        const buffer = Buffer.isBuffer(input) ? input : Buffer.from(String(input), 'utf8');
        if (this.patterns.length === 0) {
            return buffer;
        }
        return this.scan(buffer, buffer.length).output;
    }

    createStream() {
        let carry = Buffer.alloc(0);
        const masker = this;
        return new Transform({
            transform(chunk, encoding, callback) {
                if (masker.patterns.length === 0) {
                    callback(null, chunk);
                    return;
                }
                const buffer = carry.length > 0 ? Buffer.concat([carry, chunk]) : chunk;
                const safeEnd = buffer.length - (masker.maxLength - 1);
                if (safeEnd <= 0) {
                    carry = buffer;
                    callback();
                    return;
                }
                const result = masker.scan(buffer, safeEnd);
                carry = Buffer.from(buffer.subarray(result.consumed));
                callback(null, result.output);
            },
            flush(callback) {
                const rest = carry;
                carry = Buffer.alloc(0);
                callback(null, masker.maskAll(rest));
            },
        });
    }
}
