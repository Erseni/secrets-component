import { createHash } from 'node:crypto';

const MAX_DIFFICULTY_BITS = 32;

export function leadingZeroBits(bytes) {
    let count = 0;
    for (const byte of bytes) {
        if (byte === 0) {
            count += 8;
            continue;
        }
        for (let bit = 7; bit >= 0; bit -= 1) {
            if ((byte >> bit) & 1) {
                return count;
            }
            count += 1;
        }
    }
    return count;
}

export function solveProofOfWork(challenge, difficulty) {
    if (typeof challenge !== 'string' || challenge === '') {
        throw new Error('The proof-of-work challenge is missing');
    }
    if (!Number.isInteger(difficulty) || difficulty < 0 || difficulty > MAX_DIFFICULTY_BITS) {
        throw new Error('The server asked for an unsupported proof-of-work difficulty: ' + difficulty);
    }
    for (let counter = 0; ; counter += 1) {
        const hash = createHash('sha256').update(challenge + ':' + counter).digest();
        if (leadingZeroBits(hash) >= difficulty) {
            return String(counter);
        }
    }
}
