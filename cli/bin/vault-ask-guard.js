#!/usr/bin/env node
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { evaluate } from '../lib/guard.js';
import { readWrittenPaths } from '../lib/state.js';

function deny(reason) {
    process.stdout.write(JSON.stringify({
        hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'deny',
            permissionDecisionReason: 'vault-ask-guard: ' + reason,
        },
    }) + '\n');
}

if (process.argv[1] && fileURLToPath(import.meta.url) === realpathSync(process.argv[1])) {
    const raw = readFileSync(0, 'utf8');
    let input;
    try {
        input = JSON.parse(raw);
    } catch {
        process.stderr.write('vault-ask-guard: the hook input is not JSON\n');
        process.exit(1);
    }
    const reason = evaluate(input, readWrittenPaths());
    if (reason !== null) {
        deny(reason);
    }
}
