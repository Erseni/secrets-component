import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const CLI = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'vault-ask');

export function startCli(args, { env = {}, cwd } = {}) {
    const child = spawn(CLI, args, {
        cwd: cwd,
        env: { ...process.env, VAULT_ASK_API_KEY: '', ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    const linkWaiters = [];
    const textWaiters = [];
    child.stdout.on('data', (chunk) => {
        stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
        stderr += chunk;
        for (const waiter of textWaiters.filter((entry) => stderr.includes(entry.text))) {
            textWaiters.splice(textWaiters.indexOf(waiter), 1);
            waiter.resolve();
        }
        const link = stderr.split('\n').find((line) => /\/(fulfill|view)\//.test(line));
        if (link) {
            for (const waiter of linkWaiters.splice(0)) {
                waiter(link.trim());
            }
        }
    });
    const exited = new Promise((resolveExit) => {
        child.on('close', (code) => {
            for (const waiter of linkWaiters.splice(0)) {
                waiter(null);
            }
            resolveExit({ code: code, stdout: stdout, stderr: stderr });
        });
    });
    return {
        child: child,
        link: () => new Promise((resolveLink, rejectLink) => {
            const link = stderr.split('\n').find((line) => /\/(fulfill|view)\//.test(line));
            if (link) {
                resolveLink(link.trim());
                return;
            }
            linkWaiters.push((found) => (found === null ? rejectLink(new Error('vault-ask exited without a link: ' + stderr)) : resolveLink(found)));
        }),
        exited: exited,
        stderrContains: (text) => new Promise((resolveText) => {
            if (stderr.includes(text)) {
                resolveText();
                return;
            }
            textWaiters.push({ text: text, resolve: resolveText });
        }),
    };
}
