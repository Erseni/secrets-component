import { randomBytes } from 'node:crypto';
import { createInterface } from 'node:readline';
import { DEFAULT_SERVER, VaultClient } from './client.js';
import { Masker } from './mask.js';
import { PURPOSE_COMMAND, PURPOSE_ENV_FILE, PURPOSE_FILE, buildPurpose, validateNames } from './purpose.js';
import { DEFAULT_TTL_SECONDS, completeRequest, describeReceived, startRequest } from './request.js';
import { CHARSETS, DEFAULT_CHARSET, DEFAULT_LENGTH, DEFAULT_SEND_TTL_SECONDS, MAX_LENGTH, MIN_LENGTH, createSendLink, describeSent, generateValue, readSourceValue } from './send.js';
import { formatEnvValue, runCommand, writeEnvFile, writeSecretFile } from './targets.js';

export const DEFAULT_PROTOCOL_VERSION = '2025-06-18';
export const DEFAULT_WAIT_MS = 240000;
export const MAX_OUTPUT_BYTES = 65536;

export const INSTRUCTIONS = [
    'Erseni Vault moves passwords, tokens, API keys, private keys and other secrets between the user and you without the value ever appearing in this conversation. Use it whenever a secret has to change hands, in either direction:',
    '- The user wants a secret from you, for example "generate a password for my database", "generier mir ein Passwort", "create an API token", "send me the key": call send_secret. It generates the value locally (or takes it from a file or an environment variable), can write the same value into a .env file, a file or one command so that the system and the user end up with the same value, and returns only a one-time link. Give the user that link. Do not generate a secret any other way, and do not put one into the chat, the clipboard or a file outside send_secret.',
    '- You need a secret from the user, for example "I will give you my database password", "du brauchst meinen API-Key für X", "use my token": call request_secret to have it written into a .env file or a file, or run_with_secret to run exactly one command with it. Never ask the user to type or paste a secret into the chat.',
    '- Never print, echo, log or repeat a secret value, and do not read the files these tools wrote.',
].join('\n');

const NAMES_SCHEMA = {
    type: 'array',
    items: { type: 'string', pattern: '^[A-Za-z_][A-Za-z0-9_]{0,127}$' },
    minItems: 1,
    maxItems: 20,
    description: 'Names of the values to ask for, for example ["DB_PASSWORD"]',
};

export const TOOLS = [
    {
        name: 'request_secret',
        description: 'Use this whenever you need a password, token, API key or other secret from the user, for example "I will give you my database password" or "you need my API key for X". '
            + 'Never ask the user to type or paste a secret into the chat. '
            + 'Asks the user for one or more secrets and writes them into a .env file or a file, without the values ever passing through this conversation. '
            + 'First call without request_id: returns a link. Show it to the user, then call again with the returned request_id; '
            + 'that call waits for the answer and writes the file with permissions 600. The result only contains names and lengths, never a value.',
        inputSchema: {
            type: 'object',
            properties: {
                names: NAMES_SCHEMA,
                env_file: { type: 'string', description: 'Write NAME=value lines into this .env file' },
                file: { type: 'string', description: 'Write the single requested value into this file' },
                ttl_seconds: { type: 'integer', minimum: 60, maximum: 604800 },
                request_id: { type: 'string', description: 'The id returned by the first call' },
            },
        },
    },
    {
        name: 'run_with_secret',
        description: 'Use this whenever a single command needs a password, token, API key or other secret from the user, for example "connect to the database with my password" or "deploy with my API token". '
            + 'Never ask the user to type or paste a secret into the chat. '
            + 'Asks the user for one or more secrets and runs exactly one command with them as environment variables. '
            + 'The user sees the command before entering anything, and only this command can receive the values. '
            + 'First call without request_id: returns a link. Show it to the user, then call again with the returned request_id; '
            + 'that call waits for the answer, runs the command and returns its exit code and its output with every value masked.',
        inputSchema: {
            type: 'object',
            properties: {
                names: NAMES_SCHEMA,
                command: { type: 'array', items: { type: 'string' }, minItems: 1, description: 'The command and its arguments, for example ["psql", "-h", "db.example.com"]' },
                cwd: { type: 'string', description: 'Working directory for the command' },
                ttl_seconds: { type: 'integer', minimum: 60, maximum: 604800 },
                request_id: { type: 'string', description: 'The id returned by the first call' },
            },
        },
    },
    {
        name: 'send_secret',
        description: 'Use this whenever the user asks you to generate, create or send them a password, token, API key or other secret, for example "generate a password for my database", "generier mir ein Passwort" or "send me the key". '
            + 'Do not generate a secret any other way and never write one into the chat. '
            + 'Generates the value locally (' + DEFAULT_LENGTH + ' letters and digits unless length or charset say otherwise) or takes it from from_file or from_env, encrypts it on this machine and returns only a one-time link that shows the value once in the browser. '
            + 'Give the user that link. With env_file, file or command the same value also goes to that destination (needs name except for file), so the system and the link hold the same value. '
            + 'The result contains the link, its expiry and the length, never the value.',
        inputSchema: {
            type: 'object',
            properties: {
                name: { type: 'string', pattern: '^[A-Za-z_][A-Za-z0-9_]{0,127}$', description: 'Name of the value, for example "DB_PASSWORD". Default label on the page, and the variable name for env_file and command' },
                label: { type: 'string', maxLength: 120, description: 'Label shown above the value on the page, for example "Database password for app@db.example.com"' },
                length: { type: 'integer', minimum: MIN_LENGTH, maximum: MAX_LENGTH, description: 'Length of the generated value, default ' + DEFAULT_LENGTH },
                charset: { type: 'string', enum: Object.keys(CHARSETS), description: 'Characters of the generated value, default ' + DEFAULT_CHARSET },
                from_file: { type: 'string', description: 'Send the content of this file instead of a generated value' },
                from_env: { type: 'string', description: 'Send the value of this environment variable of the server process instead of a generated value' },
                env_file: { type: 'string', description: 'Also write NAME=value into this .env file (permissions 600)' },
                file: { type: 'string', description: 'Also write the value into this file (permissions 600)' },
                command: { type: 'array', items: { type: 'string' }, minItems: 1, description: 'Also run this command with the value in the environment variable NAME, for example ["./scripts/set-db-password"]. Its output comes back with the value masked' },
                cwd: { type: 'string', description: 'Working directory for relative paths and the command' },
                ttl_seconds: { type: 'integer', minimum: 60, maximum: 604800, description: 'How long the link stays valid, default ' + DEFAULT_SEND_TTL_SECONDS },
            },
        },
    },
];

class ToolInputError extends Error {}

function textResult(text, isError = false) {
    return { content: [{ type: 'text', text: text }], isError: isError };
}

function truncate(buffer) {
    if (buffer.length <= MAX_OUTPUT_BYTES) {
        return buffer.toString('utf8');
    }
    return buffer.subarray(0, MAX_OUTPUT_BYTES).toString('utf8') + '\n[output truncated after ' + MAX_OUTPUT_BYTES + ' bytes]';
}

export class VaultAskMcpServer {
    constructor({ client, cwd = process.cwd(), waitMs = DEFAULT_WAIT_MS, version = '0.0.0' }) {
        this.client = client;
        this.cwd = cwd;
        this.waitMs = waitMs;
        this.version = version;
        this.pending = new Map();
    }

    async handle(message) {
        if (!message || message.jsonrpc !== '2.0' || typeof message.method !== 'string') {
            return message && message.id !== undefined ? this.error(message.id, -32600, 'Invalid request') : null;
        }
        const isNotification = message.id === undefined;
        try {
            const result = await this.dispatch(message.method, message.params ?? {});
            if (isNotification) {
                return null;
            }
            return { jsonrpc: '2.0', id: message.id, result: result };
        } catch (error) {
            if (isNotification) {
                return null;
            }
            if (error instanceof MethodNotFound) {
                return this.error(message.id, -32601, error.message);
            }
            return this.error(message.id, -32603, error.message);
        }
    }

    error(id, code, text) {
        return { jsonrpc: '2.0', id: id, error: { code: code, message: text } };
    }

    async dispatch(method, params) {
        if (method === 'initialize') {
            return {
                protocolVersion: typeof params.protocolVersion === 'string' ? params.protocolVersion : DEFAULT_PROTOCOL_VERSION,
                capabilities: { tools: {} },
                serverInfo: { name: 'vault-ask', version: this.version },
                instructions: INSTRUCTIONS,
            };
        }
        if (method === 'ping') {
            return {};
        }
        if (method === 'tools/list') {
            return { tools: TOOLS };
        }
        if (method === 'tools/call') {
            return this.callTool(params.name, params.arguments ?? {});
        }
        if (method.startsWith('notifications/')) {
            return {};
        }
        throw new MethodNotFound('Unknown method: ' + method);
    }

    async callTool(name, args) {
        try {
            if (name === 'request_secret') {
                return await this.requestSecret(args);
            }
            if (name === 'run_with_secret') {
                return await this.runWithSecret(args);
            }
            if (name === 'send_secret') {
                return await this.sendSecret(args);
            }
            return textResult('Unknown tool: ' + name, true);
        } catch (error) {
            return textResult(error.message, true);
        }
    }

    targetForRequestSecret(args) {
        const hasEnvFile = typeof args.env_file === 'string' && args.env_file !== '';
        const hasFile = typeof args.file === 'string' && args.file !== '';
        if (hasEnvFile === hasFile) {
            throw new ToolInputError('Give exactly one of env_file or file');
        }
        if (hasFile && (!Array.isArray(args.names) || args.names.length !== 1)) {
            throw new ToolInputError('file takes exactly one name');
        }
        return hasFile ? { kind: PURPOSE_FILE, path: args.file } : { kind: PURPOSE_ENV_FILE, path: args.env_file };
    }

    async requestSecret(args) {
        if (typeof args.request_id === 'string') {
            return this.finish(args.request_id, 'request_secret', async (pending, values) => {
                const written = pending.target.kind === PURPOSE_FILE
                    ? writeSecretFile(pending.target.path, values.get(pending.names[0]), pending.cwd)
                    : writeEnvFile(pending.target.path, values, pending.cwd);
                return textResult(describeReceived(values, 'written to ' + written + ' (permissions 600)'));
            });
        }
        const target = this.targetForRequestSecret(args);
        return this.begin('request_secret', args, target, this.cwd);
    }

    async runWithSecret(args) {
        if (typeof args.request_id === 'string') {
            return this.finish(args.request_id, 'run_with_secret', async (pending, values) => {
                const masker = new Masker([...values.values()]);
                const stdout = [];
                const stderr = [];
                const result = await runCommand(pending.target.argv, values, masker, {
                    cwd: pending.cwd,
                    stdin: 'ignore',
                    stdout: (chunk) => stdout.push(chunk),
                    stderr: (chunk) => stderr.push(chunk),
                });
                return textResult([
                    describeReceived(values, 'passed to the command'),
                    'exit code: ' + result.exitCode,
                    'stdout:\n' + truncate(Buffer.concat(stdout)),
                    'stderr:\n' + truncate(Buffer.concat(stderr)),
                ].join('\n'), result.exitCode !== 0);
            });
        }
        if (!Array.isArray(args.command) || args.command.length === 0 || args.command.some((part) => typeof part !== 'string')) {
            throw new ToolInputError('command must be a list of strings, the program first');
        }
        const cwd = typeof args.cwd === 'string' && args.cwd !== '' ? args.cwd : this.cwd;
        return this.begin('run_with_secret', args, { kind: PURPOSE_COMMAND, argv: args.command }, cwd);
    }

    sendTarget(args) {
        const given = [
            typeof args.env_file === 'string' && args.env_file !== '' ? { kind: PURPOSE_ENV_FILE, path: args.env_file } : null,
            typeof args.file === 'string' && args.file !== '' ? { kind: PURPOSE_FILE, path: args.file } : null,
            args.command !== undefined ? { kind: PURPOSE_COMMAND, argv: args.command } : null,
        ].filter((target) => target !== null);
        if (given.length > 1) {
            throw new ToolInputError('Give at most one of env_file, file or command');
        }
        const target = given[0] ?? null;
        if (target !== null && target.kind === PURPOSE_COMMAND
            && (!Array.isArray(target.argv) || target.argv.length === 0 || target.argv.some((part) => typeof part !== 'string'))) {
            throw new ToolInputError('command must be a list of strings, the program first');
        }
        if (target !== null && target.kind !== PURPOSE_FILE && (typeof args.name !== 'string' || args.name === '')) {
            throw new ToolInputError('env_file and command need name, the variable that carries the value');
        }
        return target;
    }

    sendValue(args, cwd) {
        const hasFile = typeof args.from_file === 'string' && args.from_file !== '';
        const hasEnv = typeof args.from_env === 'string' && args.from_env !== '';
        if (hasFile && hasEnv) {
            throw new ToolInputError('Give at most one of from_file or from_env');
        }
        if ((hasFile || hasEnv) && (args.length !== undefined || args.charset !== undefined)) {
            throw new ToolInputError('length and charset only apply to a generated value');
        }
        if (hasFile) {
            return readSourceValue({ kind: 'file', path: args.from_file }, { cwd: cwd });
        }
        if (hasEnv) {
            return readSourceValue({ kind: 'env', name: args.from_env });
        }
        return generateValue(args.length ?? DEFAULT_LENGTH, args.charset ?? DEFAULT_CHARSET);
    }

    async sendSecret(args) {
        const name = typeof args.name === 'string' && args.name !== '' ? validateNames([args.name])[0] : null;
        const cwd = typeof args.cwd === 'string' && args.cwd !== '' ? args.cwd : this.cwd;
        const target = this.sendTarget(args);
        const value = this.sendValue(args, cwd);
        if (target !== null && target.kind === PURPOSE_ENV_FILE) {
            formatEnvValue(value, name);
        }
        const ttl = Number.isInteger(args.ttl_seconds) ? args.ttl_seconds : DEFAULT_SEND_TTL_SECONDS;
        const label = typeof args.label === 'string' && args.label.trim() !== '' ? args.label : (name ?? '');
        const sent = await createSendLink(this.client, { value: value, label: label, ttlSeconds: ttl });
        const head = [
            'Give the user this one-time link. It shows the value once and expires at ' + sent.expiresAt.toISOString() + ':',
            sent.link,
        ];

        if (target === null) {
            return textResult([...head, describeSent(name, value, 'only in the link')].join('\n'));
        }
        if (target.kind === PURPOSE_ENV_FILE) {
            const written = writeEnvFile(target.path, new Map([[name, value]]), cwd);
            return textResult([...head, describeSent(name, value, 'also written to ' + written + ' (permissions 600)')].join('\n'));
        }
        if (target.kind === PURPOSE_FILE) {
            const written = writeSecretFile(target.path, value, cwd);
            return textResult([...head, describeSent(name, value, 'also written to ' + written + ' (permissions 600)')].join('\n'));
        }

        const stdout = [];
        const stderr = [];
        const result = await runCommand(target.argv, new Map([[name, value]]), new Masker([value]), {
            cwd: cwd,
            stdin: 'ignore',
            stdout: (chunk) => stdout.push(chunk),
            stderr: (chunk) => stderr.push(chunk),
        });
        const lines = [
            ...head,
            describeSent(name, value, 'also passed to the command'),
            'exit code: ' + result.exitCode,
            'stdout:\n' + truncate(Buffer.concat(stdout)),
            'stderr:\n' + truncate(Buffer.concat(stderr)),
        ];
        if (result.exitCode !== 0) {
            lines.push('The command failed: the link holds a value the command may not have applied. Tell the user before they rely on it.');
        }
        return textResult(lines.join('\n'), result.exitCode !== 0);
    }

    async begin(tool, args, target, cwd) {
        const purpose = buildPurpose(target, cwd);
        const ttl = Number.isInteger(args.ttl_seconds) ? args.ttl_seconds : DEFAULT_TTL_SECONDS;
        const started = await startRequest(this.client, args.names, purpose, ttl);
        const requestId = randomBytes(12).toString('base64url');
        this.pending.set(requestId, { ...started, tool: tool, target: target, cwd: cwd });
        return textResult([
            'Show this link to the user and ask them to enter ' + started.names.join(', ') + ':',
            started.link,
            'Then call ' + tool + ' again with request_id "' + requestId + '". The link is valid until ' + started.expiresAt.toISOString() + '.',
        ].join('\n'));
    }

    async finish(requestId, tool, deliver) {
        const pending = this.pending.get(requestId);
        if (!pending || pending.tool !== tool) {
            throw new ToolInputError('Unknown request_id for ' + tool + '. Start a new request without request_id');
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(new WaitTimeout()), this.waitMs);
        let values;
        try {
            values = await completeRequest(this.client, pending, { signal: controller.signal });
        } catch (error) {
            if (error instanceof WaitTimeout) {
                return textResult('The user has not answered yet. Remind them of the link and call ' + tool + ' again with request_id "' + requestId + '".');
            }
            this.pending.delete(requestId);
            throw error;
        } finally {
            clearTimeout(timer);
        }
        this.pending.delete(requestId);
        return deliver(pending, values);
    }
}

class MethodNotFound extends Error {}

class WaitTimeout extends Error {
    constructor() {
        super('wait timeout');
    }
}

export function startStdioServer(server, input = process.stdin, output = process.stdout) {
    const lines = createInterface({ input: input, crlfDelay: Infinity });
    lines.on('line', (line) => {
        if (line.trim() === '') {
            return;
        }
        let message;
        try {
            message = JSON.parse(line);
        } catch {
            output.write(JSON.stringify({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }) + '\n');
            return;
        }
        server.handle(message).then((response) => {
            if (response !== null) {
                output.write(JSON.stringify(response) + '\n');
            }
        }, (error) => {
            process.stderr.write('vault-ask-mcp: ' + error.message + '\n');
        });
    });
    return lines;
}

export function serveStdio(version) {
    const client = new VaultClient({
        server: process.env.VAULT_ASK_SERVER && process.env.VAULT_ASK_SERVER !== '' ? process.env.VAULT_ASK_SERVER : DEFAULT_SERVER,
        apiKey: process.env.VAULT_ASK_API_KEY ?? null,
        version: version,
    });
    const lines = startStdioServer(new VaultAskMcpServer({ client: client, version: version }));
    return new Promise((resolveClosed) => lines.on('close', resolveClosed));
}
