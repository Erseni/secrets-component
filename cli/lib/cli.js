import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_SERVER, VaultClient } from './client.js';
import { Masker } from './mask.js';
import { serveStdio } from './mcp.js';
import { PURPOSE_COMMAND, PURPOSE_ENV_FILE, PURPOSE_FILE, buildPurpose, validateNames } from './purpose.js';
import { DEFAULT_TTL_SECONDS, completeRequest, describeReceived, startRequest } from './request.js';
import { CHARSETS, DEFAULT_CHARSET, DEFAULT_LENGTH, DEFAULT_SEND_TTL_SECONDS, createSendLink, describeSent, generateValue, readSourceValue } from './send.js';
import { formatEnvValue, runCommand, writeEnvFile, writeSecretFile } from './targets.js';

const VERSION = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf8')).version;

const USAGE = `vault-ask ${VERSION}

Ask a person for a secret through Erseni Vault and hand it to exactly one
destination, or send a person a secret as a one-time link. The value is never
printed.

Usage:
  vault-ask [options] NAME [NAME ...] -- <command> [arguments ...]
  vault-ask [options] NAME [NAME ...] --env-file <path>
  vault-ask [options] NAME --file <path>
  vault-ask send [send options] [NAME] [--env-file <path> | --file <path> | -- <command> ...]
  vault-ask mcp

Destinations:
  -- <command>        Run the command with each value as an environment variable
                      of that process only. Its output is masked. (default)
  --env-file <path>   Write NAME=value lines into a .env file (permissions 600)
  --file <path>       Write one value into a file (permissions 600)

Options:
  --server <url>      Vault server (default: $VAULT_ASK_SERVER or ${DEFAULT_SERVER})
  --ttl <seconds>     How long the link stays valid (default: ${DEFAULT_TTL_SECONDS})
  -h, --help          Show this help
  --version           Show the version

Send options (vault-ask send):
  --length <n>        Length of the generated value (default: ${DEFAULT_LENGTH})
  --charset <set>     ${Object.keys(CHARSETS).join(', ')} (default: ${DEFAULT_CHARSET})
  --from-file <path>  Send the content of this file instead of a generated value
  --from-env <VAR>    Send the value of this environment variable instead
  --label <text>      Label shown above the value (default: NAME)
  --ttl <seconds>     How long the link stays valid (default: ${DEFAULT_SEND_TTL_SECONDS})
  The same value can also go to one destination, so that the system and the
  link hold the same value: --env-file and -- <command> need NAME.

Environment:
  VAULT_ASK_API_KEY   API key from your Vault account: no proof of work, the
                      limits of your plan, requests visible in your dashboard
`;

export function parseArguments(argv, env = process.env) {
    const options = {
        server: env.VAULT_ASK_SERVER && env.VAULT_ASK_SERVER !== '' ? env.VAULT_ASK_SERVER : DEFAULT_SERVER,
        ttl: DEFAULT_TTL_SECONDS,
        names: [],
        target: null,
        help: false,
        version: false,
    };
    const setTarget = (target) => {
        if (options.target !== null) {
            throw new Error('Choose exactly one destination: -- <command>, --env-file or --file');
        }
        options.target = target;
    };
    const requireValue = (flag, value) => {
        if (value === undefined || value === '') {
            throw new Error(flag + ' needs a value');
        }
        return value;
    };

    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (argument === '--') {
            setTarget({ kind: PURPOSE_COMMAND, argv: argv.slice(index + 1) });
            break;
        }
        if (argument === '-h' || argument === '--help') {
            options.help = true;
        } else if (argument === '--version') {
            options.version = true;
        } else if (argument === '--server') {
            options.server = requireValue(argument, argv[++index]);
        } else if (argument === '--ttl') {
            const raw = requireValue(argument, argv[++index]);
            if (!/^\d+$/.test(raw)) {
                throw new Error('--ttl needs a number of seconds');
            }
            options.ttl = Number(raw);
        } else if (argument === '--env-file') {
            setTarget({ kind: PURPOSE_ENV_FILE, path: requireValue(argument, argv[++index]) });
        } else if (argument === '--file') {
            setTarget({ kind: PURPOSE_FILE, path: requireValue(argument, argv[++index]) });
        } else if (argument.startsWith('-')) {
            throw new Error('Unknown option: ' + argument + '. There is no option that prints the value');
        } else {
            options.names.push(argument);
        }
    }

    if (options.help || options.version) {
        return options;
    }
    if (options.target === null) {
        throw new Error('Choose a destination: -- <command>, --env-file <path> or --file <path>');
    }
    if (options.target.kind === PURPOSE_COMMAND && options.target.argv.length === 0) {
        throw new Error('Name the command after --');
    }
    if (options.target.kind === PURPOSE_FILE && options.names.length !== 1) {
        throw new Error('--file takes exactly one name');
    }
    return options;
}

export function parseSendArguments(argv, env = process.env) {
    const options = {
        server: env.VAULT_ASK_SERVER && env.VAULT_ASK_SERVER !== '' ? env.VAULT_ASK_SERVER : DEFAULT_SERVER,
        ttl: DEFAULT_SEND_TTL_SECONDS,
        name: null,
        label: null,
        length: null,
        charset: null,
        source: null,
        target: null,
        help: false,
    };
    const setTarget = (target) => {
        if (options.target !== null) {
            throw new Error('Choose at most one destination: -- <command>, --env-file or --file');
        }
        options.target = target;
    };
    const setSource = (source) => {
        if (options.source !== null) {
            throw new Error('Choose at most one of --from-file and --from-env');
        }
        options.source = source;
    };
    const requireValue = (flag, value) => {
        if (value === undefined || value === '') {
            throw new Error(flag + ' needs a value');
        }
        return value;
    };
    const requireNumber = (flag, value) => {
        const raw = requireValue(flag, value);
        if (!/^\d+$/.test(raw)) {
            throw new Error(flag + ' needs a number');
        }
        return Number(raw);
    };

    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (argument === '--') {
            setTarget({ kind: PURPOSE_COMMAND, argv: argv.slice(index + 1) });
            break;
        }
        if (argument === '-h' || argument === '--help') {
            options.help = true;
        } else if (argument === '--server') {
            options.server = requireValue(argument, argv[++index]);
        } else if (argument === '--ttl') {
            options.ttl = requireNumber(argument, argv[++index]);
        } else if (argument === '--length') {
            options.length = requireNumber(argument, argv[++index]);
        } else if (argument === '--charset') {
            options.charset = requireValue(argument, argv[++index]);
        } else if (argument === '--label') {
            options.label = requireValue(argument, argv[++index]);
        } else if (argument === '--from-file') {
            setSource({ kind: 'file', path: requireValue(argument, argv[++index]) });
        } else if (argument === '--from-env') {
            setSource({ kind: 'env', name: requireValue(argument, argv[++index]) });
        } else if (argument === '--env-file') {
            setTarget({ kind: PURPOSE_ENV_FILE, path: requireValue(argument, argv[++index]) });
        } else if (argument === '--file') {
            setTarget({ kind: PURPOSE_FILE, path: requireValue(argument, argv[++index]) });
        } else if (argument.startsWith('-')) {
            throw new Error('Unknown option: ' + argument + '. There is no option that prints the value');
        } else if (options.name === null) {
            options.name = validateNames([argument])[0];
        } else {
            throw new Error('vault-ask send takes at most one name');
        }
    }

    if (options.help) {
        return options;
    }
    if (options.source !== null && (options.length !== null || options.charset !== null)) {
        throw new Error('--length and --charset only apply to a generated value, not to --from-file or --from-env');
    }
    if (options.target !== null && options.target.kind === PURPOSE_COMMAND && options.target.argv.length === 0) {
        throw new Error('Name the command after --');
    }
    if (options.target !== null && options.target.kind !== PURPOSE_FILE && options.name === null) {
        throw new Error('Name the value, for example vault-ask send DB_PASSWORD ' + (options.target.kind === PURPOSE_COMMAND ? '-- <command>' : '--env-file .env'));
    }
    return options;
}

function say(message) {
    process.stderr.write(message.split('\n').map((line) => 'vault-ask: ' + line).join('\n') + '\n');
}

async function deliverSent(options, value) {
    const target = options.target;
    if (target === null) {
        say(describeSent(options.name, value, 'only in the link'));
        return 0;
    }
    if (target.kind === PURPOSE_ENV_FILE) {
        const written = writeEnvFile(target.path, new Map([[options.name, value]]));
        say(describeSent(options.name, value, 'also written to ' + written + ' (permissions 600)'));
        return 0;
    }
    if (target.kind === PURPOSE_FILE) {
        const written = writeSecretFile(target.path, value);
        say(describeSent(options.name, value, 'also written to ' + written + ' (permissions 600)'));
        return 0;
    }
    say(describeSent(options.name, value, 'also passed to the command'));
    const result = await runCommand(target.argv, new Map([[options.name, value]]), new Masker([value]));
    if (result.exitCode !== 0) {
        say('the command exited with ' + result.exitCode + ': the link holds a value the command may not have applied');
    }
    return result.exitCode;
}

export async function mainSend(argv) {
    let options;
    try {
        options = parseSendArguments(argv);
    } catch (error) {
        say(error.message);
        say('run vault-ask --help for the usage');
        return 2;
    }
    if (options.help) {
        process.stdout.write(USAGE);
        return 0;
    }

    const value = options.source !== null
        ? readSourceValue(options.source)
        : generateValue(options.length ?? DEFAULT_LENGTH, options.charset ?? DEFAULT_CHARSET);
    if (options.target !== null && options.target.kind === PURPOSE_ENV_FILE) {
        formatEnvValue(value, options.name);
    }

    const client = new VaultClient({ server: options.server, apiKey: process.env.VAULT_ASK_API_KEY ?? null, version: VERSION });
    const sent = await createSendLink(client, { value: value, label: options.label ?? options.name ?? '', ttlSeconds: options.ttl });

    say('give this link to the person, it shows the value once:');
    process.stderr.write(sent.link + '\n');
    say('the link is valid until ' + sent.expiresAt.toISOString());

    return deliverSent(options, value);
}

export async function main(argv) {
    if (argv[0] === 'send') {
        return mainSend(argv.slice(1));
    }
    if (argv[0] === 'mcp') {
        await serveStdio(VERSION);
        return 0;
    }
    let options;
    try {
        options = parseArguments(argv);
    } catch (error) {
        say(error.message);
        say('run vault-ask --help for the usage');
        return 2;
    }
    if (options.help) {
        process.stdout.write(USAGE);
        return 0;
    }
    if (options.version) {
        process.stdout.write(VERSION + '\n');
        return 0;
    }

    const client = new VaultClient({ server: options.server, apiKey: process.env.VAULT_ASK_API_KEY ?? null, version: VERSION });
    const purpose = buildPurpose(options.target, process.cwd());
    const pending = await startRequest(client, options.names, purpose, options.ttl);

    say('open this link and enter ' + pending.names.join(', ') + ':');
    process.stderr.write(pending.link + '\n');
    say('waiting for the answer until ' + pending.expiresAt.toISOString());

    const values = await completeRequest(client, pending, {
        onReconnect: (reason, delay) => say('status stream interrupted (' + reason + '), checking again in ' + Math.round(delay / 1000) + ' s'),
    });

    if (options.target.kind === PURPOSE_ENV_FILE) {
        const written = writeEnvFile(options.target.path, values);
        say(describeReceived(values, 'written to ' + written + ' (permissions 600)'));
        return 0;
    }
    if (options.target.kind === PURPOSE_FILE) {
        const written = writeSecretFile(options.target.path, values.get(pending.names[0]));
        say(describeReceived(values, 'written to ' + written + ' (permissions 600)'));
        return 0;
    }

    say(describeReceived(values, 'passed to the command'));
    const masker = new Masker([...values.values()]);
    const result = await runCommand(options.target.argv, values, masker);
    return result.exitCode;
}

export function run() {
    const argv = process.argv.slice(2);
    if (argv[0] === '--') {
        argv.shift();
    }
    main(argv).then((code) => {
        process.exitCode = code;
    }, (error) => {
        say(error.message);
        process.exitCode = 1;
    });
}
