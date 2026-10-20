import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, isAbsolute, relative, resolve, sep } from 'node:path';

export const FORBIDDEN_COMMANDS = new Set(['env', 'printenv', 'echo', 'printf', 'sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'csh', 'tcsh', 'set', 'export', 'declare']);

const FILE_TOOLS = ['Read', 'Edit', 'MultiEdit', 'Write', 'NotebookEdit', 'NotebookRead', 'Grep', 'Glob'];
const PATH_FIELDS = ['file_path', 'path', 'notebook_path'];
const WRAPPERS = ['sudo', 'exec', 'nice', 'nohup', 'command', 'builtin', 'time', 'xargs', 'env', 'timeout', 'ionice', 'stdbuf'];
const WRAPPER_VALUE_OPTIONS = {
    sudo: ['-u', '-g', '-C', '-D', '-h', '-p', '-r', '-t', '-U', '-T'],
    nice: ['-n'],
    ionice: ['-c', '-n', '-p', '-P', '-u'],
    env: ['-u', '-C', '-S'],
    timeout: ['-s', '-k', '--signal', '--kill-after'],
    stdbuf: ['-i', '-o', '-e'],
    xargs: ['-a', '-d', '-E', '-I', '-L', '-n', '-P', '-s'],
    time: ['-f', '-o'],
    exec: ['-a'],
};
const WRAPPER_POSITIONALS = { timeout: 1 };
const COPY_PROGRAMS = new Set(['cp', 'scp', 'rsync']);
const ALWAYS_RECURSIVE = new Set(['rg', 'ag', 'ack', 'ack-grep', 'pt', 'sift', 'tar', 'bsdtar', '7z', '7za']);
const RECURSIVE_WITH_FLAG = {
    grep: ['r', 'R'],
    egrep: ['r', 'R'],
    fgrep: ['r', 'R'],
    ugrep: ['r', 'R'],
    ug: ['r', 'R'],
    cp: ['r', 'R', 'a'],
    scp: ['r'],
    rsync: ['r', 'a'],
    diff: ['r'],
    zip: ['r'],
};
const RECURSIVE_LONG_FLAGS = ['--recursive', '--dereference-recursive', '--archive', '--directories=recurse'];
const PATTERN_FIRST = new Set(['grep', 'egrep', 'fgrep', 'ugrep', 'ug', 'rg', 'ag', 'ack', 'ack-grep', 'pt', 'sift']);
const FIND_ACTIONS = ['-exec', '-execdir', '-ok', '-okdir'];
const GLOB_CHARACTERS = /[*?[]/;

function splitSegments(command) {
    return command
        .split(/[;&|\n()`]+/)
        .map((segment) => segment.split(/[\s<>]+/).filter((word) => word !== '').map((word) => word.replace(/^['"]|['"]$/g, '')))
        .filter((words) => words.length > 0);
}

function expandHome(word) {
    if (word === '~') {
        return homedir();
    }
    return word.startsWith('~/') ? homedir() + word.slice(1) : word;
}

function resolveWord(word, cwd) {
    return resolve(cwd, expandHome(word));
}

function isAncestor(directory, path) {
    const rest = relative(directory, path);
    return rest !== '' && rest !== '..' && !rest.startsWith('..' + sep) && !isAbsolute(rest);
}

function segmentPattern(segment) {
    let pattern = '';
    for (let index = 0; index < segment.length; index++) {
        const character = segment[index];
        if (character === '*') {
            pattern += '[^/]*';
        } else if (character === '?') {
            pattern += '[^/]';
        } else if (character === '[' && segment.indexOf(']', index + 2) !== -1) {
            const end = segment.indexOf(']', index + 2);
            const body = segment.slice(index + 1, end).replace(/^!/, '^').replace(/\\/g, '\\\\');
            pattern += '[' + body + ']';
            index = end;
        } else {
            pattern += character.replace(/[.+^${}()|\\/\]]/g, '\\$&');
        }
    }
    return new RegExp('^' + pattern + '$');
}

function globMatches(absolutePattern, path) {
    const patternSegments = absolutePattern.split(sep);
    const pathSegments = path.split(sep);
    if (patternSegments.length !== pathSegments.length) {
        return false;
    }
    return patternSegments.every((segment, index) => {
        const name = pathSegments[index];
        if (!GLOB_CHARACTERS.test(segment)) {
            return segment === name;
        }
        if (name.startsWith('.') && !segment.startsWith('.')) {
            return false;
        }
        return segmentPattern(segment).test(name);
    });
}

function operandValue(word) {
    if (word.startsWith('--')) {
        const equals = word.indexOf('=');
        return equals === -1 ? null : word.slice(equals + 1);
    }
    if (word.startsWith('-')) {
        return null;
    }
    return word.replace(/^[A-Za-z_][A-Za-z0-9_]*=/, '');
}

function programIndex(words) {
    let index = 0;
    while (index < words.length) {
        if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(words[index])) {
            index += 1;
            continue;
        }
        const wrapper = basename(words[index]);
        if (!WRAPPERS.includes(wrapper)) {
            break;
        }
        index += 1;
        const valueOptions = WRAPPER_VALUE_OPTIONS[wrapper] ?? [];
        while (index < words.length && words[index].startsWith('-')) {
            const option = words[index];
            index += 1;
            if (option === '--') {
                break;
            }
            if (valueOptions.includes(option)) {
                index += 1;
            }
        }
        index += Math.min(WRAPPER_POSITIONALS[wrapper] ?? 0, words.length - index);
    }
    return index;
}

function isRecursiveReader(program, args, commandHasXargs) {
    if (ALWAYS_RECURSIVE.has(program)) {
        return true;
    }
    if (program === 'find') {
        return commandHasXargs || args.some((word) => FIND_ACTIONS.includes(word));
    }
    const letters = RECURSIVE_WITH_FLAG[program];
    if (letters === undefined) {
        return false;
    }
    return args.some((word, index) => RECURSIVE_LONG_FLAGS.includes(word)
        || (word === '-d' && args[index + 1] === 'recurse')
        || (/^-[A-Za-z]+$/.test(word) && letters.some((letter) => word.includes(letter))));
}

function searchedDirectories(program, args, cwd) {
    const operands = args.filter((word) => !word.startsWith('-'));
    const givesPatternAsOption = args.some((word) => /^-[A-Za-z]*[ef]$/.test(word) || /^--(regexp|file)(=|$)/.test(word));
    const withoutPattern = PATTERN_FIRST.has(program) && !givesPatternAsOption ? operands.slice(1) : operands;
    const paths = COPY_PROGRAMS.has(program) && withoutPattern.length > 1 ? withoutPattern.slice(0, -1) : withoutPattern;
    const existing = paths.map((word) => resolveWord(word, cwd)).filter((path) => existsSync(path));
    return existing.length > 0 ? existing : [cwd];
}

function readsWrittenPath(words, writtenPaths, cwd, commandHasXargs) {
    const start = programIndex(words);
    if (start >= words.length) {
        return null;
    }
    const program = basename(words[start]);
    const args = words.slice(start + 1);

    for (const word of words.slice(start)) {
        const value = operandValue(word);
        if (value === null || value === '') {
            continue;
        }
        const target = resolveWord(value, cwd);
        for (const writtenPath of writtenPaths) {
            if (target === writtenPath || (GLOB_CHARACTERS.test(value) && globMatches(target, writtenPath))) {
                return writtenPath;
            }
        }
    }

    if (!isRecursiveReader(program, args, commandHasXargs)) {
        return null;
    }
    for (const directory of searchedDirectories(program, args, cwd)) {
        const reached = writtenPaths.find((writtenPath) => isAncestor(directory, writtenPath));
        if (reached !== undefined) {
            return reached;
        }
    }
    return null;
}

export function forbiddenVaultAskCommand(argv) {
    const vaultAskIndex = argv.findIndex((word) => basename(word) === 'vault-ask');
    if (vaultAskIndex === -1) {
        return null;
    }
    const separator = argv.indexOf('--', vaultAskIndex + 1);
    if (separator === -1 || separator + 1 >= argv.length) {
        return null;
    }
    const commandWords = argv.slice(separator + 1);
    const commandIndex = programIndex(commandWords);
    const programWord = commandIndex < commandWords.length ? commandWords[commandIndex] : commandWords[commandWords.length - 1];
    const program = programWord !== undefined ? basename(programWord) : '';
    return FORBIDDEN_COMMANDS.has(program) ? program : null;
}

function evaluateBash(command, writtenPaths, cwd) {
    const segments = splitSegments(command);
    const commandHasXargs = segments.some((words) => words.some((word) => basename(word) === 'xargs'));
    let directory = cwd;
    for (const words of segments) {
        const forbidden = forbiddenVaultAskCommand(words);
        if (forbidden !== null) {
            return 'vault-ask with ' + forbidden + ' as the command would only print the value. Run the program that actually needs it, for example vault-ask DB_PASSWORD -- psql ...';
        }
        if (words[0] === 'cd') {
            directory = words[1] === undefined ? homedir() : resolveWord(words[1], directory);
            continue;
        }
        if (basename(words[programIndex(words)] ?? '') === 'vault-ask') {
            continue;
        }
        const reached = readsWrittenPath(words, writtenPaths, directory, commandHasXargs);
        if (reached !== null) {
            return reached + ' was written by vault-ask and holds a secret, and this command would read it, by name, through a glob or by searching a directory above it. Pass the file path to the program that needs it, and search a directory that does not contain the file.';
        }
    }
    return null;
}

function grepGlobExcludes(glob, directory, writtenPath) {
    if (typeof glob !== 'string' || glob === '' || /[!?[\]]/.test(glob)) {
        return false;
    }
    const alternatives = /^(.*)\{([^{}]*)\}(.*)$/.exec(glob);
    const patterns = alternatives === null ? [glob] : alternatives[2].split(',').map((middle) => alternatives[1] + middle + alternatives[3]);
    const relativePath = relative(directory, writtenPath);
    return !patterns.some((pattern) => {
        const expression = new RegExp('^' + pattern.split('**/').map((part) => part.split('*').map((piece) => piece.replace(/[.+^${}()|[\]\\?]/g, '\\$&')).join('[^/]*')).join('(?:.*/)?') + '$');
        return expression.test(pattern.includes('/') ? relativePath : basename(writtenPath));
    });
}

export function evaluate(input, writtenPaths) {
    const tool = typeof input.tool_name === 'string' ? input.tool_name : '';
    const toolInput = input.tool_input && typeof input.tool_input === 'object' ? input.tool_input : {};
    const cwd = typeof input.cwd === 'string' ? input.cwd : process.cwd();

    if (tool === 'Bash' && typeof toolInput.command === 'string') {
        return evaluateBash(toolInput.command, writtenPaths, cwd);
    }

    const commandTool = ['run_with_secret', 'send_secret'].find((name) => tool.startsWith('mcp__') && tool.endsWith('__' + name));
    if (commandTool !== undefined && Array.isArray(toolInput.command)) {
        const program = basename(String(toolInput.command[0] ?? ''));
        if (FORBIDDEN_COMMANDS.has(program)) {
            return commandTool + ' with ' + program + ' as the command would only print the value.';
        }
        return null;
    }

    if (FILE_TOOLS.includes(tool)) {
        for (const field of PATH_FIELDS) {
            if (typeof toolInput[field] !== 'string' || toolInput[field] === '') {
                continue;
            }
            const target = resolve(cwd, toolInput[field]);
            if (writtenPaths.includes(target)) {
                return target + ' was written by vault-ask and holds a secret. It stays out of this conversation.';
            }
        }
    }

    if (tool === 'Grep') {
        const directory = typeof toolInput.path === 'string' && toolInput.path !== '' ? resolve(cwd, toolInput.path) : cwd;
        const reached = writtenPaths.find((writtenPath) => isAncestor(directory, writtenPath) && !grepGlobExcludes(toolInput.glob, directory, writtenPath));
        if (reached !== undefined) {
            return reached + ' was written by vault-ask and holds a secret, and this search would include it. Search a directory that does not contain it, or narrow the search with a glob that leaves it out.';
        }
    }
    return null;
}
