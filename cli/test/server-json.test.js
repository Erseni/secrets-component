import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

const packageJson = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const serverJson = JSON.parse(readFileSync(new URL('../server.json', import.meta.url), 'utf8'));

test('server.json names the server like the mcpName of the npm package', () => {
    assert.equal(serverJson.name, packageJson.mcpName);
});

test('server.json carries the version of package.json, so the MCP Registry gets the release that npm gets', () => {
    assert.equal(serverJson.version, packageJson.version);
    assert.deepEqual(serverJson.packages.map((entry) => [entry.identifier, entry.version]), [[packageJson.name, packageJson.version]]);
});
