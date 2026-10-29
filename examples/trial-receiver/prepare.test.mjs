import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {prepareReceiver, argumentsFor} from './prepare.mjs';
import {manifest, privateKey} from './protocol.mjs';
const here = fileURLToPath(new URL('./', import.meta.url));
test('offline ephemeral preparation writes exclusive owner-only files and emits only public manifest', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'receiver-prepare-test-')); fs.chmodSync(root, 0o700);
  const output = path.join(root, 'new'), options = {releaseId: 'fixture', projectId: 'p_' + 'c'.repeat(60),
    callbackUrl: 'https://receiver.account.workers.dev/callback', outputDirectory: output};
  try {
    const m = prepareReceiver(options); assert.deepEqual(manifest(m), m);
    assert.equal(fs.statSync(output).mode & 0o777, 0o700);
    for (const name of fs.readdirSync(output)) assert.equal(fs.statSync(path.join(output, name)).mode & 0o777, 0o600);
    const secret = fs.readFileSync(path.join(output, 'receiver-setup-private.pem'), 'utf8');
    assert.ok(privateKey(secret, m)); assert.ok(!JSON.stringify(m).includes('PRIVATE KEY'));
    assert.throws(() => prepareReceiver(options)); assert.equal(fs.readFileSync(path.join(output, 'receiver-setup-private.pem'), 'utf8'), secret);
    const second = path.join(root, 'cli'), args = ['--release', 'fixture', '--project', options.projectId, '--url', options.callbackUrl, '--output-dir', second];
    const result = spawnSync(process.execPath, [path.join(here, 'prepare.mjs'), ...args], {encoding: 'utf8'});
    assert.equal(result.status, 0); assert.equal(result.stderr, ''); assert.ok(manifest(JSON.parse(result.stdout)));
    assert.ok(!result.stdout.includes('PRIVATE KEY')); assert.ok(!result.stdout.includes(fs.readFileSync(path.join(second, 'receiver-setup-private.pem'), 'utf8')));
  } finally {fs.rmSync(root, {recursive: true});}
});
test('unsafe parents/symlinks/repo paths/existing outputs fail without replacement', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'receiver-prepare-negative-')); fs.chmodSync(root, 0o700);
  const base = {releaseId: 'fixture', projectId: 'p_' + 'd'.repeat(60), callbackUrl: 'https://receiver.account.workers.dev/callback'};
  try {
    const unsafe = path.join(root, 'unsafe'); fs.mkdirSync(unsafe, {mode: 0o755});
    assert.throws(() => prepareReceiver({...base, outputDirectory: path.join(unsafe, 'new')})); assert.deepEqual(fs.readdirSync(unsafe), []);
    const writable = path.join(root, 'writable'); fs.mkdirSync(writable, {mode: 0o777}); fs.chmodSync(writable, 0o777);
    const privateChild = path.join(writable, 'private'); fs.mkdirSync(privateChild, {mode: 0o700});
    assert.throws(() => prepareReceiver({...base, outputDirectory: path.join(privateChild, 'new')}));
    assert.deepEqual(fs.readdirSync(privateChild), []);
    const link = path.join(root, 'link'); fs.symlinkSync(root, link);
    assert.throws(() => prepareReceiver({...base, outputDirectory: path.join(link, 'new')}));
    const dangling = path.join(root, 'dangling'); fs.symlinkSync(path.join(root, 'absent'), dangling);
    assert.throws(() => prepareReceiver({...base, outputDirectory: dangling})); assert.ok(fs.lstatSync(dangling).isSymbolicLink());
    assert.throws(() => prepareReceiver({...base, outputDirectory: path.join(here, 'no-secret-output')}));
    assert.throws(() => prepareReceiver({...base, callbackUrl: 'https://evil.example/callback', outputDirectory: path.join(root, 'bad')}));
    assert.equal(fs.existsSync(path.join(root, 'bad')), false);
    assert.throws(() => argumentsFor(['--release', 'x']));
    assert.throws(() => argumentsFor(['--release', 'x', '--release', 'x', '--url', 'x', '--output-dir', 'x']));
  } finally {fs.rmSync(root, {recursive: true});}
});
test('a partial local write failure removes only newly created secret files and directory', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'receiver-prepare-failure-')); fs.chmodSync(root, 0o700);
  const output = path.join(root, 'new'), original = fs.writeFileSync; let writes = 0;
  try {
    fs.writeFileSync = (...args) => {if (++writes === 2) throw Error('fixture write failure'); return original(...args);};
    assert.throws(() => prepareReceiver({releaseId: 'fixture', projectId: 'p_' + 'e'.repeat(60),
      callbackUrl: 'https://receiver.account.workers.dev/callback', outputDirectory: output}), /receiver_preparation_failed/);
    assert.equal(fs.existsSync(output), false); assert.deepEqual(fs.readdirSync(root), []);
  } finally {fs.writeFileSync = original; fs.rmSync(root, {recursive: true});}
});
