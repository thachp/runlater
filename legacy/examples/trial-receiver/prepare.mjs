// Offline preparation only. No deployment, provider access, key output or identity replacement.
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {generateKeyPairSync, randomBytes, sign} from 'node:crypto';
import {manifest, manifestBytes} from './protocol.mjs';
const repository = path.resolve(fileURLToPath(new URL('../../', import.meta.url)));
function privateParent(output) {
  if (typeof output !== 'string' || !path.isAbsolute(output) || path.normalize(output) !== output
    || output === repository || output.startsWith(repository + path.sep)) throw Error();
  const parent = path.dirname(output); let child = null;
  for (let current = parent;; current = path.dirname(current)) {
    const stat = fs.lstatSync(current);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw Error();
    if (stat.mode & 0o022) {
      // A sticky root/current-user directory may protect our owned descendant (for example /tmp).
      if (!(stat.mode & 0o1000) || ![0, process.getuid()].includes(stat.uid) || child === null
        || fs.lstatSync(child).uid !== process.getuid()) throw Error();
    }
    if (current === path.dirname(current)) break;
    child = current;
  }
  const stat = fs.lstatSync(parent);
  if ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid()) throw Error();
  if (fs.existsSync(output)) throw Error();
}
export function prepareReceiver({releaseId, projectId, callbackUrl, outputDirectory}) {
  privateParent(outputDirectory);
  if (typeof releaseId !== 'string' || !/^[A-Za-z0-9_-]{1,32}$/.test(releaseId)
    || typeof projectId !== 'string' || !/^p_[a-f0-9]{60}$/.test(projectId)) throw Error('invalid_receiver_setup');
  const url = new URL(callbackUrl);
  if (url.href !== callbackUrl || url.protocol !== 'https:' || url.username || url.password || url.port
    || url.pathname !== '/callback' || url.search || url.hash
    || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.workers\.dev$/.test(url.hostname)) throw Error('invalid_receiver_setup');
  let created = false; const files = [];
  try {
    fs.mkdirSync(outputDirectory, {mode: 0o700}); created = true;
    const st = fs.lstatSync(outputDirectory);
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid() || (st.mode & 0o777) !== 0o700) throw Error();
    const pair = generateKeyPairSync('ed25519'), now = Date.now();
    const m = {version: 1, release_id: releaseId, project_id: projectId, url: callbackUrl,
      receiver_public_key: pair.publicKey.export({format: 'der', type: 'spki'}).subarray(12).toString('hex'),
      pairing_id: randomBytes(32).toString('hex'), issued_at_ms: now, expires_at_ms: now + 300000};
    m.signature = sign(null, Buffer.from(manifestBytes(m)), pair.privateKey).toString('hex'); manifest(m);
    for (const [name, value] of [['receiver-setup-private.pem', pair.privateKey.export({format: 'pem', type: 'pkcs8'})],
      ['receiver-manifest.json', JSON.stringify(m)]]) {
      const destination = path.join(outputDirectory, name);
      const fd = fs.openSync(destination, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_NOFOLLOW, 0o600);
      files.push(destination);
      try {fs.writeFileSync(fd, value); fs.fsyncSync(fd);} finally {fs.closeSync(fd);}
    }
    return m;
  } catch {
    // Only exclusively created files and our empty directory, never recursive traversal.
    for (const file of files) {try {fs.unlinkSync(file);} catch {}}
    if (created) {try {fs.rmdirSync(outputDirectory);} catch {}}
    throw Error('receiver_preparation_failed');
  }
}
export function argumentsFor(argv) {
  if (argv.length !== 8) throw Error();
  const accepted = new Map([['--release', 'releaseId'], ['--project', 'projectId'], ['--url', 'callbackUrl'], ['--output-dir', 'outputDirectory']]);
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    const key = accepted.get(argv[i]); if (!key || Object.hasOwn(options, key) || !argv[i + 1]) throw Error();
    options[key] = argv[i + 1];
  }
  return options;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {process.stdout.write(JSON.stringify(prepareReceiver(argumentsFor(process.argv.slice(2)))) + '\n');}
  catch {
    process.stderr.write('Receiver preparation failed. Use a new output directory outside the repository under an existing owner-only, non-symlink parent. No deployment was attempted.\n');
    process.exitCode = 1;
  }
}
