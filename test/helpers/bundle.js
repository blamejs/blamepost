// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Data volumes, the bundles `backup run` takes of them, and the altered
 * bundles a restore has to refuse.
 *
 * Every bundle here is taken through the shipped binary. The altered ones
 * are built from those at run time, inside the test's own temporary
 * directory, and model two different attackers.
 *
 * `resign` edits a manifest and signs it with a fresh Ed25519 key. That
 * needs no secret: a manifest carries the public key its signature is
 * checked under, so anyone who can write the backup location can do it.
 *
 * `sealEntry` replaces or adds one file, sealed under the bundle
 * passphrase, and signs the manifest with the volume's own audit signing
 * key. That needs both passphrases, so it stands in for a bundle an older
 * release wrote rather than for an attacker.
 */

var nodeCrypto = require("node:crypto");
var nodeFs     = require("node:fs");
var nodePath   = require("node:path");

var helpers   = require("./index");
var cliHelper = require("./cli");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");

var HOSTNAME          = "mx.example.com";
var DOMAIN            = "example.com";
var VAULT_PASSPHRASE  = "a long enough vault passphrase for one test run";
var BUNDLE_PASSPHRASE = "a different passphrase that only the bundle uses";
var ACCOUNT_PASSWORD  = "quiet lantern bicycle 4291";

/**
 * volume(prefix) creates a temporary root holding an empty data directory
 * at the mode the server requires, a working directory for the decrypted
 * database copy, a storage directory for bundles and a bundle passphrase
 * file. Nothing is opened.
 */
function volume(prefix) {
  var root = helpers.tempDir(prefix);
  var dataDir = helpers.dataDir(root);
  var workDir = nodePath.join(root, "work");
  var storageDir = nodePath.join(root, "bundles");
  var passFile = nodePath.join(root, "bundle.pass");
  nodeFs.mkdirSync(workDir, { recursive: true });
  nodeFs.writeFileSync(passFile, BUNDLE_PASSPHRASE + "\n", { mode: 0o600 });
  return {
    root:       root,
    dataDir:    dataDir,
    workDir:    workDir,
    storageDir: storageDir,
    passFile:   passFile,
  };
}

/**
 * configFor(vol, env) loads the configuration the binary would load for
 * this volume, with `env` layered over the defaults.
 */
function configFor(vol, env) {
  return config.load({
    env: Object.assign({
      BLAMEPOST_HOSTNAME:         HOSTNAME,
      BLAMEPOST_DATA_DIR:         vol.dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    }, env || {}),
    cwd: vol.root,
  });
}

/**
 * cliFor(vol, opts) is the spawner from `helpers/cli`, bound to the volume.
 * `opts.env` and `opts.execArgv` pass through unchanged.
 */
function cliFor(vol, opts) {
  opts = opts || {};
  return cliHelper.create({
    dataDir:         vol.dataDir,
    workDir:         vol.workDir,
    hostname:        HOSTNAME,
    vaultPassphrase: VAULT_PASSPHRASE,
    env:             opts.env,
    execArgv:        opts.execArgv,
  });
}

function _message(address, subject) {
  return Buffer.from(
    "From: Sender <sender@example.net>\r\n" +
    "To: " + address + "\r\n" +
    "Subject: " + subject + "\r\n" +
    "Date: Mon, 01 Jan 2024 00:00:00 +0000\r\n" +
    "Message-Id: <" + subject.replace(/[^A-Za-z0-9]/g, "") + "@example.net>\r\n" +
    "\r\n" +
    "The body of " + subject + ".\r\n", "utf8");
}

/**
 * addAccount(cfg, localPart) opens the store in this process, hosts the
 * test domain when it is not hosted yet, creates the account, delivers one
 * message to its inbox and closes the store. Returns the address.
 */
async function addAccount(cfg, localPart) {
  var address = localPart + "@" + DOMAIN;
  var handle = await store.open(cfg);
  try {
    var hosted = handle.domains.list().some(function (d) { return d.domain === DOMAIN; });
    if (!hosted) await handle.domains.add({ domain: DOMAIN });
    var account = await handle.accounts.create({ address: address, password: ACCOUNT_PASSWORD });
    handle.mailbox.appendMessage("INBOX", _message(address, "a message for " + localPart), {
      actor: { id: account.id },
    });
  } finally {
    handle.close();
  }
  return address;
}

function _parsed(text) {
  var opened = String(text).indexOf("{");
  var closed = String(text).lastIndexOf("}");
  if (opened === -1 || closed <= opened) return null;
  try { return JSON.parse(String(text).slice(opened, closed + 1)); } catch (_e) { return null; }
}

/**
 * takeBundle(cli, vol, extra) runs `backup run --json` against the volume
 * and returns the parsed report. A run that fails throws with its
 * transcript, because every caller needs the bundle to exist.
 */
function takeBundle(cli, vol, extra) {
  var run = cli(["backup", "run", "--storage", vol.storageDir,
    "--passphrase-file", vol.passFile, "--json"].concat(extra || []));
  var report = _parsed(run.stdout);
  if (run.status !== 0 || report === null || typeof report.bundleId !== "string") {
    throw new Error("bundle fixture: `backup run` exited " + run.status + ": " +
      run.both.replace(/\s+/g, " ").slice(0, 600));
  }
  return report;
}

/**
 * parsed(text) reads the one JSON object a `--json` run printed, or null.
 */
function parsed(text) {
  return _parsed(text);
}

function bundleDir(vol, bundleId) {
  return nodePath.join(vol.storageDir, bundleId);
}

function readManifest(dir) {
  return JSON.parse(nodeFs.readFileSync(nodePath.join(dir, "manifest.json"), "utf8"));
}

function writeManifest(dir, manifest) {
  nodeFs.writeFileSync(nodePath.join(dir, "manifest.json"),
    JSON.stringify(manifest, null, 2) + "\n", { mode: 0o600 });
}

/**
 * bundleIdAt(when) is a bundle id in the framework's format for a moment.
 */
function bundleIdAt(when) {
  return b.atomicFile.pathTimestamp(when) + "-" + nodeCrypto.randomBytes(4).toString("hex");
}

/**
 * cloneBundle(vol, fromId, when) copies a bundle directory to a new id
 * and returns the id. The manifest is copied unchanged, so it still names
 * the bundle it was written as.
 */
function cloneBundle(vol, fromId, when) {
  var id = bundleIdAt(when);
  b.atomicFile.copyDirRecursive(bundleDir(vol, fromId), bundleDir(vol, id));
  return id;
}

/**
 * resign(dir, edit) hands the manifest to `edit`, then signs what `edit`
 * left with a fresh Ed25519 key and writes it back without validating it.
 */
function resign(dir, edit) {
  var manifest = readManifest(dir);
  delete manifest.signature;
  edit(manifest);
  // An algorithm the framework accepts for an audit signature, so the
  // re-signed manifest is refused for whose key it is rather than for the
  // kind of key it is.
  var pair = nodeCrypto.generateKeyPairSync("ml-dsa-65", {
    publicKeyEncoding:  { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  var payload = Buffer.from(b.backupManifest.signingPayload(manifest), "utf8");
  manifest.signature = {
    algorithm:   "ml-dsa-65",
    publicKey:   pair.publicKey,
    fingerprint: b.auditSign.fingerprintOf(pair.publicKey),
    value:       nodeCrypto.sign(null, payload, pair.privateKey).toString("base64"),
    signedAt:    new Date().toISOString(),
  };
  writeManifest(dir, manifest);
  return manifest;
}

/**
 * sealEntry(cfg, dir, relativePath, bytes, edit) seals `bytes` under the
 * bundle passphrase with `relativePath` bound as associated data, puts the
 * blob in the bundle, replaces any entry already naming that path, lets
 * `edit` change the manifest further, and signs the result with the
 * volume's audit signing key. The store is opened in this process to reach
 * that key, which writes to the live volume, so a caller takes any
 * before-and-after reading of the volume afterwards.
 */
async function sealEntry(cfg, dir, relativePath, bytes, edit) {
  var manifest = readManifest(dir);
  delete manifest.signature;
  var sealed = await b.backupCrypto.encryptWithFreshSalt(bytes, BUNDLE_PASSPHRASE, relativePath);
  var encryptedPath = "files/" + relativePath + ".enc";
  var blobPath = nodePath.join(dir, encryptedPath);
  nodeFs.mkdirSync(nodePath.dirname(blobPath), { recursive: true });
  nodeFs.writeFileSync(blobPath, sealed.encrypted, { mode: 0o600 });
  manifest.files = manifest.files.filter(function (entry) {
    return entry.relativePath !== relativePath;
  });
  manifest.files.push({
    relativePath:  relativePath,
    encryptedPath: encryptedPath,
    size:          bytes.length,
    encryptedSize: sealed.encrypted.length,
    checksum:      b.backupCrypto.checksum(bytes),
    salt:          sealed.salt,
    kind:          "raw",
  });
  if (typeof edit === "function") edit(manifest);
  var handle = await store.open(cfg);
  try {
    b.backupManifest.sign(manifest);
  } finally {
    handle.close();
  }
  writeManifest(dir, manifest);
  return manifest;
}

/**
 * resignAsVolume(cfg, dir, edit) hands the manifest to `edit` and signs
 * what `edit` left with the volume's own audit signing key. No file in the
 * bundle is added or replaced, so this changes what the manifest RECORDS
 * and nothing else.
 *
 * Reaching that key needs the vault passphrase, so this stands in for a
 * bundle this server wrote whose manifest records another moment, another
 * directory or another server, rather than for an attacker, who has
 * neither passphrase and can only sign with a key of their own. The store
 * is opened in this process to reach the key, which writes to the live
 * volume, so a caller takes any before-and-after reading of the volume
 * afterwards.
 */
async function resignAsVolume(cfg, dir, edit) {
  var manifest = readManifest(dir);
  delete manifest.signature;
  if (typeof edit === "function") edit(manifest);
  var handle = await store.open(cfg);
  try {
    b.backupManifest.sign(manifest);
  } finally {
    handle.close();
  }
  writeManifest(dir, manifest);
  return manifest;
}

/**
 * volumeFiles(dataDir) maps every regular file under the data directory,
 * by path relative to it with forward slashes, to a SHA-512 digest of its
 * bytes. `.restore` and the volume lock are left out, since both change on
 * every restore by design. Two readings compare with `differences`.
 */
function volumeFiles(dataDir) {
  var out = {};
  var stack = [""];
  while (stack.length > 0) {
    var rel = stack.pop();
    var abs = rel === "" ? dataDir : nodePath.join(dataDir, rel);
    var entries;
    try { entries = nodeFs.readdirSync(abs, { withFileTypes: true }); }
    catch (_e) { continue; }
    for (var i = 0; i < entries.length; i += 1) {
      var name = entries[i].name;
      if (rel === "" && (name === ".restore" || name === "blamepost.lock")) continue;
      var childRel = rel === "" ? name : rel + "/" + name;
      if (entries[i].isDirectory()) stack.push(childRel);
      else if (entries[i].isFile()) {
        out[childRel] = nodeCrypto.createHash("sha512")
          .update(nodeFs.readFileSync(nodePath.join(dataDir, childRel))).digest("hex");
      }
    }
  }
  return out;
}

/**
 * differences(before, after) lists every path added, removed or changed
 * between two `volumeFiles` readings, as short strings.
 */
function differences(before, after) {
  var out = [];
  Object.keys(before).forEach(function (p) {
    if (!Object.prototype.hasOwnProperty.call(after, p)) out.push("removed " + p);
    else if (after[p] !== before[p]) out.push("changed " + p);
  });
  Object.keys(after).forEach(function (p) {
    if (!Object.prototype.hasOwnProperty.call(before, p)) out.push("added " + p);
  });
  return out;
}

/**
 * accountsListed(cli) runs `account list --json` and returns the addresses
 * it printed, or null with the transcript when the run did not succeed.
 */
function accountsListed(cli) {
  var run = cli(["account", "list", "--json"]);
  if (run.status !== 0) return { addresses: null, run: run };
  var text = run.stdout;
  var start = text.indexOf("[");
  var end = text.lastIndexOf("]");
  var rows;
  try { rows = JSON.parse(text.slice(start, end + 1)); } catch (_e) { rows = []; }
  return {
    addresses: rows.map(function (row) { return row.address; }).sort(),
    run:       run,
  };
}

module.exports = {
  HOSTNAME:          HOSTNAME,
  DOMAIN:            DOMAIN,
  VAULT_PASSPHRASE:  VAULT_PASSPHRASE,
  BUNDLE_PASSPHRASE: BUNDLE_PASSPHRASE,
  volume:            volume,
  configFor:         configFor,
  cliFor:            cliFor,
  addAccount:        addAccount,
  takeBundle:        takeBundle,
  parsed:            parsed,
  bundleDir:         bundleDir,
  readManifest:      readManifest,
  writeManifest:     writeManifest,
  bundleIdAt:        bundleIdAt,
  cloneBundle:       cloneBundle,
  resign:            resign,
  resignAsVolume:    resignAsVolume,
  sealEntry:         sealEntry,
  volumeFiles:       volumeFiles,
  differences:       differences,
  accountsListed:    accountsListed,
};
