// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The DKIM selector lifecycle and the listener composition, driven
 * against a real temporary data directory: a real vault sealing the
 * private keys, a real encrypted database holding the selector rows,
 * and the real identity store answering the routing questions.
 *
 * Nothing about the key handling is faked. A suite that seals with a
 * pretend vault has not tested the thing that ships, and the sealing is
 * the whole reason a stolen data volume yields nothing.
 *
 * The listeners are composed but never bound. Binding real ports is
 * layer 2 work; what belongs here is the configuration validation and
 * the boot gate, both of which decide their answer before any socket
 * exists.
 *
 * Run standalone: node test/layer-1-state/mail-dkim.test.js
 */

var nodeFs    = require("node:fs");
var nodePath  = require("node:path");

var helpers   = require("../helpers");
var certs     = require("../helpers/certs");
var dnsZone   = require("../helpers/dns-zone");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;

// RFC 5322 section 2.1 header/body separator, as octets. The signature
// headers `sign` prepends sit above it, so one split reads the body of
// the input and the body of the result, and comparing the two is a byte
// comparison rather than a text one.
var SEPARATOR = Buffer.from("\r\n\r\n", "latin1");

function _bodyOctets(buf) {
  var at = buf.indexOf(SEPARATOR);
  return at === -1 ? Buffer.alloc(0) : buf.subarray(at + SEPARATOR.length);
}

// An ordinary legacy message: an 8-bit body in a single-byte charset.
// Six of these octets are not valid UTF-8 standing alone, and a decode
// turns each of them into three, so a decode is visible as a length
// change as well as a content change.
var LEGACY_BODY = Buffer.from([
  0x43, 0x61, 0x66, 0xe9, 0x0d, 0x0a,           // "Cafe" with an acute e, ISO-8859-1
  0x82, 0xa0, 0x82, 0xa2, 0x0d, 0x0a,           // two Shift_JIS kana
]);

function legacyMessageFor(domain) {
  return Buffer.concat([
    Buffer.from([
      "From: alice@" + domain,
      "To: bob@example.net",
      "Subject: legacy charset",
      "Date: Mon, 1 Jan 2026 00:00:00 +0000",
      "Message-ID: <legacy@" + domain + ">",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=iso-8859-1",
      "Content-Transfer-Encoding: 8bit",
      "", "",
    ].join("\r\n"), "latin1"),
    LEGACY_BODY,
  ]);
}

function refuses(label, fn) {
  var thrown = false;
  try { fn(); } catch (_e) { thrown = true; }
  check(label, thrown);
}

async function refusesAsync(label, fn) {
  var thrown = false;
  try { await fn(); } catch (_e) { thrown = true; }
  check(label, thrown);
}

// The refusal a probe produced, or null when it produced none. The code
// and the wording are both read afterwards, so the error itself has to
// come back rather than only the fact that one was raised.
function refusalOf(fn) {
  try { fn(); return null; }
  catch (e) { return e; }
}

// A signer built through a handle that has never signed for this domain.
// The signer for a domain is built once and kept, so a handle that has
// already signed answers from what it built rather than from the file a
// probe has just damaged, and every probe below would pass over an
// intact key.
function freshSignerFor(dataDir, identity, domain) {
  return blamepost.mail.dkim.create({ dataDir: dataDir, store: identity })
    .signerFor(domain);
}

// How much of a sealed key file a probe leaves in place. Far enough in
// to keep the marker the vault reads to recognize one of its own, and
// far short of the whole envelope, which is what a copy that stopped
// part way through leaves behind.
var TRUNCATED_KEY_BYTES = 64;

async function run() {
  var dataDir = helpers.tempDir("dkim");

  // The decrypted working copy needs somewhere to live, and this run has
  // to name it. Opening an encrypted volume without one used to fall
  // back to /dev/shm, which is a tmpfs on Linux and an ordinary
  // directory on disk under a POSIX shell on Windows, so every run of
  // this file left a decrypted database behind. The store refuses that
  // now, so the directory is named here the way every other stateful
  // file in this suite names it.
  var workDir  = nodePath.join(dataDir, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  var cfg = config.load({ env: {
    BLAMEPOST_HOSTNAME:         "mx.example.com",
    BLAMEPOST_VAULT_PASSPHRASE: "a passphrase long enough for the vault",
    BLAMEPOST_DATA_DIR:         dataDir,
  } });

  var handle = await store.open(cfg);
  try {
    await handle.domains.add({ domain: "example.com" });
    var dkim = blamepost.mail.dkim.create({ dataDir: dataDir, store: handle });

    // ---- first keys --------------------------------------------------------

    var minted = await dkim.generate({ domain: "example.com", selector: "bp202601" });
    check("generate mints one Ed25519 and one RSA selector", minted.publish.length === 2);
    check("the selector rows live in the store rather than a second file",
      handle.domains.listSelectors({ domain: "example.com" }).length === 2);
    check("both selectors sign from the moment they exist",
      minted.publish.every(function (r) { return r.state === "active"; }));

    var ed = minted.publish.filter(function (r) { return r.algorithm === "ed25519"; })[0];
    check("the Ed25519 record declares its key family",
      ed.dnsTxtValue.indexOf("v=DKIM1; k=ed25519; p=") === 0);
    check("the zone line quotes the record", ed.dnsRecord.indexOf(' IN TXT ("v=DKIM1;') !== -1);

    var rsa = minted.publish.filter(function (r) { return r.algorithm === "rsa-sha256"; })[0];
    // RFC 1035 caps one TXT character string at 255 octets, so a 2048
    // bit RSA key has to be published as several quoted strings.
    check("a long RSA record is split into several character strings",
      (rsa.dnsRecord.match(/"/g) || []).length > 2);

    await refusesAsync("generate refuses a domain that already has active keys", function () {
      return dkim.generate({ domain: "example.com" });
    });

    // ---- signing -----------------------------------------------------------

    var message =
      "From: alice@example.com\r\nTo: bob@example.net\r\nSubject: t\r\n" +
      "Date: Mon, 1 Jan 2026 00:00:00 +0000\r\nMessage-ID: <a@example.com>\r\n\r\nbody\r\n";
    var signed = await dkim.sign("example.com", message);
    check("the dual signer emits one signature per algorithm",
      (signed.match(/DKIM-Signature:/g) || []).length === 2);
    check("one signature is Ed25519", signed.indexOf("a=ed25519-sha256") !== -1);
    check("the other is RSA", signed.indexOf("a=rsa-sha256") !== -1);
    check("the signature names the selector", signed.indexOf("s=bp202601") !== -1);
    check("the signature names the domain", signed.indexOf("d=example.com") !== -1);

    // A domain with no key signs nothing, and saying so is better than
    // sending unsigned mail from a domain whose DMARC record promises
    // the mail will be signed.
    await refusesAsync("signing refuses a domain with no active selector", function () {
      return dkim.sign("example.org", message);
    });

    // A domain with no active selector refuses under a stable code, so
    // the caller that relays the message unsigned can file the gap under
    // something an operator can filter on rather than under a sentence
    // that changes whenever the wording improves. It is a setup state
    // that ends when setup ends, which is the one thing the record has
    // to distinguish it as.
    var noKeyCode = null;
    try { await dkim.sign("example.org", message); }
    catch (e) { noKeyCode = e && e.code; }
    count("a domain with no active selector refuses under a stable code",
      noKeyCode === "dkim/no-active-selector", String(noKeyCode));

    // ---- the octets signed are the octets sent ------------------------------
    //
    // A submitted message is an octet stream, not text. Legacy
    // single-byte charsets and 8BITMIME bodies routinely carry octets
    // that are not valid UTF-8, and a UTF-8 decode replaces every one of
    // the 128 values from 0x80 up with U+FFFD. A signer that decodes,
    // signs what it decoded and re-encodes hands back a DIFFERENT
    // message from the one it was given: the body is destroyed, the
    // signature authenticates the destruction rather than the message,
    // and the relayed copy and the locally delivered copy both carry it,
    // so nothing anywhere still holds what the account sent.
    //
    // Both halves are asserted, because either one alone can hold while
    // the message is still wrong. A signer that returns the octets it
    // was given but hashes a decoded copy of them emits a signature that
    // fails at every receiver; a signer that hashes and returns the same
    // decoded copy emits one that passes over a message the sender never
    // wrote. So: the octets come back, AND the signature verifies over
    // the octets that come back.

    var legacyBody = LEGACY_BODY;
    var legacyMessage = legacyMessageFor("example.com");
    var legacySigned = await dkim.sign("example.com", legacyMessage);

    count("an 8-bit message signs rather than being refused",
      Buffer.isBuffer(legacySigned) &&
      (legacySigned.toString("latin1").match(/DKIM-Signature:/g) || []).length === 2,
      Buffer.isBuffer(legacySigned)
        ? String((legacySigned.toString("latin1").match(/DKIM-Signature:/g) || []).length)
        : "returned a " + typeof legacySigned);
    count("signing hands back a message whose body octets are the ones that went in",
      _bodyOctets(legacySigned).equals(legacyBody),
      "body came back as " + _bodyOctets(legacySigned).toString("hex") +
        " instead of " + legacyBody.toString("hex"));
    count("and the whole message below the prepended headers is byte for byte the input",
      legacySigned.subarray(legacySigned.length - legacyMessage.length).equals(legacyMessage),
      legacySigned.length + " octets returned for a " + legacyMessage.length + " octet message");

    // The octets go to the verifier as octets. Handing it a latin1
    // rendering of them instead would have it read that rendering as
    // text and re-encode it, so the verifier would be checking a
    // different message from the one that was signed, and the failure
    // would look like a signer defect.
    var legacyVerdicts = await dnsZone.verifyAgainst(
      legacySigned, dkim.dnsRecords("example.com"));
    count("the signature verifies against the octets it returns",
      dnsZone.allPass(legacyVerdicts), dnsZone.summarize(legacyVerdicts));

    // An 8-bit octet in a header field is a different path through the
    // signer than one in a body: the header block is canonicalized field
    // by field and the body is hashed whole. A run that only carried the
    // octet in the body would pass while every unencoded Subject line a
    // legacy client sends was still being rewritten.
    var headerOctetMessage = Buffer.concat([
      Buffer.from("From: alice@example.com\r\nTo: bob@example.net\r\nSubject: caf", "latin1"),
      Buffer.from([0xe9]),
      Buffer.from("\r\nDate: Mon, 1 Jan 2026 00:00:00 +0000\r\n" +
        "Message-ID: <legacyhdr@example.com>\r\n\r\nplain ascii body\r\n", "latin1"),
    ]);
    var headerOctetSigned = await dkim.sign("example.com", headerOctetMessage);
    count("an 8-bit octet in a header field survives signing byte for byte",
      headerOctetSigned
        .subarray(headerOctetSigned.length - headerOctetMessage.length)
        .equals(headerOctetMessage),
      headerOctetSigned.length + " vs " + headerOctetMessage.length);
    var headerOctetVerdicts = await dnsZone.verifyAgainst(
      headerOctetSigned, dkim.dnsRecords("example.com"));
    count("and that signature verifies too",
      dnsZone.allPass(headerOctetVerdicts), dnsZone.summarize(headerOctetVerdicts));

    // A message that reached this server from an mbox or through
    // operator tooling that stripped the CRs carries bare LF. The signer
    // canonicalizes line endings on the way to the hash, so the thing to
    // prove is that it does not also rewrite the copy it returns: a
    // message signed over one set of octets and relayed as another fails
    // DKIM at every receiver, and nothing on the sending side says so.
    var bareLfMessage = Buffer.from([
      "From: alice@example.com",
      "To: bob@example.net",
      "Subject: bare lf",
      "Date: Mon, 1 Jan 2026 00:00:00 +0000",
      "Message-ID: <barelf@example.com>",
      "",
      "first line",
      "second line",
      "",
    ].join("\n"), "latin1");
    var bareLfSigned = await dkim.sign("example.com", bareLfMessage);
    var bareLfTail = bareLfSigned.subarray(bareLfSigned.length - bareLfMessage.length);
    count("a bare-LF message is relayed with its own line endings rather than rewritten",
      bareLfTail.equals(bareLfMessage),
      bareLfTail.toString("latin1").indexOf("\r\n") === -1
        ? "line endings kept but the octets differ"
        : "the returned copy was folded to CRLF");
    var bareLfVerdicts = await dnsZone.verifyAgainst(
      bareLfSigned, dkim.dnsRecords("example.com"));
    count("and its signature verifies over the octets that are relayed",
      dnsZone.allPass(bareLfVerdicts), dnsZone.summarize(bareLfVerdicts));

    // Refusing every 8-bit message would satisfy the check above by
    // signing nothing at all. Valid UTF-8 is the ordinary modern case:
    // it has to keep signing, keep its octets, and keep verifying.
    var utf8Message = Buffer.from([
      "From: alice@example.com",
      "To: bob@example.net",
      "Subject: éà 中文",
      "Date: Mon, 1 Jan 2026 00:00:00 +0000",
      "Message-ID: <utf8@example.com>",
      "MIME-Version: 1.0",
      "Content-Type: text/plain; charset=utf-8",
      "Content-Transfer-Encoding: 8bit",
      "",
      "Café naïve 中文",
      "",
    ].join("\r\n"), "utf8");

    var utf8Signed = await dkim.sign("example.com", utf8Message);
    check("a valid UTF-8 message still signs",
      (utf8Signed.toString("utf8").match(/DKIM-Signature:/g) || []).length === 2);
    count("and multi-byte characters come back byte for byte",
      _bodyOctets(utf8Signed).equals(_bodyOctets(utf8Message)),
      _bodyOctets(utf8Signed).toString("hex"));

    var utf8Verdicts = await dnsZone.verifyAgainst(
      utf8Signed, dkim.dnsRecords("example.com"));
    count("and the signature verifies against the octets it returns",
      dnsZone.allPass(utf8Verdicts), dnsZone.summarize(utf8Verdicts));

    // ---- key material at rest ----------------------------------------------

    var keyPath = helpers.path.join(dataDir, "keys", "example.com.bp202601.ed25519.sealed");
    check("the private key is a file under the keys folder", helpers.fs.existsSync(keyPath));
    var onDisk = helpers.fs.readFileSync(keyPath, "utf8");
    // Sealed, and sealed as this selector's key rather than to the volume
    // at large. The plain seal opens wherever it is found, so a file
    // carrying it opens as a signing key whatever it was sealed as.
    check("the private key is sealed at rest", onDisk.indexOf("vault.aad:") === 0);
    check("no plaintext private key is written", onDisk.indexOf("BEGIN PRIVATE KEY") === -1);

    // ---- key material that will not open -----------------------------------
    //
    // Signing runs on every message an account submits, so what the
    // signer does with a key file it cannot open is an operator-facing
    // answer rather than an internal one. The two callers that relay a
    // message unsigned read the refusal's code to decide what they
    // record and log its message for the operator, so a fault carrying
    // neither is filed as an unknown and read as a transient one.
    //
    // Four shapes, because they have four different remedies. A file
    // that is gone is a volume missing part of itself. A file sealed to
    // this selector that does not open is not this selector's key, and
    // no command re-derives one. A file carrying the plain volume seal
    // that does not open was written under a different vault key or has
    // been damaged where it lies. A file that carries no seal at all is
    // signing material lying in the open, which is the one thing sealing
    // a key at rest exists to prevent.
    //
    // The damage is done to a second domain, so the key the rest of this
    // file signs with is never touched, and the file is put back whole
    // at the end so the probes are provably about the file rather than
    // about the domain.

    await handle.domains.add({ domain: "example.net" });
    await dkim.generate({ domain: "example.net", selector: "bp202609" });

    var netKeyPath = helpers.path.join(
      dataDir, "keys", "example.net.bp202609.ed25519.sealed");
    var wholeKey = helpers.fs.readFileSync(netKeyPath, "utf8");
    check("the second domain signs before anything is done to its key file",
      freshSignerFor(dataDir, handle, "example.net").pairs === 1);

    // What a restore that copied a prefix leaves, and what a write cut
    // off part way through leaves: the right name holding the front of
    // the right bytes. A seal authenticates what it carries end to end,
    // so a file missing its tail does not open at all.
    helpers.fs.truncateSync(netKeyPath, TRUNCATED_KEY_BYTES);
    var cutShort = refusalOf(function () {
      return freshSignerFor(dataDir, handle, "example.net");
    });
    count("a sealed key cut short refuses in this layer's words rather than the vault's",
      cutShort !== null && cutShort.code === "dkim/key-seal-foreign",
      cutShort ? String(cutShort.code) : "signed with a key that did not open");
    count("and the refusal names the domain and the selector, which is what an operator " +
      "acts on",
      cutShort !== null && cutShort.message.indexOf("example.net") !== -1 &&
      cutShort.message.indexOf("bp202609") !== -1,
      cutShort ? cutShort.message : "(no refusal)");
    // A `dkim/` code is what tells the admin interface it may show a
    // message, so anything this one carries is rendered into a browser.
    count("and carries no part of the volume's layout, because a coded refusal is shown " +
      "to whoever asked",
      cutShort !== null && cutShort.message.indexOf(dataDir) === -1 &&
      cutShort.message.indexOf(netKeyPath) === -1 &&
      cutShort.message.indexOf(".sealed") === -1,
      cutShort ? cutShort.message : "(no refusal)");
    // The relay path files a domain with no key under an action of its
    // own, because that is a setup state that ends when setup ends. A
    // key that will not open is not that, and filing it as one sends an
    // operator to run the command that mints a pair the domain already
    // has.
    count("and is not the code a domain still waiting to be set up refuses under",
      cutShort !== null && cutShort.code !== "dkim/no-active-selector",
      cutShort ? String(cutShort.code) : "(no refusal)");

    // The same damage to a key still carrying the plain volume seal,
    // which is what a volume holds until `blamepost dkim reseal` has run
    // on it. Such a file carries nothing saying which value it is, so a
    // seal that will not open says only that: it was written under a
    // different vault key, or its bytes have been damaged. The remedy is
    // a restore rather than a replacement, so it is a refusal of its own.
    var netKeyPem = helpers.b.vault.aad.unseal(wholeKey, {
      purpose:   "blamepost.mail.dkim.signing-key",
      domain:    "example.net",
      selector:  "bp202609",
      algorithm: "ed25519",
    });
    helpers.fs.writeFileSync(netKeyPath, helpers.b.vault.seal(netKeyPem), { mode: 0o600 });
    helpers.fs.truncateSync(netKeyPath, TRUNCATED_KEY_BYTES);
    var olderCutShort = refusalOf(function () {
      return freshSignerFor(dataDir, handle, "example.net");
    });
    count("a key sealed the way this volume sealed them before, cut short, refuses under the " +
      "code whose remedy is a restore rather than a new pair",
      olderCutShort !== null && olderCutShort.code === "dkim/key-seal-unopened",
      olderCutShort ? String(olderCutShort.code) : "signed with a key that did not open");
    count("and names the domain and the selector too",
      olderCutShort !== null && olderCutShort.message.indexOf("example.net") !== -1 &&
      olderCutShort.message.indexOf("bp202609") !== -1,
      olderCutShort ? olderCutShort.message : "(no refusal)");

    // The vault passes a value carrying no seal straight back, so a key
    // file that was never sealed reads as key material and signs. That
    // is a private key sitting in the open on the volume, which is the
    // condition sealing it at rest exists to rule out.
    helpers.fs.writeFileSync(netKeyPath, "this file carries no seal\n", { mode: 0o600 });
    var unsealed = refusalOf(function () {
      return freshSignerFor(dataDir, handle, "example.net");
    });
    count("a key file carrying no seal is refused rather than signed with",
      unsealed !== null && unsealed.code === "dkim/key-not-sealed",
      unsealed ? String(unsealed.code) : "signed with an unsealed key");
    count("and that refusal names the domain and the selector too",
      unsealed !== null && unsealed.message.indexOf("example.net") !== -1 &&
      unsealed.message.indexOf("bp202609") !== -1,
      unsealed ? unsealed.message : "(no refusal)");
    count("and carries no part of the volume's layout either",
      unsealed !== null && unsealed.message.indexOf(dataDir) === -1 &&
      unsealed.message.indexOf(netKeyPath) === -1 &&
      unsealed.message.indexOf(".sealed") === -1,
      unsealed ? unsealed.message : "(no refusal)");

    helpers.fs.rmSync(netKeyPath, { force: true });
    var gone = refusalOf(function () {
      return freshSignerFor(dataDir, handle, "example.net");
    });
    count("a key file that is not on the volume is refused in this layer's words as well",
      gone !== null && gone.code === "dkim/key-unreadable",
      gone ? String(gone.code) : "signed with a key that is not there");
    count("and that refusal names the domain and the selector as well",
      gone !== null && gone.message.indexOf("example.net") !== -1 &&
      gone.message.indexOf("bp202609") !== -1,
      gone ? gone.message : "(no refusal)");
    count("and carries no path, which is the whole of what the file layer's own message " +
      "would have handed over",
      gone !== null && gone.message.indexOf(dataDir) === -1 &&
      gone.message.indexOf(netKeyPath) === -1 &&
      gone.message.indexOf(".sealed") === -1,
      gone ? gone.message : "(no refusal)");

    helpers.fs.writeFileSync(netKeyPath, wholeKey, { mode: 0o600 });
    count("and the whole file signs again, so all three refusals were about the file " +
      "rather than about the domain",
      freshSignerFor(dataDir, handle, "example.net").pairs === 1,
      "restored " + wholeKey.length + " character(s)");

    // ---- which refusals were written for a person ---------------------------
    //
    // A surface showing an operator why something was not done has to
    // separate a refusal this module composed from a fault raised
    // underneath it, because the two are written for different readers.
    // The code prefix cannot make that separation: the framework codes
    // its own DKIM faults under `dkim/` as well, and writes them for
    // whoever composed the framework. The published set is what makes
    // the separation instead, so what it has to hold is everything this
    // module throws and nothing anybody else does.

    var published = blamepost.mail.dkim.CODES;
    var vocabulary = Object.keys(published).map(function (name) { return published[name]; });
    count("every code this module raised in this run is in the set it publishes, so a " +
      "surface reading the set recognizes the refusals written for a reader",
      [noKeyCode, cutShort && cutShort.code, unsealed && unsealed.code, gone && gone.code]
        .every(function (code) { return vocabulary.indexOf(code) !== -1; }),
      JSON.stringify([noKeyCode, cutShort && cutShort.code, unsealed && unsealed.code,
        gone && gone.code]));
    count("the set holds no duplicate, so two names for one code cannot answer differently",
      vocabulary.filter(function (code, at) { return vocabulary.indexOf(code) === at; })
        .length === vocabulary.length,
      JSON.stringify(vocabulary));
    // The point of the set. Each of these is a real code the framework
    // raises while generating a key or building a signer, each starts
    // `dkim/`, and none of them was written for an operator: they name
    // the framework's own option paths and primitives. A prefix admits
    // all four; the set admits none.
    count("and none of the framework's own dkim-prefixed codes is in it, which is the whole " +
      "reason the set exists rather than a prefix",
      ["dkim/missing-private-key", "dkim/bad-algorithm", "dkim/l-tag-forbidden",
        "dkim/dual-signer-missing", "dkim/bad-rsa-bits", "dkim/bad-selector",
        "dkim/bad-domain", "dkim/bad-private-key"]
        .every(function (code) { return vocabulary.indexOf(code) === -1; }),
      JSON.stringify(vocabulary));

    // The one framework refusal a caller could actually provoke through
    // this module. An RSA modulus below the floor this server signs at
    // used to travel to the generator and come back worded for whoever
    // composed it, naming its own option path. It is measured at the
    // entry point now, so it never gets there.
    var tooShort = refusalOf(function () {
      return blamepost.mail.dkim.create({ dataDir: dataDir, store: handle, rsaBits: 1024 });
    });
    count("an RSA modulus below this server's floor is refused when the handle is built",
      tooShort !== null, "the handle was built");
    count("and the refusal names the floor, so an operator sees the number to use rather " +
      "than only that theirs was wrong",
      tooShort !== null && tooShort.message.indexOf("2048") !== -1,
      tooShort ? tooShort.message : "(no refusal)");
    count("and it does not carry the generator's own vocabulary, because the value never " +
      "reached it",
      tooShort !== null && tooShort.message.indexOf("b.mail.dkim.bootstrap") === -1,
      tooShort ? tooShort.message : "(no refusal)");
    count("a modulus that is not a whole number of bits is refused too",
      refusalOf(function () {
        return blamepost.mail.dkim.create({ dataDir: dataDir, store: handle, rsaBits: 2048.5 });
      }) !== null, "the handle was built");
    count("and the floor itself is accepted, so the check refuses what is short rather than " +
      "everything that is stated",
      refusalOf(function () {
        return blamepost.mail.dkim.create({ dataDir: dataDir, store: handle, rsaBits: 2048 });
      }) === null, "the floor was refused");

    // The other two settings the handle takes decide what a signature
    // covers and how it is canonicalized. The framework refuses either
    // one when it builds the signer, which happens the first time a
    // domain signs rather than when the server starts, so a value
    // carried unread to that point lets a mistyped setting boot cleanly
    // and then sends every message from every hosted domain unsigned,
    // with the refusal worded for whoever composed the framework and
    // reaching only an audit row.
    var badCanon = refusalOf(function () {
      return blamepost.mail.dkim.create({
        dataDir: dataDir, store: handle, canonicalization: "relaxed/nonsense",
      });
    });
    count("a canonicalization the signer cannot use is refused when the handle is built, " +
      "rather than on the first message from the first domain",
      badCanon !== null, "the handle was built");
    count("and the refusal names the forms that are accepted",
      badCanon !== null && badCanon.message.indexOf("relaxed/relaxed") !== -1,
      badCanon ? badCanon.message.slice(0, 200) : "(no refusal)");
    count("the shipped default is still accepted, so the check refuses what is wrong rather " +
      "than everything that is stated",
      refusalOf(function () {
        return blamepost.mail.dkim.create({
          dataDir: dataDir, store: handle, canonicalization: "relaxed/relaxed",
        });
      }) === null, "the default was refused");

    var badHeader = refusalOf(function () {
      return blamepost.mail.dkim.create({
        dataDir: dataDir, store: handle, headersToSign: ["from", ""],
      });
    });
    count("a header set carrying something that is not a header name is refused at the same " +
      "point, because it decides what a signature binds",
      badHeader !== null, "the handle was built");
    count("and a header set of real names is accepted",
      refusalOf(function () {
        return blamepost.mail.dkim.create({
          dataDir: dataDir, store: handle, headersToSign: ["from", "subject"],
        });
      }) === null, "a usable header set was refused");

    // ---- rotation ----------------------------------------------------------

    var rotated = await dkim.rotate({ domain: "example.com", selector: "bp202602" });
    check("rotate mints a replacement pair", rotated.minted.length === 2);

    var duringChangeover = await dkim.sign("example.com", message);
    check("both pairs sign during the changeover",
      (duringChangeover.match(/DKIM-Signature:/g) || []).length === 4);
    check("the outgoing signature keeps verifying while the new records propagate",
      duringChangeover.indexOf("s=bp202601") !== -1);
    check("the incoming signature is present from the start",
      duringChangeover.indexOf("s=bp202602") !== -1);

    await refusesAsync("rotate refuses a selector name already in use", function () {
      return dkim.rotate({ domain: "example.com", selector: "bp202602" });
    });
    await refusesAsync("retire refuses without a selector to retire", function () {
      return dkim.retire({ domain: "example.com" });
    });
    await refusesAsync("retire refuses a selector that does not exist", function () {
      return dkim.retire({ domain: "example.com", selector: "bp190001" });
    });

    var out = await dkim.retire({ domain: "example.com", selector: "bp202601" });
    check("retire moves the outgoing pair out of signing", out.retired.length === 2);
    check("the retiring records keep a publish window", out.retired[0].retiresAt > Date.now());
    check("the retired private key is erased", !helpers.fs.existsSync(keyPath));

    var afterRetire = await dkim.sign("example.com", message);
    check("only the live pair signs once the old one is retired",
      (afterRetire.match(/DKIM-Signature:/g) || []).length === 2);
    check("the retired selector no longer signs", afterRetire.indexOf("s=bp202601") === -1);
    check("the retiring records are still published during their window",
      dkim.dnsRecords("example.com").length === 4);

    var inventory = dkim.list("example.com");
    check("the inventory carries every selector and its state", inventory.length === 4);
    check("and never carries key material",
      inventory.every(function (s) { return s.privateKey === undefined; }));
    // Two domains are hosted by the time this runs, so the claim is
    // settled against both of their inventories rather than against one
    // of them. Held against a single domain it would pass on a listing
    // that answered for that domain alone, which is the failure the
    // wording describes.
    count("listing without a domain covers every domain",
      dkim.list().length === inventory.length + dkim.list("example.net").length,
      dkim.list().map(function (s) { return s.domain + ":" + s.selector; }).join(", "));

    var signer = dkim.signerFor("example.com");
    check("the signer reports how many pairs are signing", signer.pairs === 1);

    var swept = await dkim.sweep({});
    check("sweep leaves a selector inside its window alone", swept.withdrawn.length === 0);

    // Withdrawing before the overlap elapses is the right answer for
    // exactly one situation, a key believed to be exposed, so it takes
    // an explicit ask.
    var withdrawn = await dkim.sweep({ immediate: true });
    check("an immediate sweep withdraws a selector still inside its window",
      withdrawn.withdrawn.length === 2);
    check("only the live pair is left to publish",
      dkim.dnsRecords("example.com").length === 2);

    // ---- listener composition ----------------------------------------------

    var sentEnvelopes = [];
    var recordingDelivery = helpers.standInDelivery({
      send: function (e) {
        sentEnvelopes.push(e);
        return Promise.resolve({ delivered: [], deferred: [], failed: [] });
      },
    });
    var recordingMailStore = { appendMessage: function () { return { objectid: "obj_test" }; } };

    var listeners = blamepost.mail.listeners.create({
      config: {
        hostname:        "mx.example.com",
        dnsAcknowledged: false,
        pop3Enabled:     false,
        listeners:       { mx: { port: 2525 }, imap: { port: 2143 } },
      },
      store:      handle,
      mailStore:  recordingMailStore,
      certificate: certs.handle({}),
      delivery:   recordingDelivery,
    });
    var described = listeners.describe();
    check("a configured port overrides the default", described.listeners.mx.port === 2525);
    check("POP3 stays off unless the operator asks", described.listeners.pop3.enabled === false);
    check("implicit TLS submission takes port 465", described.listeners.submissions.port === 465);
    check("ManageSieve takes port 4190", described.listeners.managesieve.port === 4190);
    check("PLAIN is the advertised mechanism", described.mechanisms.join(",") === "PLAIN");
    check("nothing is bound before start", Object.keys(described.bound).length === 0);

    // The MX listener refuses to bind for a domain nobody prepared,
    // because mail arriving before SPF, DKIM and DMARC exist is mail
    // nobody can authenticate. The refusal has to name the variable
    // that clears it, or an operator has a dead end rather than a step.
    var gateMessage = null;
    try { await listeners.start(); } catch (e) { gateMessage = (e && e.message) || String(e); }
    check("the MX listener refuses to bind without an acknowledged DNS posture",
      gateMessage !== null && gateMessage.indexOf("BLAMEPOST_DNS_ACKNOWLEDGED") !== -1);
    check("and nothing was left bound behind it",
      Object.keys(listeners.bound()).length === 0);

    // The server wide setting is not a blanket answer for the domains
    // the server hosts. example.com was added above and nobody has
    // acknowledged it, so the gate still refuses and names it.
    var perDomain = blamepost.mail.listeners.create({
      config: {
        hostname:        "mx.example.com",
        dnsAcknowledged: true,
        listeners:       { mx: { port: 2526 } },
      },
      store:      handle,
      mailStore:  recordingMailStore,
      certificate: certs.handle({}),
      delivery:   recordingDelivery,
    });
    var perDomainMessage = null;
    try { await perDomain.start(); }
    catch (e) { perDomainMessage = (e && e.message) || String(e); }
    count("an acknowledged server does not acknowledge its domains",
      perDomainMessage !== null && perDomainMessage.indexOf("example.com") !== -1,
      perDomainMessage);
    count("and the refusal names the command that clears it",
      perDomainMessage !== null && perDomainMessage.indexOf("domain acknowledge") !== -1,
      perDomainMessage);
    check("nothing bound behind the per domain refusal either",
      Object.keys(perDomain.bound()).length === 0);
    await perDomain.stop({ timeoutMs: 1000 });

    // Draining what never bound is a no operation rather than an error,
    // so a shutdown path does not have to know how far the boot got.
    var drained = await listeners.stop({ timeoutMs: 1000 });
    check("stopping a server that never bound closes nothing and throws nothing",
      drained.closed.length === 0);

    refuses("a port written as a string throws at configuration time", function () {
      blamepost.mail.listeners.create({
        config: { hostname: "mx.example.com", listeners: { imap: { port: "143" } } },
        store: handle, mailStore: recordingMailStore, certificate: certs.handle({}), delivery: recordingDelivery,
      });
    });
    refuses("an incomplete store contract throws at create time", function () {
      blamepost.mail.listeners.create({
        config: { hostname: "mx.example.com" },
        store: { resolve: function () {} },
        mailStore: recordingMailStore, certificate: certs.handle({}), delivery: recordingDelivery,
      });
    });
    refuses("a missing certificate throws at create time", function () {
      blamepost.mail.listeners.create({
        config: { hostname: "mx.example.com" },
        store: handle, mailStore: recordingMailStore, delivery: recordingDelivery,
      });
    });
    refuses("a missing hostname throws at create time", function () {
      blamepost.mail.listeners.create({
        config: {}, store: handle, mailStore: recordingMailStore,
        certificate: certs.handle({}), delivery: recordingDelivery,
      });
    });

    var pop3On = blamepost.mail.listeners.create({
      config: { hostname: "mx.example.com", dnsAcknowledged: true, pop3Enabled: true },
      store: handle, mailStore: recordingMailStore, certificate: certs.handle({}), delivery: recordingDelivery,
    });
    check("the configuration switch turns POP3 on",
      pop3On.describe().listeners.pop3.enabled === true);

    // ---- routing the listeners depend on -------------------------------------

    var account = await handle.accounts.create({
      address: "alice@example.com", password: "a password long enough to pass",
    });
    var verdict = handle.resolve("Alice+Receipts@Example.com");
    check("the store resolves a tagged address to the mailbox",
      verdict.deliverable === true && verdict.targets.length === 1);
    check("the resolved target names the account",
      verdict.targets[0].accountId === account.id);
    check("an address on a domain this server does not host is not local",
      handle.resolve("someone@elsewhere.example").local === false);
    check("an address with no mailbox is local and undeliverable",
      handle.resolve("nobody@example.com").local === true &&
      handle.resolve("nobody@example.com").deliverable === false);

    return helpers.getChecks();
  } finally {
    handle.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(dataDir);
  }
}

module.exports = { name: "mail-dkim", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
