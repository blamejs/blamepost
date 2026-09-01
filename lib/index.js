// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost
 * @title  Composition facade
 *
 * @intro
 *   The map of this server. Every subsystem is attached from here, and
 *   a subsystem you cannot find on this page is attached in the wrong
 *   place.
 *
 *   What this exports is deliberately small. A member that is not
 *   wired is absent rather than present and broken, because a facade
 *   that advertises a verb which throws is worse than one that never
 *   mentioned it: the caller finds out at run time, in production,
 *   from a stack trace.
 *
 *   ## What is here
 *
 *   `mail` holds the protocol and message modules: listener
 *   composition, the single outbound path, DKIM signing with its
 *   selector lifecycle, message composition, and DNS posture
 *   verification.
 *
 *   `web` holds the browser surface: webmail, the administration
 *   console, the JMAP mount at `/jmap`, the readiness probe and the
 *   well known documents, all on the one HTTP application rather than
 *   on a port each. The JMAP push channels ride the same ports: the
 *   event source stream is a route, and the WebSocket transport is
 *   attached to each bound server's upgrade event, which is a separate
 *   mounting step because an upgrade never reaches the router.
 *
 *   `create` builds one running server out of them and returns a
 *   `start` and `stop` pair. `resolver` and `tlsContext` are the two
 *   framework helpers a caller needs before `create` will accept its
 *   arguments.
 *
 *   ## What is deliberately not here
 *
 *   The vendored framework handle. Re-exporting it would put several
 *   hundred upstream primitives into this project's public surface,
 *   where every refresh would read as an API change to a gate that
 *   should be watching this project's own shape. Code that needs the
 *   framework requires `lib/vendor/blamejs` directly.
 *
 *   Configuration loading and the stores. `create` takes them as
 *   arguments rather than reaching for them, which keeps the
 *   dependency arrow pointing one way: the command line builds the
 *   configuration and opens the stores, then hands both to this file.
 *   The reverse would make the facade impossible to exercise without a
 *   data directory on disk.
 *
 *   ## The arguments create expects
 *
 *   `config` is what `lib/config` returns: `hostname`, `dataDir`,
 *   `dnsAcknowledged`, `pop3Enabled`, the optional `tlsCert` and
 *   `tlsKey` paths, and the resolved `paths` block. The vault must
 *   already be open, which is what opening the store does.
 *
 *   `store` is what `lib/store` returns: the identity and routing
 *   layer that owns accounts, domains, aliases and address
 *   resolution. The listeners reach for `resolve(recipient)`,
 *   `accounts.authenticate(credentials)` and `domains.list()`.
 *
 *   `mailStore` is the message store the protocols read and write. It
 *   is the application's protocol-facing adapter over `b.mailStore`,
 *   not `b.mailStore` itself, because the listeners call it with
 *   per session verbs such as `selectFolder` and `expungeFolder` that
 *   carry the acting account.
 *
 *   `messageStore` is the `b.mailStore` handle underneath that
 *   adapter, and it is optional: one is composed over the open
 *   database when the caller names none. Two arguments for one body of
 *   mail looks redundant and is not. The adapter speaks in sessions,
 *   which is what a wire protocol has; the mailbox access agent
 *   addresses messages by object id, which is what JMAP and the
 *   browser surface have. Both read the same rows.
 */

var nodeCrypto = require("node:crypto");

var pkg = require("../package.json");
var b = require("./vendor/blamejs");

var listeners = require("./mail/listeners");
var delivery = require("./mail/delivery");
var dkim = require("./mail/dkim");
var compose = require("./mail/compose");
var posture = require("./mail/posture");
var mailbox = require("./mail/mailbox");
var web = require("./web");

var TIME = b.constants.TIME;

var DEFAULT_STOP_MS = TIME.seconds(20);

// How often a running server anchors its audit trail, and the range a
// caller naming its own interval is held to.
//
// The trail's witness outside the database advances only when a
// checkpoint is written. The framework writes one when the volume is
// opened, and the ordered shutdown writes another on the way out, so
// with nothing in between a server that is KILLED rather than stopped
// leaves every row written since it started outside what that witness can
// answer for. Those rows can then be rewritten on the stopped volume, in
// full, with the record beside them still agreeing, which is the one
// rewrite the record exists to refuse. An out of memory kill, a host
// reboot, a container killed rather than signaled and a power loss all
// arrive that way, so this is the ordinary case rather than the exotic
// one.
//
// An hour is where the cost stops being free and the guarantee is still
// worth stating. Measured on this tree: an anchor with rows to cover
// costs about a tenth of a second of signing, plus one encrypt of the
// whole database, which is work the framework already repeats every five
// minutes on its own. What it leaves behind is permanent, and that is the
// half that decides the number: each anchor stores a signature of just
// under fifty kilobytes, and every later verification of the chain walks
// every one of them at roughly three milliseconds each. An interval short
// enough to make the window negligible turns a year of service into tens
// of gigabytes of signatures and a verification measured in hours; an
// hour of it keeps that year inside half a gigabyte and bounds the window
// at the last hour. An hour on a QUIET server costs neither, because the
// tip has not moved and nothing is signed or written.
var DEFAULT_AUDIT_ANCHOR_MS = TIME.hours(1);

// A day is the longest interval at which this is still doing anything.
// Past it the anchoring is a gesture, and a value that large is more
// likely a unit that slipped than a posture anybody chose. There is no
// value that turns it off: a security default that can be switched off is
// one deployment away from being off everywhere it mattered.
var MAX_AUDIT_ANCHOR_MS = TIME.days(1);

// The runtime environments a build meant for production must not be
// started in. Each of them turns on a convenience somewhere in the
// dependency tree, and none of them is a thing an operator sets on
// purpose on the machine that holds other people's mail.
var FORBIDDEN_RUNTIME_ENVIRONMENTS = Object.freeze(["development", "dev", "test"]);

// The transport floor every listener here presents. The framework raises
// the process wide minimum to this when it is required; asserting it back
// catches a dependency or an operator flag that lowered it again, which
// is invisible from every other angle.
var REQUIRED_TLS_VERSION = "TLSv1.3";

// How much of a certificate's life has to be left before this server
// stops mentioning it. Publicly trusted certificates are issued for
// ninety days or fewer and renewal clients aim to replace them with a
// third of the life remaining, so a server still holding one inside two
// weeks is a server whose renewal has already missed several attempts.
// Saying so then leaves an operator a fortnight to look, which is the
// difference between a task and an outage.
var EXPIRY_NOTICE_DAYS = 14;

// What `b.vault.sealPemFile` writes ahead of a sealed private key. A
// file starting with it is a sealed cell rather than PEM, and reading it
// as PEM would report an unusable key on a key that is perfectly good.
var SEALED_PEM_PREFIX = "vault:";

// The PEM block that opens a certificate. Counted rather than parsed:
// the question the count answers is how many certificates the file
// holds, which is what separates a chain from a bare leaf.
var CERTIFICATE_PEM_RE = /-----BEGIN CERTIFICATE-----/g;

// The Node major version this build refuses to run below, taken from the
// one place that declares it so a raised floor cannot leave the boot
// assertion behind on the old one.
function _nodeFloorMajor() {
  var declared = (pkg.engines && pkg.engines.node) || "";
  var found = /(\d+)/.exec(String(declared));
  if (!found) {
    throw new TypeError("blamepost: package.json declares no engines.node, so there is no " +
      "Node floor to assert at boot. Set it to the oldest release this build supports.");
  }
  return parseInt(found[1], 10);
}


/**
 * @primitive blamepost.resolver
 * @signature blamepost.resolver(opts?)
 * @since     0.1.0
 * @status    stable
 * @spec      internal (design: one DNS resolver shared by every mail path)
 * @related   blamepost.create
 *
 * Build the DNS resolver the mail paths share. One resolver rather
 * than one per subsystem, so the cache is shared: the MX lookup an
 * outbound delivery performs is the same answer the posture check
 * reads, and a domain queried on every message is queried once.
 *
 * The strict profile is the default because these lookups drive
 * security decisions. A spoofed MTA-STS or DKIM answer changes what
 * this server will accept and how it will send.
 *
 * @example
 *   var resolver = blamepost.resolver();
 *   var answer = await resolver.queryTxt("_dmarc.example.com");
 */
function resolver(opts) {
  return b.network.dns.resolver.create(Object.assign({ profile: "strict" }, opts || {}));
}

/**
 * @primitive blamepost.tlsContext
 * @signature blamepost.tlsContext(opts)
 * @since     0.1.0
 * @status    stable
 * @spec      internal (design: operator-supplied certificate, reloaded on rotation)
 * @related   blamepost.create
 *
 * Load the certificate and key the listeners present, and keep
 * watching them. Composes `b.mail.server.tls.context`, so a renewal
 * written to the same paths is picked up in process rather than at the
 * next restart. The returned handle carries `secureContext`, which is
 * what every listener wants, plus `stop()` to clear the watch timer.
 *
 * The pair itself comes from the operator. Nothing here orders or
 * renews a certificate, so whatever writes these files, a certificate
 * client or an internal authority, keeps doing so.
 *
 * The private key may be sealed on disk. Passing the vault handle lets
 * the loader unseal it at load time without the plaintext key ever
 * being written anywhere.
 *
 * The context also carries this server's key-agreement preference, from
 * `blamepost.mail.listeners.keyAgreementGroups`. Left unset the loader
 * composes the same server-form string on its own, so what naming it
 * here buys is not the string but the refusal attached to it: that
 * accessor will not return a preference whose leading tuple names no
 * post-quantum hybrid. The browser port reads the same accessor by a
 * different route, so every port that negotiates a key answers to the
 * same refusal.
 *
 * @opts
 *   certFile: string,    // required; PEM chain
 *   keyFile:  string,    // required; PEM private key, sealed or plain
 *   vault:    object,    // optional; unseals a sealed key file
 *   watch:    boolean,   // reload on rotation; default true
 *   pollMs:   number,    // how often to look; default is the framework's
 *
 * @example
 *   var tls = blamepost.tlsContext({
 *     certFile: "/var/lib/blamepost/tls/fullchain.pem",
 *     keyFile:  "/var/lib/blamepost/tls/privkey.pem",
 *   });
 *   tls.secureContext;
 */
function tlsContext(opts) {
  if (!opts || typeof opts !== "object") {
    throw new TypeError("blamepost.tlsContext: opts object is required");
  }
  return b.mail.server.tls.context({
    certFile:  opts.certFile,
    keyFile:   opts.keyFile,
    vault:     opts.vault,
    watch:     opts.watch === undefined ? true : opts.watch === true,
    pollMs:    opts.pollMs,
    ecdhCurve: listeners.keyAgreementGroups(),
  });
}

// A certificate handle over material somebody else already turned into a
// context. It reports the same `secureContext` accessor the loader does,
// so everything downstream reads a certificate the same way whether or
// not a file is being watched, and it says plainly that it cannot
// rotate: there is no path behind it for a renewal to be written to.
function _staticCertificate(secureContext) {
  return {
    get secureContext() { return secureContext; },
    certFile: null,
    keyFile:  null,
    watched:  false,
    stop:     function () {},
  };
}

// One finding, in the shape `blamepost doctor` renders, plus the one
// thing a boot needs that a report does not: whether this stops a
// server from starting.
//
// The two questions are genuinely different and conflating them gets one
// of them wrong. A certificate can be WRONG without being UNUSABLE. A
// chain missing its issuer serves every peer that does not verify the
// issuer and fails the ones that do; a certificate issued to another
// name serves every peer that does not check the name. Both are real
// faults, both belong in a report as failures, and neither is a reason
// to refuse to start a server that would otherwise carry mail. An
// operator who has been running that way for a year should not have a
// version upgrade take their server down over it.
//
// What is fatal is a certificate this server cannot present at all: a
// file it cannot read, bytes that are not a certificate, a key that
// belongs to a different one so no context can be built, or a validity
// window that has closed, which no deployment intends and which every
// peer that checks anything at all refuses.
function _certFinding(check, ok, detail, opts) {
  var finding = { check: check, ok: ok === true, detail: detail };
  if (opts && opts.advised === true) finding.severity = "advised";
  finding.fatal = !!(opts && opts.fatal === true);
  return finding;
}

function _readPem(path, maxBytes, label, findings) {
  try {
    return b.atomicFile.fdSafeReadSync(path, { maxBytes: maxBytes, encoding: "utf8" });
  } catch (err) {
    findings.push(_certFinding(label, false,
      "cannot be read at " + path + ": " + ((err && err.message) || String(err)) +
      ". The process that runs this server has to be able to read both halves of the pair; " +
      "a key readable only by root is the usual cause on a container that drops privileges.",
      { fatal: true }));
    return null;
  }
}

/**
 * @primitive blamepost.certificateReport
 * @signature blamepost.certificateReport(opts)
 * @since     0.1.0
 * @status    stable
 * @spec      internal (design: read the certificate rather than confirm the file exists)
 * @related   blamepost.tlsContext, blamepost.create
 *
 * Read the certificate and key an operator supplied and report what is
 * actually in them. Answers the questions a file existence check cannot:
 * when it expires, whether the key belongs to it, whether it covers the
 * name this server answers to, and whether the chain is complete.
 *
 * Every one of those fails silently. A certificate that expired last
 * night is a file that is still present and still readable, so a server
 * checking only for a file starts, binds every port and refuses every
 * handshake. A leaf with no issuer beside it works in a browser, which
 * fetches the missing intermediate, and fails against sending mail
 * servers, which do not, so the operator's own test passes and the mail
 * stops. A key from a previous issuance produces a context that cannot
 * be built at all.
 *
 * Each finding says whether it passed and, separately, whether it is
 * FATAL. The two are not the same question. A chain missing its issuer
 * and a certificate issued to another name are both real faults and
 * both reported as failures, and neither stops a server from carrying
 * mail: every peer that does not verify the issuer or the name is served
 * exactly as before. What is fatal is a certificate this server cannot
 * present at all: an unreadable file, bytes that are not a certificate,
 * a key belonging to a different one, or a validity window that has
 * closed.
 *
 * Nothing here reaches the network and nothing is written. The private
 * key is read to compare it against the certificate and is never
 * reported, logged or returned.
 *
 * @opts
 *   certFile: string,   // required; the PEM chain
 *   keyFile:  string,   // required; the private key, sealed or plain
 *   hostname: string,   // the name to check the certificate covers
 *   vault:    object,   // unseals a sealed key; defaults to the framework vault
 *   now:      number,   // epoch ms the validity window is measured against
 *
 * @example
 *   var report = blamepost.certificateReport({
 *     certFile: config.tlsCert,
 *     keyFile:  config.tlsKey,
 *     hostname: config.hostname,
 *   });
 *   report.expiresInDays;
 */
function certificateReport(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.certificateReport: opts object is required");
  }
  if (typeof opts.certFile !== "string" || opts.certFile.length === 0) {
    throw new TypeError("blamepost.certificateReport: opts.certFile is required");
  }
  if (typeof opts.keyFile !== "string" || opts.keyFile.length === 0) {
    throw new TypeError("blamepost.certificateReport: opts.keyFile is required");
  }
  var now = opts.now === undefined ? Date.now() : opts.now;
  if (typeof now !== "number" || !isFinite(now)) {
    throw new TypeError("blamepost.certificateReport: opts.now must be an epoch in milliseconds");
  }

  var findings = [];
  var report = {
    certFile:      opts.certFile,
    keyFile:       opts.keyFile,
    subject:       null,
    issuer:        null,
    serial:        null,
    validFrom:     null,
    validTo:       null,
    expiresInDays: null,
    chainLength:   0,
    selfSigned:    false,
    findings:      findings,
    ok:            false,
  };

  var certPem = _readPem(opts.certFile, b.constants.BYTES.mib(1), "certificate file", findings);
  if (certPem === null) return report;

  var leaf;
  try {
    leaf = new nodeCrypto.X509Certificate(certPem);
  } catch (err) {
    findings.push(_certFinding("certificate file", false,
      opts.certFile + " does not hold a certificate this server can read: " +
      ((err && err.message) || String(err)) + ". A key written where the chain belongs " +
      "reads exactly like this.", { fatal: true }));
    return report;
  }

  report.subject     = String(leaf.subject || "").replace(/\r?\n/g, ", ");
  report.issuer      = String(leaf.issuer || "").replace(/\r?\n/g, ", ");
  report.serial      = leaf.serialNumber || null;
  report.validFrom   = leaf.validFrom || null;
  report.validTo     = leaf.validTo || null;
  report.chainLength = (certPem.match(CERTIFICATE_PEM_RE) || []).length;
  try { report.selfSigned = leaf.verify(leaf.publicKey) === true; }
  catch (_e) { report.selfSigned = false; }

  // ---- when it expires ----
  var notAfter  = Date.parse(leaf.validTo);
  var notBefore = Date.parse(leaf.validFrom);
  if (isFinite(notAfter)) {
    report.expiresInDays = Math.floor((notAfter - now) / TIME.days(1));
  }
  if (isFinite(notBefore) && notBefore > now) {
    findings.push(_certFinding("certificate validity", false,
      "the certificate at " + opts.certFile + " is not valid until " + leaf.validFrom +
      ". Every handshake is refused until then. A host whose clock is wrong reads a " +
      "perfectly good certificate this way, so check the clock before reissuing.",
      { fatal: true }));
  } else if (!isFinite(notAfter)) {
    findings.push(_certFinding("certificate validity", false,
      "the certificate at " + opts.certFile + " carries no readable expiry date.",
      { fatal: true }));
  } else if (notAfter <= now) {
    findings.push(_certFinding("certificate validity", false,
      "the certificate at " + opts.certFile + " expired on " + leaf.validTo + ". Every " +
      "listener here requires TLS, so until it is replaced this server refuses every " +
      "connection offered to it. Renew it and write the new pair to the same two paths.",
      { fatal: true }));
  } else if (report.expiresInDays <= EXPIRY_NOTICE_DAYS) {
    findings.push(_certFinding("certificate validity", true,
      "expires on " + leaf.validTo + ", in " + report.expiresInDays + " day(s). Renewal " +
      "clients replace a certificate with about a third of its life left, so this one has " +
      "already missed several attempts. Check whatever runs the renewal.", { advised: true }));
  } else {
    findings.push(_certFinding("certificate validity", true,
      "valid until " + leaf.validTo + ", " + report.expiresInDays + " day(s) from now"));
  }

  // ---- whether the key belongs to it ----
  var keyPem = _readPem(opts.keyFile, b.constants.BYTES.kib(64), "private key file", findings);
  if (keyPem !== null) {
    if (keyPem.indexOf(SEALED_PEM_PREFIX) === 0) {
      var vault = opts.vault || b.vault;
      try { keyPem = vault.unseal(keyPem).toString("utf8"); }
      catch (err2) {
        keyPem = null;
        // A seal authenticates what it carries end to end, so there are
        // two ways it does not open: the bytes were written under a
        // different volume's vault key, or they have been damaged where
        // they lie. The passphrase is not a third. It opens
        // vault.key.sealed while the vault is being opened, which
        // happens before anything here runs and refuses the boot
        // outright when it does not fit, so a passphrase that had
        // changed would never have reached this read.
        findings.push(_certFinding("private key", false,
          "the key at " + opts.keyFile + " is sealed and would not open: " +
          ((err2 && err2.message) || String(err2)) + ". It was written under a different " +
          "volume's vault key, or its bytes have been damaged where they lie. Restore the " +
          "file from a backup taken before the damage, or write the unsealed pair to the " +
          "two paths this server reads.", { fatal: true }));
      }
    }
    if (keyPem !== null) {
      var matches = false;
      var keyProblem = null;
      try { matches = leaf.checkPrivateKey(nodeCrypto.createPrivateKey(keyPem)) === true; }
      catch (err3) { keyProblem = (err3 && err3.message) || String(err3); }
      if (keyProblem !== null) {
        findings.push(_certFinding("private key", false,
          "the key at " + opts.keyFile + " could not be read as a private key: " + keyProblem +
          ". A certificate written where the key belongs reads exactly like this, so check " +
          "that the two paths are not pointing at each other.", { fatal: true }));
      } else if (!matches) {
        findings.push(_certFinding("private key", false,
          "the key at " + opts.keyFile + " does not belong to the certificate at " +
          opts.certFile + ". The two are from different issuances, which happens when a " +
          "renewal wrote one file and not the other. Write both halves of one pair.",
          { fatal: true }));
      } else {
        findings.push(_certFinding("private key", true, "matches the certificate"));
      }
    }
  }

  // ---- whether it covers the name this server answers to ----
  if (typeof opts.hostname === "string" && opts.hostname.length > 0) {
    var covered;
    try { covered = leaf.checkHost(opts.hostname); }
    catch (_e2) { covered = null; }
    if (covered === undefined || covered === null) {
      findings.push(_certFinding("certificate name", false,
        "the certificate at " + opts.certFile + " is issued to " + report.subject +
        " and does not cover " + opts.hostname + ", which is the name this server " +
        "announces and the name an MX record points at. Every peer that verifies the " +
        "name refuses the connection."));
    } else {
      findings.push(_certFinding("certificate name", true, "covers " + opts.hostname));
    }
  }

  // ---- whether the chain is complete ----
  //
  // The single most common way a mail certificate is wrong, and the one
  // that hides best: browsers fetch a missing intermediate themselves,
  // so the operator's own check of the web port passes while every
  // sending mail server, which does not fetch anything, fails the
  // handshake. A self-signed certificate is a whole chain on its own and
  // is left alone.
  if (report.chainLength <= 1 && !report.selfSigned) {
    findings.push(_certFinding("certificate chain", false,
      opts.certFile + " holds one certificate and it is not self-signed, so the issuer " +
      "that vouches for it is missing. A browser fetches that issuer on its own and a " +
      "sending mail server does not, so this fails on the mail ports while a web check " +
      "of the same certificate passes. Point BLAMEPOST_TLS_CERT at the full chain: " +
      "certificate clients write it as fullchain.pem beside the cert.pem that holds " +
      "only the leaf."));
  } else {
    findings.push(_certFinding("certificate chain", true,
      report.selfSigned && report.chainLength <= 1
        ? "one self-signed certificate, which is a complete chain"
        : report.chainLength + " certificates, leaf first"));
  }

  report.ok = findings.every(function (f) { return f.ok; });
  return report;
}

/**
 * @primitive blamepost.productionPosture
 * @signature blamepost.productionPosture(config)
 * @since     0.1.0
 * @status    stable
 * @spec      internal (design: the deployment guarantees a boot refuses without)
 * @related   blamepost.create
 *
 * The deployment posture `start` asserts before the first listener
 * binds, as the option set `b.security.assertProduction` reads. It is a
 * value rather than a call so an operator, and this project's own
 * tests, can see the whole list in one place instead of inferring it
 * from a boot that happened to succeed.
 *
 * What each entry defends is the same failure in a different place: a
 * server that is configured correctly and deployed wrong. The vault left
 * in its unprotected mode, the database written in the clear, the audit
 * signing key unsealed on disk, the clock unchecked so every audit
 * timestamp is a guess, the transport minimum lowered back below TLS
 * 1.3, a data directory the rest of the host can read, or the process
 * started in a developer's runtime environment. Every one of those is
 * silent: mail flows, and the guarantees underneath it are not the ones
 * the operator was told they had.
 *
 * The at-rest mode is read through a resolver of this project's own,
 * because the framework's default reads an accessor it does not export
 * and therefore reports an absent mode for every caller.
 *
 * Not asserted here, and worth knowing rather than assuming. The
 * checks that read a mounted middleware list need a router that
 * publishes one, and no router in the vendored framework does, so
 * requiring CSRF, the content security policy nonce, the request bound
 * and a refusal of wildcard cross origin sharing through this primitive
 * would only ever report that the list could not be read. Those
 * middleware are wired unconditionally in the browser surface and
 * exercised there.
 *
 * @example
 *   blamepost.productionPosture(config).vault;
 *   // "wrapped"
 */
function productionPosture(config) {
  if (!config || typeof config !== "object") {
    throw new TypeError("blamepost.productionPosture: config object is required");
  }
  var dataDir = (config.paths && config.paths.dataDir) || config.dataDir;
  return {
    vault:         "wrapped",
    dbAtRest:      "encrypted",
    auditSigning:  "wrapped",
    ntpStrict:     true,
    minNodeMajor:  _nodeFloorMajor(),
    minTlsVersion: REQUIRED_TLS_VERSION,
    dataDir:       dataDir,
    forbidNodeEnv: FORBIDDEN_RUNTIME_ENVIRONMENTS.slice(),
    resolvers: {
      dbAtRest: function () { return b.db.getMode(); },
    },
    audit: b.audit,
  };
}

// The certificate has to be usable before anything binds.
//
// The loader builds a context out of whatever bytes are on disk and asks
// no questions about them, so a certificate that expired three weeks ago
// produces a server that starts cleanly, reports every listener bound,
// answers its own health probe, and refuses every connection anyone
// offers it. That state is indistinguishable from a network fault from
// the outside and from a working server from the inside, which is the
// worst pair of properties a failure can have. Reading the pair here
// turns it into a refusal that names the date.
//
// Only the conditions that make the certificate unusable stop a boot. An
// expiry that is merely close is said out loud and does not, because a
// server that still works should keep working while the operator fixes
// the renewal.
function _refuseUnusableCertificate(config, vault) {
  var report = certificateReport({
    certFile: config.tlsCert,
    keyFile:  config.tlsKey,
    hostname: config.hostname,
    vault:    vault,
  });
  var fatal = report.findings.filter(function (f) { return f.fatal === true; });
  if (fatal.length > 0) {
    throw new TypeError("blamepost.create: the certificate this server would present " +
      "cannot be used.\n" +
      fatal.map(function (f) { return "  - " + f.check + ": " + f.detail; }).join("\n") +
      "\nBLAMEPOST_TLS_CERT is " + config.tlsCert + " and BLAMEPOST_TLS_KEY is " +
      config.tlsKey + ". Nothing here issues or renews a certificate, so whatever wrote " +
      "them is the operator's to correct. `blamepost doctor` reports the same reading " +
      "without starting anything.");
  }
  // Everything else the reading found. These are faults an operator
  // should fix and none of them stops a server that would otherwise
  // carry mail, so they are said once at boot and left alone: a chain
  // with no issuer and a certificate issued to another name both work
  // against every peer that does not check, which is most of them, and
  // taking a working server down over either would cost more than it
  // saved. `blamepost doctor` reports them as failures, which is where a
  // fault belongs.
  var notices = report.findings.filter(function (f) {
    return f.fatal !== true && (!f.ok || f.severity === "advised");
  });
  if (notices.length > 0) {
    var log = b.log.boot("tls");
    notices.forEach(function (f) { log.warn(f.check + ": " + f.detail); });
  }
}

// Say what a rotation did, and say what it did not do.
//
// A renewal that reaches some listeners and not others is the state an
// operator is least able to diagnose: the port they check presents the
// new certificate, so the certificate looks fine, while a different port
// goes on failing. Naming the ports that kept the old material turns a
// silent partial rotation into a line saying which one still needs a
// restart. A rotation that reaches everything says so and names nothing.
//
// The names come from `staleAfterRotation`, which asks each layer what
// it does with its certificate. A list written here instead would go on
// naming a port long after that port started rotating, which is a
// warning that has become a lie about the one subject nobody can check
// from the outside.
function _reportRotations(tlsHandle, config, vault, staleAfterRotation) {
  var log = b.log.boot("tls");
  tlsHandle.onReload(function () {
    var stale = staleAfterRotation();
    var line = "certificate reloaded from " + config.tlsCert + "; every listener that can " +
      "take a new certificate while this process runs now presents it.";
    if (stale.length > 0) {
      log.warn(line + " Still holding the certificate this process started with, until it " +
        "is restarted: " + stale.join(", ") + ".");
    } else {
      log.info(line);
    }
    var report = certificateReport({
      certFile: config.tlsCert,
      keyFile:  config.tlsKey,
      hostname: config.hostname,
      vault:    vault,
    });
    // Read after the reload rather than refused before it. A running
    // server that has just been handed a certificate it cannot use keeps
    // the one it had, so the answer here is a warning about what was
    // written rather than a reason to stop serving.
    report.findings.forEach(function (f) {
      if (!f.ok || f.severity === "advised") log.warn("renewed certificate: " + f.detail);
    });
  });
}

/**
 * @primitive blamepost.create
 * @signature blamepost.create(opts)
 * @since     0.1.0
 * @status    stable
 * @spec      internal (design: one lifecycle over every mail subsystem)
 * @related   blamepost.resolver, blamepost.tlsContext, blamepost.mail.listeners.create
 *
 * Assemble one server. Builds the outbound path, the DKIM handle, the
 * composer, the posture checker, the mailbox access agent, the protocol
 * listeners and the browser surface, wires them to each other, and
 * returns `{ start, stop, describe, mail, web, config }`.
 *
 * Nothing binds and nothing is written until `start`. The deployment
 * posture is asserted first, so a server whose vault, database, audit
 * signing, clock, transport floor, data directory or runtime
 * environment is not what this build guarantees refuses rather than
 * serving mail under guarantees it does not hold. The mail listeners
 * come up next behind their own boot gates, including the one that
 * keeps the MX port shut until the DNS records are acknowledged, then
 * the HTTP listener, so the readiness probe reports a complete server
 * the moment it can answer at all. The trail's anchoring is armed last,
 * once everything that could refuse has come up. `stop` reverses it
 * inside a deadline: the anchoring comes down first and any pass
 * already running is waited for, so nothing anchors while the store is
 * closing and nothing races the shutdown's own final anchor, then
 * outbound sweeping stops so no new attempt begins during the drain,
 * then the browser surface drains, then the mail listeners close, then
 * the certificate watcher.
 *
 * While it runs, the trail is anchored on `auditAnchorMs`. The record
 * beside the volume, which is what a wholesale rewrite of the chain has
 * to get past, otherwise advances only when the volume is opened and
 * when an ordered shutdown closes it, so a server that is killed rather
 * than stopped would leave every row written since it started with
 * nothing outside the database to answer for it. Anchoring on an
 * interval bounds that to the interval. It cannot fail the server: a
 * pass that throws is recorded and dropped, because a trail that could
 * not be anchored is not a reason to lose the delivery that was in
 * flight when it happened.
 *
 * The certificate can arrive two ways, and they differ in more than
 * spelling. Naming the files through `config.tls` puts the loader on
 * the path, so the pair is read before anything binds and a renewal
 * written to those paths later reaches the running mail listeners.
 * Passing `tlsContext` hands over material nothing is watching: it
 * cannot rotate, and it is the shape a test uses rather than the shape a
 * deployment does. With neither, this throws rather than starting
 * listeners that would have no way to encrypt anything. Only the file
 * form reaches the HTTP listener, because a Node TLS server builds its
 * own context from bytes and cannot be handed one.
 *
 * A rotation reaches every listener, and the reload says so. Any port it
 * did not reach would be named there instead, rather than left for an
 * operator to find out from a client that stopped connecting. The list is
 * asked of each layer rather than written down, so a port that stops
 * rotating is named without an edit here.
 *
 * @opts
 *   config:       object,   // required; the loaded configuration
 *   store:        object,   // required; accounts, domains, aliases, address resolution
 *   mailStore:    object,   // required; the protocol facing message store
 *   messageStore: object,   // the b.mailStore under it; composed over b.db when absent
 *   agent:        object,   // overrides the adapter's agent; build it with blamepost.mail.mailbox.agent
 *   tlsContext:   object,   // a node:tls SecureContext, when one is already built; cannot rotate
 *   tlsPollMs:    number,   // how often the certificate files are re-read; default is the framework's
 *   auditAnchorMs: number,  // how often a running server anchors its audit trail; default one hour
 *   vault:        object,   // seal and unseal pair; defaults to the framework vault
 *   resolver:     object,   // a shared DNS resolver, when one is already built
 *   greylist:     object,   // optional inbound gate
 *   rbl:          object,   // optional inbound gate
 *   httpAddress:  string,   // interface the browser surface binds; default 0.0.0.0
 *
 * @example
 *   var server = blamepost.create({ config: config, store: store, mailStore: store.mailbox });
 *   await server.start();
 */
function create(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.create: opts object is required");
  }
  var config = opts.config;
  if (!config || typeof config !== "object") {
    throw new TypeError("blamepost.create: opts.config is required");
  }
  if (typeof config.hostname !== "string" || config.hostname.length === 0) {
    throw new TypeError("blamepost.create: config.hostname is required. Set " +
      "BLAMEPOST_HOSTNAME to the public name of this server, the one the MX record " +
      "points at.");
  }
  if (typeof config.dataDir !== "string" || config.dataDir.length === 0) {
    throw new TypeError("blamepost.create: config.dataDir is required. It holds the " +
      "database, the outbound spool, the DKIM keys and the certificates.");
  }

  // How often the trail is anchored while this server runs. Refused at
  // assembly rather than accepted and misread later: an interval that is
  // not an interval would leave the window at the whole uptime, and the
  // only symptom is a volume nobody can vouch for after it has already
  // been stopped.
  var auditAnchorMs = opts.auditAnchorMs === undefined
    ? DEFAULT_AUDIT_ANCHOR_MS
    : opts.auditAnchorMs;
  if (typeof auditAnchorMs !== "number" || !isFinite(auditAnchorMs) ||
      auditAnchorMs <= 0 || auditAnchorMs > MAX_AUDIT_ANCHOR_MS) {
    throw new TypeError("blamepost.create: opts.auditAnchorMs must be a positive number of " +
      "milliseconds no greater than " + MAX_AUDIT_ANCHOR_MS + ", which is a day. It is how " +
      "often a running server anchors its audit trail, and it is what bounds how much of " +
      "that trail is left outside the record beside the volume when this process is killed " +
      "rather than stopped. Received " + JSON.stringify(opts.auditAnchorMs) + ".");
  }

  var sharedResolver = opts.resolver || resolver();
  var vault = opts.vault || b.vault;

  // The certificate, as a handle that is read rather than a value that
  // was read. Everything downstream takes this object and asks it for a
  // context when it needs one, so a renewal written to the two files
  // while this process is serving reaches the listeners instead of being
  // loaded and discarded.
  var tlsHandle = null;
  var certificate;
  if (opts.tlsContext) {
    // A caller that built its own context is naming a certificate that
    // nothing is watching, so this one cannot rotate and says so. It is
    // still presented through the same accessor as the watched form, so
    // there is one shape downstream rather than two.
    certificate = _staticCertificate(opts.tlsContext);
  } else {
    if (!config.tlsCert || !config.tlsKey) {
      throw new TypeError("blamepost.create: no certificate. Every listener here requires " +
        "TLS and none of them has a plaintext mode, so there is nothing to start. Set " +
        "BLAMEPOST_TLS_CERT and BLAMEPOST_TLS_KEY to a certificate and key on disk. " +
        ((config.paths && config.paths.tls) || (config.dataDir + "/tls")) +
        " is the directory this server keeps for them, and whatever writes them there, an " +
        "ACME client or an internal authority, is the operator's to run.");
    }
    // What the pair on disk actually is, before anything binds. The
    // loader below builds a context out of whichever bytes are there and
    // will build one out of an expired certificate without comment, so a
    // server whose renewal stopped running weeks ago would come up,
    // report every listener bound, and fail every handshake offered to
    // it. Reading the certificate here turns that into a refusal naming
    // the date it expired.
    _refuseUnusableCertificate(config, vault);
    tlsHandle = tlsContext({
      certFile: config.tlsCert,
      keyFile:  config.tlsKey,
      vault:    vault,
      watch:    true,
      pollMs:   opts.tlsPollMs,
    });
    certificate = tlsHandle;
  }

  // An optional setting the operator left alone reads as null, and the
  // outbound composer distinguishes an absent postmaster, which takes
  // its own default of mailer-daemon at this hostname, from one supplied
  // as something that is not an address. Both spellings of unset mean
  // the same thing here, so null arrives as absent rather than as a
  // refusal at create time.
  var deliveryHandle = delivery.create({
    hostname:   config.hostname,
    dataDir:    config.dataDir,
    postmaster: config.postmaster === null ? undefined : config.postmaster,
    resolver:   sharedResolver,
    policy:     config.outboundPolicy,
    retry:      config.outboundRetry,
    timeouts:   config.outboundTimeouts,
    spool:      config.outboundSpool,
    // What the listeners accept, so the queue ceiling can be checked
    // against one message rather than against a size this layer guessed.
    // A queue that cannot hold a single message the listeners take
    // refuses everything, and that is a setting to catch at boot.
    maxMessageBytes: config.limits === null || config.limits === undefined
      ? undefined : config.limits.maxMessageBytes,
    requireTls: config.requireTls === true,
  });

  // Where a delivery status notification about this server's own mail
  // gets read. Reports addressed to an account are that account's mail
  // and stay theirs; the mail this server sends about itself comes back
  // to the reporting identity, into a mailbox nobody opens, and a report
  // saying a receiver has stopped accepting the transport reports this
  // server owes it is the only notice anybody gets.
  //
  // The observation point is the filing path rather than the MX handoff
  // because filing is the one call every message reaching a mailbox
  // makes, whichever protocol put it there. That also means it cannot
  // say where a message came from, which is why the reader only ever
  // records: see blamepost.mail.delivery.reports.
  if (!opts.mailStore || typeof opts.mailStore.onFiled !== "function") {
    throw new TypeError("blamepost.create: opts.mailStore must expose onFiled, the one " +
      "point at which a message reaching a mailbox is observed. Build it with " +
      "blamepost.mail.mailbox.create, which is what blamepost.store.open hands back as " +
      "`mailbox`. Without it the reports about this server's own mail arrive and nothing " +
      "reads them.");
  }
  opts.mailStore.onFiled(deliveryHandle.reports.observe);

  var dkimHandle = dkim.create({
    dataDir: config.dataDir,
    store:   opts.store,
    vault:   vault,
  });

  var postureHandle = posture.create({
    hostname: config.hostname,
    resolver: sharedResolver,
    dkim:     dkimHandle,
  });

  var listenerHandle = listeners.create({
    config:      config,
    store:       opts.store,
    mailStore:   opts.mailStore,
    // The handle rather than the context it currently holds. Reading it
    // here would freeze the certificate at the value it had while this
    // server was starting, and the whole point of the loader is that the
    // value changes underneath a process that keeps running.
    certificate: certificate,
    delivery:    deliveryHandle,
    dkim:        dkimHandle,
    resolver:    sharedResolver,
    greylist:    opts.greylist,
    rbl:         opts.rbl,
  });

  // After the listeners, because the outbound handle the composer takes
  // is the routed one they build. A recipient this server hosts is filed
  // in the mailbox here rather than sent out to DNS and waited for on
  // port 25, so the browser compose form, JMAP EmailSubmission/set and
  // the submission listener answer that question the same way. Handing
  // `deliveryHandle` over instead is the arrangement where a desktop
  // client and the browser disagree about where one address goes.
  var composeHandle = compose.create({
    delivery:  listenerHandle.relay,
    hostname:  config.hostname,
    dkim:      dkimHandle,
    mailStore: opts.mailStore,
  });

  // The byte level substrate the agent dispatches over. The listeners
  // hold the per account adapter above it, which speaks in sessions and
  // has no object addressed read to offer; the agent needs exactly that
  // read. Composing one here when the caller names none takes a handle
  // over the open database rather than a second copy of the mail. The
  // store runs its append and its hard delete in a transaction it opens
  // through this backend, and it works out which calling convention the
  // backend offers by whether the body ran, so the framework database
  // goes in with nothing in between.
  var messageStore = opts.messageStore || b.mailStore.create({ backend: b.db });

  // The regulatory posture the mailbox access agent holds in front of a
  // hard delete, read from the one configuration key that names it.
  // `none` is the absence of a posture rather than the name of one, so
  // it becomes null: the framework refuses a posture it does not know,
  // and would refuse that string.
  var compliancePosture = config.compliancePosture && config.compliancePosture !== "none"
    ? config.compliancePosture
    : null;

  // A disagreement between the adapter and this configuration is silent
  // everywhere else: both halves answer every call, and the only visible
  // difference is a message that one protocol keeps and another
  // destroys. So it is a refusal to assemble rather than a warning, and
  // the operator finds it at boot instead of in an audit that cannot get
  // the message back.
  if (opts.mailStore && typeof opts.mailStore.describe === "function") {
    var adapterPosture = opts.mailStore.describe().posture || null;
    if (adapterPosture !== compliancePosture) {
      throw new TypeError("blamepost.create: the message adapter enforces compliance posture " +
        JSON.stringify(adapterPosture) + " and this configuration asks for " +
        JSON.stringify(compliancePosture) + ". A hard delete would then be refused on one " +
        "protocol and carried out on another. Build the adapter from the same configuration " +
        "this server is given, or pass the agent both should use as opts.agent.");
    }
  }

  // Every message read and every mailbox mutation the browser surface
  // makes goes through this, because it is what holds the retention
  // floor, the legal hold refusals and the role gate in front of the
  // store. All three are read off the agent, so an agent built with a
  // different option set destroys precisely what the other one refuses
  // and checks a role where the other one checks nothing.
  //
  // It is ONE agent, and the ordering is why this reads it rather than
  // building it. The store and its protocol facing adapter are opened
  // before `create` is called, so by the time this line runs the adapter
  // already holds the agent IMAP EXPUNGE, POP3 QUIT and ManageSieve
  // drive. Building a second here for JMAP `Email/set` `destroyed` and
  // the webmail purge is exactly the defect: two handles over one body
  // of mail, agreeing on every call they allow and differing on every
  // call they do not. So the adapter's is the one this server uses, and
  // it is composed only when the caller brought an adapter that names
  // none.
  //
  // `opts.agent` still overrides both, for a caller building the pair
  // itself, and `blamepost.mail.mailbox.agent` is what it should build
  // that agent with: an agent with no role gate is refused rather than
  // wired, because `b.mail.agent` reads a missing permission table as
  // "check nothing" and no caller downstream can tell that apart from a
  // gate that is simply permissive.
  var agentHandle = opts.agent ||
    (opts.mailStore && opts.mailStore.agent) ||
    mailbox.agent({ store: messageStore, posture: compliancePosture });
  mailbox.assertRoleGate(agentHandle, "blamepost.create");

  // The certificate reaches the browser listener as bytes rather than as
  // the context the mail listeners hold, because a Node TLS server
  // builds its own context and ignores one passed as an option. A caller
  // that supplied `tlsContext` and named no files therefore gets the
  // cleartext port alone, which is the right answer behind a proxy that
  // terminates TLS and holds the only copy of the key.
  var webTls = (config.tlsCert && config.tlsKey)
    ? { certFile: config.tlsCert, keyFile: config.tlsKey, vault: vault }
    : null;

  // The reading the readiness probe answers with. A function rather than
  // a reading, because a reading taken here describes the certificate
  // this process started with, and the whole subject is that the files
  // change underneath a process that keeps running. With no files named
  // there is nothing on disk to read and the probe says so.
  var certificateReading = webTls === null ? undefined : function () {
    return certificateReport({
      certFile: config.tlsCert,
      keyFile:  config.tlsKey,
      hostname: config.hostname,
      vault:    vault,
    });
  };

  var webHandle = null;

  // Which ports a renewal written to the two files does not reach while
  // this process runs.
  //
  // Asked of each layer rather than listed here. The mail listeners
  // publish what the framework's listeners do with their certificate,
  // and the browser surface publishes what it was actually given, so a
  // port that starts rotating drops off this list in the same change
  // that makes it rotate. A name written here instead survives the fix
  // that made it wrong, and it is a name an operator acts on by
  // restarting a mail server that did not need it.
  function staleAfterRotation() {
    var named = listeners.STALE_AFTER_ROTATION.map(function (entry) {
      return entry.listener;
    });
    return webHandle === null
      ? named
      : named.concat(webHandle.describe().staleAfterRotation);
  }

  // The listener inventory the health probes report.
  //
  // A listener that was configured and did not bind is the case this
  // exists for: a process that came up without a port it was meant to
  // hold is not fit to serve, and answering that it is fine is how mail
  // goes missing with nobody told.
  //
  // What that reading cannot do on its own is tell such a listener apart
  // from one this server deliberately left shut, and the two are not the
  // same fact at all. Port 25 stays closed while no domain is hosted,
  // which is the ordinary state of a first boot: the documented sequence
  // starts the container and only then runs the command that creates the
  // first domain, so every operator passes through it. Reported as a
  // failure, that window is a working mail server telling every readiness
  // gate, load balancer and dependent service that it is down, for as
  // long as the setup takes. Reported as nothing at all, it is a server
  // whose MX port is shut and whose monitoring says mail is arriving.
  //
  // So the row carries a state rather than a boolean, and the reason
  // travels with it. The reason is the listener layer's own sentence,
  // read from the handle rather than composed again here: a second
  // wording of why a port is shut is a second thing to keep true.
  //
  // Listeners this configuration does not enable are in the inventory
  // too, as themselves. They count against nothing, because a listener
  // nobody asked for cannot fail to arrive. Leaving them out entirely
  // makes an absence carry the answer, and an absence is also what a
  // listener wrongly read as not enabled would produce.
  var STATES = listeners.LISTENER_STATES;

  function listenerRow(name, port, reason) {
    if (typeof port === "number") return { name: name, state: STATES.BOUND, reason: null };
    if (typeof reason === "string") {
      return { name: name, state: STATES.WITHHELD, reason: reason };
    }
    return {
      name:   name,
      state:  STATES.UNBOUND,
      reason: "the listener is enabled and holds no port",
    };
  }

  function listenerTable() {
    var shape = listenerHandle.describe();
    var held  = shape.withheld || {};
    var rows  = Object.keys(shape.listeners).map(function (name) {
      if (shape.listeners[name].enabled !== true) {
        return {
          name:   name,
          state:  STATES.DISABLED,
          reason: "this configuration does not enable it",
        };
      }
      return listenerRow(name, shape.bound[name], held[name]);
    });
    if (webHandle === null) return rows;
    // The browser surface has no path that holds its port back: it is
    // the one listener whose absence a person notices immediately, and
    // it either took the port or the boot did not get this far.
    var webShape = webHandle.describe();
    rows.push(listenerRow("http", webShape.bound.http));
    if (webShape.httpsPort !== null) {
      rows.push(listenerRow("https", webShape.bound.https));
    }
    return rows;
  }

  webHandle = web.serve({
    agent:     agentHandle,
    store:     opts.store,
    // Both halves of the message layer, because the browser surface
    // needs both and they answer different questions. The adapter says
    // which folders an account owns, which is the only place that is
    // recorded; the store underneath is what the JMAP listener wants.
    mailbox:   opts.mailStore,
    mailStore: messageStore,
    compose:   composeHandle,
    dkim:      dkimHandle,
    delivery:  deliveryHandle,
    config:    config,
    listeners: listenerTable,
    certificateReport: certificateReading,
    address:   opts.httpAddress,
    tls:       webTls,
    // The same handle the mail listeners hold. The browser surface
    // cannot read a context through an accessor the way they do, so it
    // takes the other half of the arrangement: it is told when the two
    // files changed, and hands the running TLS server the new material.
    // One reload therefore moves every port that can move.
    certificate: certificate,
  });

  // After the browser surface exists, so the reload has something to ask
  // and so the port that can now take a renewal has already registered
  // for one. Only the watched form reaches here: a caller that built its
  // own context named no path for a renewal to be written to.
  if (tlsHandle !== null) _reportRotations(tlsHandle, config, vault, staleAfterRotation);

  // ---- anchoring the trail while this server runs ----
  //
  // See DEFAULT_AUDIT_ANCHOR_MS for what this is defending and why the
  // interval is the number it is.
  var anchorTimer    = null;
  var anchorInFlight = null;
  var anchoredCounter = null;
  var anchoredAt      = null;
  var anchorFailures  = 0;

  // Write the trail down and anchor it where it now ends.
  //
  // The flush first, because a row that has not left the buffer is not in
  // the chain and an anchor taken over the chain without it names an
  // older tip. `skipIfUnchanged` is what makes a quiet server free: the
  // tip has not moved, so nothing is signed and nothing is stored.
  //
  // Never throws. This is a hot path observability sink in the shape §8
  // describes: it runs on a timer beside deliveries in flight, and a
  // volume that would not take the anchor is not a reason to lose the
  // message that happened to be arriving. Drop-silent by design, with the
  // failure recorded where an operator watching the trail can see it and
  // a count on the handle for anything reading the shape.
  async function _anchorTrail() {
    try {
      await b.audit.flush();
      var anchored = await b.audit.checkpoint({ skipIfUnchanged: true });
      if (anchored) {
        anchoredCounter = Number(anchored.atMonotonicCounter);
        anchoredAt      = Date.now();
      }
    } catch (err) {
      anchorFailures += 1;
      try {
        b.audit.safeEmit({
          action:   "blamepost.audit.anchor_failed",
          outcome:  "failure",
          metadata: { error: (err && err.message) || String(err) },
        });
      } catch (_e) { /* drop-silent by design */ }
    }
  }

  // One pass at a time, and a handle on the pass that is running.
  //
  // The framework's repeating timer is fixed rate and its stop does not
  // wait for a tick already in flight, so both halves of this matter. A
  // pass that outlasts its interval must not have a second one started
  // over it, and `stop` has to be able to WAIT for the one that is
  // running: a checkpoint still going when the store closes resumes
  // against a database that is gone, and one still going when the
  // shutdown writes its own final anchor races it for the same tip.
  function _anchorPass() {
    if (anchorInFlight !== null) return anchorInFlight;
    anchorInFlight = _anchorTrail().then(function () { anchorInFlight = null; });
    return anchorInFlight;
  }

  // Disarm, then wait for whatever was already running. In that order:
  // clearing the timer first means the pass being waited for is the last
  // one there will be.
  function _stopAnchoring() {
    if (anchorTimer !== null) {
      anchorTimer.stop();
      anchorTimer = null;
    }
    return anchorInFlight === null ? Promise.resolve() : anchorInFlight;
  }

  // A start that throws leaves nothing armed. The outbound sweep timer
  // is the piece that would otherwise survive: it goes up before
  // anything binds, and the command line answers a failed start by
  // closing the store, so a sweep firing afterwards would read a store
  // that is no longer there. Each step therefore unwinds the steps
  // before it on the way out. The anchoring is armed last for the same
  // reason from the other end: nothing after it can refuse, so it needs
  // no unwind and can never fire against a half assembled server.
  async function start() {
    // Before anything else, and before anything binds. A posture that is
    // wrong is wrong for the whole process, so finding out after the MX
    // port is open means mail has already arrived under guarantees this
    // deployment does not hold. The refusal names every predicate that
    // failed rather than the first, so one restart carries the whole
    // list.
    await b.security.assertProduction(productionPosture(config));
    deliveryHandle.start();
    var listening;
    try {
      listening = await listenerHandle.start();
    } catch (err) {
      deliveryHandle.stop();
      throw err;
    }
    // The browser surface goes up last and comes down first. It is the
    // only listener whose absence a person notices immediately, and the
    // last thing to bind is the honest place to report that everything
    // before it did.
    try {
      await webHandle.start();
    } catch (err) {
      await listenerHandle.stop({ timeoutMs: TIME.seconds(5) });
      deliveryHandle.stop();
      throw err;
    }
    anchorTimer = b.safeAsync.repeating(_anchorPass, auditAnchorMs, {
      unref: true,
      name:  "blamepost-audit-anchor",
      onError: function (err) {
        // Unreachable while `_anchorTrail` catches its own, and here
        // regardless: a rejection escaping a repeating timer that nobody
        // caught is an unhandled rejection, which ends the process. The
        // one thing this path may never do is take the server down.
        try {
          b.audit.safeEmit({
            action:   "blamepost.audit.anchor_failed",
            outcome:  "failure",
            metadata: { error: (err && err.message) || String(err) },
          });
        } catch (_e) { /* drop-silent by design */ }
      },
    });
    return listening;
  }

  async function stop(stopOpts) {
    stopOpts = stopOpts || {};
    var timeoutMs = stopOpts.timeoutMs === undefined ? DEFAULT_STOP_MS : stopOpts.timeoutMs;
    // Before anything else, and awaited. The command line's shutdown runs
    // this, then anchors the trail itself, then closes the store, and a
    // pass still running underneath either of those is the race this
    // ordering removes rather than narrows.
    await _stopAnchoring();
    deliveryHandle.stop();
    var webClosed = await webHandle.stop({ timeoutMs: timeoutMs });
    var drained = await listenerHandle.stop({ timeoutMs: timeoutMs });
    if (tlsHandle && typeof tlsHandle.stop === "function") tlsHandle.stop();
    return { closed: webClosed.closed.concat(drained.closed) };
  }

  function describe() {
    return {
      version:   pkg.version,
      hostname:  config.hostname,
      dataDir:   config.dataDir,
      listeners: listenerHandle.describe(),
      web:       webHandle.describe(),
      outbound:  deliveryHandle.describe(),
      dkim:      dkimHandle.describe(),
      // How much of the trail is currently outside the record beside the
      // volume, which is the question an operator asks after a crash.
      // `anchoredCounter` is the last counter this process anchored and
      // is null until the first pass has rows to cover, so a reader can
      // tell a server that has anchored from one that has not yet had
      // anything to anchor. `failures` above zero says the anchoring is
      // being attempted and refused, and that is the reading that matters
      // most: it is otherwise silent by design.
      audit: {
        anchorIntervalMs: auditAnchorMs,
        anchoring:        anchorTimer !== null,
        anchoredCounter:  anchoredCounter,
        anchoredAt:       anchoredAt,
        failures:         anchorFailures,
      },
      // Which files the certificate came from, whether anything is
      // watching them, and which ports a renewal written to them will
      // not reach until this process restarts. An operator planning a
      // renewal is asking exactly that, and the answer is otherwise
      // spread across a configuration file and a framework's internals.
      certificate: {
        certFile: certificate.certFile === undefined ? config.tlsCert : certificate.certFile,
        keyFile:  certificate.keyFile === undefined ? config.tlsKey : certificate.keyFile,
        watched:  tlsHandle !== null,
        staleAfterRotation: staleAfterRotation(),
      },
    };
  }

  return {
    start:    start,
    stop:     stop,
    describe: describe,
    config:   config,
    web:      webHandle,
    mail: {
      listeners: listenerHandle,
      delivery:  deliveryHandle,
      dkim:      dkimHandle,
      compose:   composeHandle,
      posture:   postureHandle,
      agent:     agentHandle,
    },
  };
}

module.exports = {
  version:          pkg.version,
  frameworkVersion: b.version,
  create:           create,
  productionPosture: productionPosture,
  resolver:         resolver,
  tlsContext:       tlsContext,
  certificateReport: certificateReport,
  web:              web,
  mail: {
    listeners: listeners,
    delivery:  delivery,
    dkim:      dkim,
    compose:   compose,
    posture:   posture,
  },
};
