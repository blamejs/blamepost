// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * dns-untrusted-input: the write gate against input this server did not
 * write.
 *
 * Four kinds of input reach the gate from outside it: the provider's
 * responses, the change set a caller hands back to `apply`, the sealed
 * value that stands in for the credential, and the configuration that
 * names the endpoint. Each case drives one of them in a hostile shape
 * through the call the administration console or the command line makes,
 * and reads the outcome off what the stand-in provider received.
 *
 * The stand-in is the one in `test/helpers/dns-provider.js`, bound on
 * loopback and speaking TLS. It records every request, so a case that
 * asserts nothing was written measures the requests rather than trusting
 * a return value.
 *
 * Every case runs even when an earlier one fails, and each failure is
 * printed as it happens, so one run reports the whole set.
 *
 * Run standalone: node test/layer-2-integration/dns-untrusted-input.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers      = require("../helpers");
var cliHelper    = require("../helpers/cli");
var dnsZone      = require("../helpers/dns-zone");
var standIn      = require("../helpers/dns-provider");
var b            = require("../../lib/vendor/blamejs");
var dns          = require("../../lib/dns");
var provider     = require("../../lib/dns/cloudflare");
var configModule = require("../../lib/config");

var count = helpers.count;

var DOMAIN       = standIn.DOMAIN;
var ZONE         = standIn.ZONE_ID;
var OTHER_DOMAIN = "other-zone.example";

var HOSTNAME         = "mx." + DOMAIN;
var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// A credential shaped like the provider's. It is a fixture and never
// leaves this process except to the stand-in.
var TOKEN = "fixtureDnsTokenZ8bC3dF6gH1jL5nS0aE2uT9iO";

// Display controls a stored record value can carry. Built rather than
// typed, so this file holds none of the bytes it tests for.
var RIGHT_TO_LEFT_OVERRIDE      = String.fromCharCode(0x202e);
var CONTROL_SEQUENCE_INTRODUCER = String.fromCharCode(0x9b);

// A provider identifier of the width the stand-in uses, built from a
// readable prefix.
function idFor(prefix) {
  var id = prefix;
  while (id.length < 32) id += "0";
  return id;
}

var OTHER_ZONE = idFor("otherzone");

var sealedToken = null;

// ---- small readers ----------------------------------------------------------

// The outcome of one call, as a value. A refusal is data a case asserts
// on, so it is caught here rather than thrown past the assertions.
async function settle(fn) {
  try {
    return { error: null, value: await fn() };
  } catch (e) {
    return { error: e, value: null };
  }
}

function settleSync(fn) {
  try {
    return { error: null, value: fn() };
  } catch (e) {
    return { error: e, value: null };
  }
}

function codeOf(outcome) {
  return outcome.error && typeof outcome.error.code === "string" ? outcome.error.code : null;
}

function describeOutcome(outcome) {
  if (outcome.error === null) return "returned without a refusal";
  return (codeOf(outcome) || "no code") + ": " + String(outcome.error.message).slice(0, 300);
}

function describeRequests(fake) {
  return fake.state.requests.map(function (r) { return r.method + " " + r.path; }).join(", ");
}

// The bare credential out of the authorization header a request carried,
// which is the form a provider quoting it back would use.
function bareToken(request) {
  var header = String(request.headers.authorization || "");
  return header.indexOf("Bearer ") === 0 ? header.slice("Bearer ".length) : header;
}

// Every display control in a string, as code points: C0 controls other
// than the line feed that separates diff lines, DEL, the C1 block a
// terminal acts on, the zero-width characters, the bidirectional
// embeddings, overrides and isolates, and the byte order mark. Ordinary
// text in any writing system is not one.
function displayControls(text) {
  var out = [];
  for (var i = 0; i < text.length; i += 1) {
    var code = text.charCodeAt(i);
    if (code === 0x0a) continue;
    var control = code < 0x20 || (code >= 0x7f && code <= 0x9f) ||
      (code >= 0x200b && code <= 0x200f) || (code >= 0x202a && code <= 0x202e) ||
      (code >= 0x2066 && code <= 0x2069) || code === 0x061c || code === 0xfeff;
    if (control) out.push("U+" + code.toString(16));
  }
  return out;
}

// A gate over one stand-in, built the way the configuration builds one
// apart from the certificate authority it trusts.
function gateOver(fake, extra) {
  extra = extra || {};
  var opts = {
    domain:        DOMAIN,
    sealedToken:   extra.sealedToken || sealedToken,
    vault:         b.vault,
    resolver:      dnsZone.pinnedResolverOver({}),
    clientOptions: {
      baseUrl:               fake.baseUrl,
      agent:                 fake.agent,
      allowInternalEndpoint: true,
      maxAttempts:           extra.maxAttempts || 2,
    },
  };
  Object.keys(extra).forEach(function (key) {
    if (key !== "maxAttempts" && key !== "sealedToken") opts[key] = extra[key];
  });
  return dns.create(opts);
}

function dmarc(content) {
  return { type: "TXT", name: "_dmarc." + DOMAIN, content: content };
}

function loadedConfig(root, dataDir, extra) {
  return configModule.load({
    env: Object.assign({
      BLAMEPOST_HOSTNAME:         HOSTNAME,
      BLAMEPOST_DATA_DIR:         dataDir,
      BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
    }, extra || {}),
    cwd: root,
  });
}

// ---- an edited change set ----------------------------------------------------

// The zone every edited set is applied against. The apex carries an
// address record and a verification record nobody here wrote, beside the
// sender policy, and the DMARC address carries the record a real preview
// proposes to replace.
function tamperZone() {
  return [
    { id: idFor("apexaddress"), type: "A", name: DOMAIN, content: "203.0.113.7", ttl: 300 },
    { id: idFor("apexverify"), type: "TXT", name: DOMAIN,
      content: "some-vendor-site-verification=abc123", ttl: 300 },
    { id: idFor("apexpolicy"), type: "TXT", name: DOMAIN, content: "v=spf1 -all", ttl: 300 },
    { id: idFor("dmarcnow"), type: "TXT", name: "_dmarc." + DOMAIN,
      content: "v=DMARC1; p=none", ttl: 300 },
  ];
}

// A real preview, edited, and handed to apply. Each edit gets a zone of its
// own, so one that got through cannot change what the next one meets.
async function applyEdited(desired, edit) {
  var fake = await standIn.start({
    records: tamperZone(),
    zones:   [{ id: ZONE, name: DOMAIN }, { id: OTHER_ZONE, name: OTHER_DOMAIN }],
  });
  var gate = gateOver(fake);
  try {
    var real = await gate.preview({ desired: desired, reason: "compute a change", prune: true });
    var outcome = await settle(function () {
      return gate.apply(edit(real), { reason: "apply an edited change set", confirm: true });
    });
    return { outcome: outcome, fake: fake };
  } finally {
    gate.close();
    fake.close();
  }
}

function recordNamed(fake, id) {
  return fake.state.records.filter(function (r) { return r.id === id; })[0] || null;
}

async function anEditedChangeSetWritesNothingApplyDidNotReadItself() {
  var PUBLISH = [dmarc("v=DMARC1; p=reject")];

  function replacing(after) {
    return function (real) {
      var change = Object.assign({}, real.changes[0], { after: after });
      return Object.assign({}, real, { changes: [change] });
    };
  }

  var mx = await applyEdited(PUBLISH, replacing(
    { type: "MX", name: DOMAIN, content: "mx.elsewhere.example", ttl: null, priority: 10 }));
  count("an edited replacement whose record is an MX at the apex is refused",
    mx.outcome.error !== null, describeOutcome(mx.outcome));
  count("and no MX record reached the provider while MX writes are off",
    mx.fake.writes().length === 0 &&
    !mx.fake.state.records.some(function (r) { return r.type === "MX"; }),
    describeRequests(mx.fake));

  var address = await applyEdited(PUBLISH, replacing(
    { type: "A", name: "www." + DOMAIN, content: "203.0.113.9", ttl: null }));
  count("an edited replacement whose record is an address record elsewhere is refused",
    address.outcome.error !== null && address.fake.writes().length === 0,
    describeOutcome(address.outcome) + " / " + describeRequests(address.fake));

  var retargeted = await applyEdited(PUBLISH, function (real) {
    var change = Object.assign({}, real.changes[0], { recordId: idFor("apexaddress") });
    return Object.assign({}, real, { changes: [change] });
  });
  count("a replacement aimed at a record the change set does not name is refused",
    retargeted.outcome.error !== null && retargeted.fake.writes().length === 0,
    describeOutcome(retargeted.outcome) + " / " + describeRequests(retargeted.fake));
  var apexAfter = recordNamed(retargeted.fake, idFor("apexaddress"));
  count("and the apex address record is still the address record it was",
    apexAfter !== null && apexAfter.type === "A" && apexAfter.content === "203.0.113.7",
    JSON.stringify(apexAfter));

  var removal = await applyEdited(PUBLISH, function (real) {
    return Object.assign({}, real, { changes: [{
      action: "delete", type: "TXT", name: "_dmarc." + DOMAIN,
      before: real.changes[0].before, after: null, recordId: idFor("apexaddress"),
    }] });
  });
  count("a removal aimed at the apex address record through a DMARC change is refused",
    removal.outcome.error !== null && removal.fake.writes().length === 0 &&
    recordNamed(removal.fake, idFor("apexaddress")) !== null,
    describeOutcome(removal.outcome) + " / " + describeRequests(removal.fake));

  var moved = await applyEdited(PUBLISH, function (real) {
    return Object.assign({}, real, { zone: OTHER_ZONE });
  });
  count("a change set moved onto another zone the credential reaches is refused",
    moved.outcome.error !== null, describeOutcome(moved.outcome));
  count("and nothing was sent to that zone",
    !moved.fake.state.requests.some(function (r) {
      return r.method !== "GET" && r.path.indexOf(OTHER_ZONE) !== -1;
    }), describeRequests(moved.fake));

  var unknownAction = await applyEdited(PUBLISH, function (real) {
    var change = Object.assign({}, real.changes[0], { action: "purge" });
    return Object.assign({}, real, { changes: [change] });
  });
  count("a change carrying an action this gate does not perform is refused rather than read " +
    "as a removal", unknownAction.outcome.error !== null &&
    unknownAction.fake.writes().length === 0,
    describeOutcome(unknownAction.outcome) + " / " + describeRequests(unknownAction.fake));

  var unread = await applyEdited(PUBLISH, function (real) {
    return Object.assign({}, real, { changes: [{
      action: "create", type: "TXT", name: "_mta-sts." + DOMAIN, before: null,
      after: { type: "TXT", name: "_mta-sts." + DOMAIN, content: "v=STSv1; id=20260917",
        ttl: null },
      recordId: null,
    }] });
  });
  count("a write at an address the preview never read is refused",
    unread.outcome.error !== null && unread.fake.writes().length === 0,
    describeOutcome(unread.outcome) + " / " + describeRequests(unread.fake));

  // A preview that did read the apex, edited to remove the verification
  // record sitting there beside the sender policy.
  var verification = await applyEdited([{ type: "TXT", name: DOMAIN, content: "v=spf1 -all" }],
    function (real) {
      return Object.assign({}, real, { changes: [{
        action: "delete", type: "TXT", name: DOMAIN,
        before: { content: "v=spf1 -all" }, after: null, recordId: idFor("apexverify"),
      }] });
    });
  count("a removal of the verification record at the apex, written as a sender policy change, " +
    "is refused",
    verification.outcome.error !== null && verification.fake.writes().length === 0 &&
    recordNamed(verification.fake, idFor("apexverify")) !== null,
    describeOutcome(verification.outcome) + " / " + describeRequests(verification.fake));
}

// ---- identifiers the provider supplies ---------------------------------------

async function anIdentifierFromTheProviderIsNeverAPathSegment() {
  var RECORD_PATH = new RegExp("^/client/v4/(?:zones|zones/" + ZONE +
    "/dns_records(?:/[A-Za-z0-9]+)?)$");

  var shapes = [
    { label: "an identifier of two dots", id: ".." },
    { label: "an identifier of one dot", id: "." },
    { label: "an identifier carrying separators", id: "x/../../zones" },
  ];
  for (var i = 0; i < shapes.length; i += 1) {
    var fake = await standIn.start({ records: [
      { id: idFor("dmarcnow"), type: "TXT", name: "_dmarc." + DOMAIN,
        content: "v=DMARC1; p=none", ttl: 300 },
      { id: shapes[i].id, type: "TXT", name: "_dmarc." + DOMAIN,
        content: "v=DMARC1; p=quarantine", ttl: 300 },
    ] });
    var gate = gateOver(fake);
    try {
      var previewed = await settle(function () {
        return gate.preview({ desired: [dmarc("v=DMARC1; p=reject")],
          reason: "publish the DMARC policy", prune: true });
      });
      if (previewed.error === null) {
        await settle(function () {
          return gate.apply(previewed.value,
            { reason: "publish the DMARC policy", confirm: true });
        });
      }
      var stray = fake.state.requests.filter(function (r) { return !RECORD_PATH.test(r.path); });
      count("a record listing carrying " + shapes[i].label + " sends no request anywhere but " +
        "a record path", stray.length === 0, describeRequests(fake));
      count("and the listing is refused as a malformed response",
        codeOf(previewed) === provider.CODES.malformedResponse, describeOutcome(previewed));
    } finally {
      gate.close();
      fake.close();
    }
  }

  var zoneFake = await standIn.start({ zones: [{ id: "..", name: DOMAIN }] });
  var zoneGate = gateOver(zoneFake);
  try {
    var zoned = await settle(function () {
      return zoneGate.preview({ desired: [dmarc("v=DMARC1; p=reject")],
        reason: "publish the DMARC policy", prune: true });
    });
    count("a zone listing whose identifier is two dots sends nothing past the zone listing",
      zoneFake.state.requests.every(function (r) { return r.path === "/client/v4/zones"; }),
      describeRequests(zoneFake));
    count("and it is refused as a malformed response",
      codeOf(zoned) === provider.CODES.malformedResponse, describeOutcome(zoned));
  } finally {
    zoneGate.close();
    zoneFake.close();
  }
}

// ---- the credential quoted back ------------------------------------------------

async function aCredentialTheProviderQuotesBackReachesNoMessage() {
  var fake = await standIn.start();
  var gate = gateOver(fake, { maxAttempts: 1 });
  try {
    fake.state.onRequest = function (request) {
      return { status: 401, body: standIn.fail(10000, "Invalid API Token " + bareToken(request) +
        RIGHT_TO_LEFT_OVERRIDE + "nekot" + CONTROL_SEQUENCE_INTRODUCER + "2J" +
        "\r\nblamepost zone: the token is active") };
    };
    var read = await settle(function () {
      return gate.preview({ desired: [dmarc("v=DMARC1; p=reject")], reason: "read the zone" });
    });
    count("a read refusal quoting the credential is still a refusal",
      read.error !== null, describeOutcome(read));
    count("and the credential is not in the message an operator reads",
      read.error !== null && String(read.error.message).indexOf(TOKEN) === -1 &&
      String(read.error.stack).indexOf(TOKEN) === -1, describeOutcome(read));
    count("and neither is a display control the provider wrote into its refusal",
      read.error !== null && displayControls(String(read.error.message)).length === 0,
      displayControls(String(read.error && read.error.message)).join(" "));
    count("nor a line break that would start a line of its own in a transcript",
      read.error !== null && !/[\r\n]/.test(String(read.error.message)),
      JSON.stringify(String(read.error && read.error.message)).slice(0, 300));

    fake.state.onRequest = function (request) {
      return { status: 401, body: standIn.fail(10000,
        new Array(292).join("x") + " " + bareToken(request)) };
    };
    var cut = await settle(function () {
      return gate.preview({ desired: [dmarc("v=DMARC1; p=reject")], reason: "read the zone" });
    });
    count("a credential quoted where the message is cut short leaves no part of itself",
      cut.error !== null && String(cut.error.message).indexOf(TOKEN.slice(0, 8)) === -1,
      describeOutcome(cut));

    fake.state.onRequest = null;
    var previewed = await gate.preview({ desired: [dmarc("v=DMARC1; p=reject")],
      reason: "publish the DMARC policy" });
    fake.state.onRequest = function (request) {
      if (request.method === "GET") return null;
      return { status: 403, body: standIn.fail(9109,
        "token " + bareToken(request) + " cannot edit this zone") };
    };
    var written = await settle(function () {
      return gate.apply(previewed, { reason: "publish the DMARC policy", confirm: true });
    });
    count("a write refusal quoting the credential is reported without it",
      written.error !== null && String(written.error.message).indexOf(TOKEN) === -1,
      describeOutcome(written));
  } finally {
    gate.close();
    fake.close();
  }

  var statusFake = await standIn.start();
  var client = provider.create({
    readToken:             function () { return TOKEN; },
    baseUrl:               statusFake.baseUrl,
    agent:                 statusFake.agent,
    allowInternalEndpoint: true,
    maxAttempts:           1,
  });
  try {
    statusFake.state.onRequest = function (request) {
      return { status: 200, body: standIn.ok({ id: "tok0000",
        status: "disabled " + bareToken(request) }) };
    };
    var verified = await settle(function () { return client.verifyToken(); });
    count("a verification status quoting the credential is reported without it",
      verified.error !== null && String(verified.error.message).indexOf(TOKEN) === -1,
      describeOutcome(verified));
  } finally {
    client.close();
    statusFake.close();
  }
}

// ---- an envelope that contradicts itself ------------------------------------------

async function anEnvelopeThatContradictsItselfIsNotReadAsSuccess() {
  var fake = await standIn.start();
  var gate = gateOver(fake, { maxAttempts: 1 });
  try {
    fake.state.onRequest = function (request) {
      if (request.path !== "/client/v4/zones") return null;
      return { status: 200, body: { success: true,
        errors: [{ code: 1000, message: "the listing is incomplete" }], messages: [],
        result: [{ id: ZONE, name: DOMAIN }] } };
    };
    var read = await settle(function () {
      return gate.preview({ desired: [dmarc("v=DMARC1; p=reject")], reason: "read the zone" });
    });
    count("a read answering success while carrying errors is refused as malformed",
      codeOf(read) === provider.CODES.malformedResponse, describeOutcome(read));

    fake.state.onRequest = null;
    var previewed = await gate.preview({ desired: [dmarc("v=DMARC1; p=reject")],
      reason: "publish the DMARC policy" });
    fake.state.onWrite = function () {
      return { status: 200, body: { success: true,
        errors: [{ code: 1000, message: "the record was not stored" }], messages: [],
        result: { id: idFor("contradicted"), type: "TXT", name: "_dmarc." + DOMAIN,
          content: "v=DMARC1; p=reject", ttl: 300 } } };
    };
    var written = await settle(function () {
      return gate.apply(previewed, { reason: "publish the DMARC policy", confirm: true });
    });
    count("a write answering success while carrying errors is not reported as performed",
      codeOf(written) === dns.CODES.writeIncomplete, describeOutcome(written));
  } finally {
    gate.close();
    fake.close();
  }
}

// ---- a write whose outcome is unknown ------------------------------------------------

async function aWriteWhoseOutcomeIsUnknownIsNotReportedAsUnwritten() {
  var fake = await standIn.start();
  var gate = gateOver(fake, { maxAttempts: 1 });
  try {
    var previewed = await gate.preview({ desired: [dmarc("v=DMARC1; p=reject")],
      reason: "publish the DMARC policy" });
    fake.state.onWrite = function () {
      return { status: 200, body: standIn.ok({ type: "TXT" }) };
    };
    var unreadable = await settle(function () {
      return gate.apply(previewed, { reason: "publish the DMARC policy", confirm: true });
    });
    count("a write the provider accepted with an unreadable answer is reported as incomplete",
      codeOf(unreadable) === dns.CODES.writeIncomplete, describeOutcome(unreadable));
    count("and it does not say nothing was written, because the provider said it was",
      unreadable.error !== null &&
      String(unreadable.error.message).indexOf("Nothing was written") === -1,
      describeOutcome(unreadable));
    count("and a set that stopped at its first change does not say the zone holds part of it",
      unreadable.error !== null &&
      String(unreadable.error.message).indexOf("holds part of") === -1,
      describeOutcome(unreadable));

    fake.state.onWrite = null;
    fake.state.failWrites = 99;
    var failing = await settle(function () {
      return gate.apply(previewed, { reason: "publish the DMARC policy", confirm: true });
    });
    count("a write the provider failed on is not reported as one that wrote nothing",
      failing.error !== null &&
      String(failing.error.message).indexOf("Nothing was written") === -1,
      describeOutcome(failing));

    fake.state.failWrites = 0;
    fake.state.onWrite = function () {
      return { status: 403, body: standIn.fail(9109, "Unauthorized to access requested resource") };
    };
    var refused = await settle(function () {
      return gate.apply(previewed, { reason: "publish the DMARC policy", confirm: true });
    });
    count("a write the provider refused outright still says nothing was written",
      refused.error !== null &&
      String(refused.error.message).indexOf("Nothing was written") !== -1,
      describeOutcome(refused));
  } finally {
    gate.close();
    fake.close();
  }
}

// ---- the endpoint, at assembly ---------------------------------------------------------

async function anEndpointOnAnInternalAddressIsRefusedWhenTheServerIsAssembled(root) {
  var base    = nodePath.join(root, "endpoint");
  var dataDir = nodePath.join(base, "data");
  var workDir = nodePath.join(base, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  await dns.storeToken(loadedConfig(base, dataDir, { BLAMEPOST_ZONE_PROVIDER: "cloudflare" }),
    TOKEN, { vault: b.vault });

  function assemble(extra) {
    return settleSync(function () {
      var cfg = loadedConfig(base, dataDir,
        Object.assign({ BLAMEPOST_ZONE_PROVIDER: "cloudflare" }, extra));
      var handle = dns.fromConfig(cfg, { vault: b.vault });
      handle.close();
      return handle;
    });
  }

  var refused = [
    { label: "a cloud metadata address, with the internal permission set",
      env: { BLAMEPOST_ZONE_ENDPOINT: "https://169.254.169.254/client/v4",
        BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT: "1" } },
    { label: "a cloud metadata address written as a mapped IPv6 literal",
      env: { BLAMEPOST_ZONE_ENDPOINT: "https://[::ffff:169.254.169.254]/client/v4",
        BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT: "1" } },
    { label: "a private address without the internal permission",
      env: { BLAMEPOST_ZONE_ENDPOINT: "https://10.20.30.40/client/v4" } },
    { label: "a loopback IPv6 literal without the internal permission",
      env: { BLAMEPOST_ZONE_ENDPOINT: "https://[::1]:8443/client/v4" } },
    { label: "the loopback name without the internal permission",
      env: { BLAMEPOST_ZONE_ENDPOINT: "https://localhost:8443/client/v4" } },
  ];
  refused.forEach(function (entry) {
    var outcome = assemble(entry.env);
    count("an endpoint at " + entry.label + " is refused while the writer is assembled",
      outcome.error !== null, describeOutcome(outcome));
  });

  var permitted = assemble({ BLAMEPOST_ZONE_ENDPOINT: "https://10.20.30.40/client/v4",
    BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT: "1" });
  count("a private address with the internal permission set is assembled",
    permitted.error === null, describeOutcome(permitted));
  var publicApi = assemble({});
  count("and so is the provider's public API", publicApi.error === null,
    describeOutcome(publicApi));

  var run = cliHelper.create({
    dataDir: dataDir, workDir: workDir, hostname: HOSTNAME, vaultPassphrase: VAULT_PASSPHRASE,
    env: {
      BLAMEPOST_ZONE_PROVIDER:                "cloudflare",
      BLAMEPOST_ZONE_ENDPOINT:                "https://169.254.169.254/client/v4",
      BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT: "1",
    },
  });
  var said = run(["zone", "allowlist", DOMAIN]);
  count("`zone allowlist` refuses a writer pointed at a cloud metadata address",
    said.status !== 0 && said.both.indexOf("169.254.169.254") !== -1,
    "exit " + said.status + " " + said.both.slice(0, 300));
}

// ---- what a preview renders ---------------------------------------------------------------

async function theDiffShowsAStoredValueAsVisibleText() {
  var fake = await standIn.start({ records: [
    { id: idFor("dmarcnow"), type: "TXT", name: "_dmarc." + DOMAIN,
      content: "v=DMARC1; p=none; rua=mailto:x@" + RIGHT_TO_LEFT_OVERRIDE + "moc.elpmaxe" +
        CONTROL_SEQUENCE_INTRODUCER + "2J",
      ttl: 300 },
  ] });
  var gate = gateOver(fake);
  try {
    var previewed = await gate.preview({ desired: [dmarc("v=DMARC1; p=reject")],
      reason: "publish the DMARC policy" });
    count("the preview proposes replacing the stored value",
      previewed.changes.length === 1 && previewed.changes[0].action === "update", previewed.diff);
    var hidden = displayControls(previewed.diff);
    count("and the diff carries no display control", hidden.length === 0, hidden.join(" "));
    count("while the stored value is still readable in it",
      previewed.diff.indexOf("moc.elpmaxe") !== -1, previewed.diff);
  } finally {
    gate.close();
    fake.close();
  }
}

// ---- a sealed value that is not the credential ------------------------------------------

async function aValueSealedForSomethingElseIsNotACredential() {
  var OTHER_SECRET = "a-single-line-value-sealed-for-another-purpose";
  var fake = await standIn.start();
  try {
    var built = settleSync(function () {
      return gateOver(fake, { sealedToken: b.vault.seal(OTHER_SECRET), maxAttempts: 1 });
    });
    if (built.error === null) {
      await settle(function () {
        return built.value.preview({ desired: [dmarc("v=DMARC1; p=reject")],
          reason: "read the zone" });
      });
      built.value.close();
    }
    count("a value sealed for another purpose is never sent as the credential",
      !fake.state.requests.some(function (r) {
        return String(r.headers.authorization || "").indexOf(OTHER_SECRET) !== -1;
      }), describeRequests(fake));
    count("and the gate refuses it before any request is built",
      built.error !== null && fake.state.requests.length === 0,
      describeOutcome(built) + " / " + describeRequests(fake));
  } finally {
    fake.close();
  }
}

async function aTokenThatCannotAuthenticateIsNotStored(root) {
  var base    = nodePath.join(root, "token-shape");
  var dataDir = nodePath.join(base, "data");
  var workDir = nodePath.join(base, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });
  var run = cliHelper.create({
    dataDir: dataDir, workDir: workDir, hostname: HOSTNAME, vaultPassphrase: VAULT_PASSPHRASE,
  });
  var sealedAt = nodePath.join(dataDir, "keys", "zone-token.sealed");

  var shapes = [
    { label: "a value with a space in it", body: "two words\n" },
    { label: "a value spread over two lines", body: "first-line\nsecond-line\n" },
  ];
  shapes.forEach(function (shape, index) {
    var file = nodePath.join(base, "token-" + index);
    nodeFs.writeFileSync(file, shape.body, "utf8");
    var said = run(["zone", "token", "set", "--token-file", file,
      "--reason", "installing the provider credential"]);
    count("`zone token set` refuses " + shape.label + " as the provider token",
      said.status !== 0, "exit " + said.status + " " + said.both.slice(0, 300));
    count("and nothing is sealed onto the volume for it", !nodeFs.existsSync(sealedAt),
      sealedAt);
  });
}

// ---- what an address is for ----------------------------------------------------------------

async function anAddressAdmitsOnlyTheRecordItIsFor() {
  var verify = { id: idFor("apexverify"), type: "TXT", name: DOMAIN,
    content: "some-vendor-site-verification=abc123", ttl: 300 };

  var lone = await standIn.start({ records: [Object.assign({}, verify)] });
  var loneGate = gateOver(lone);
  try {
    var first = await loneGate.preview({
      desired: [{ type: "TXT", name: DOMAIN, content: "v=spf1 -all" }],
      reason:  "publish the sender policy",
    });
    count("a sender policy at an apex holding only a verification record is a create",
      first.changes.length === 1 && first.changes[0].action === "create", first.diff);
    await settle(function () {
      return loneGate.apply(first, { reason: "publish the sender policy", confirm: true });
    });
    count("and the verification record is still there afterwards",
      recordNamed(lone, idFor("apexverify")) !== null &&
      recordNamed(lone, idFor("apexverify")).content === verify.content,
      JSON.stringify(lone.state.records));
  } finally {
    loneGate.close();
    lone.close();
  }

  var crowded = await standIn.start({ records: [
    Object.assign({}, verify),
    { id: idFor("spfold"), type: "TXT", name: DOMAIN,
      content: "v=spf1 include:old.example -all", ttl: 300 },
    { id: idFor("spfnew"), type: "TXT", name: DOMAIN, content: "v=spf1 -all", ttl: 300 },
  ] });
  var crowdedGate = gateOver(crowded);
  try {
    var pruned = await crowdedGate.preview({
      desired: [{ type: "TXT", name: DOMAIN, content: "v=spf1 -all" }],
      reason:  "reduce the apex to one sender policy",
      prune:   true,
    });
    var removals = pruned.changes.filter(function (c) { return c.action === "delete"; });
    count("pruning the apex removes the extra sender policy and nothing else",
      removals.length === 1 && removals[0].recordId === idFor("spfold"), pruned.diff);
  } finally {
    crowdedGate.close();
    crowded.close();
  }

  var empty = await standIn.start();
  var emptyGate = gateOver(empty);
  try {
    var offPurpose = [
      { label: "a verification record at the apex",
        record: { type: "TXT", name: DOMAIN, content: "another-vendor-verification=xyz" } },
      { label: "a record at the DMARC address that is not a DMARC policy",
        record: dmarc("another-vendor-verification=xyz") },
      { label: "a record at the MTA-STS address that is not a policy identifier",
        record: { type: "TXT", name: "_mta-sts." + DOMAIN, content: "hello" } },
      { label: "a record at the TLS reporting address that is not a reporting record",
        record: { type: "TXT", name: "_smtp._tls." + DOMAIN, content: "hello" } },
    ];
    for (var i = 0; i < offPurpose.length; i += 1) {
      var outcome = await settle((function (entry) {
        return function () {
          return emptyGate.preview({ desired: [entry.record], reason: "attempt " + entry.label });
        };
      })(offPurpose[i]));
      count(offPurpose[i].label + " is outside the allowlist",
        codeOf(outcome) === dns.CODES.writeNotAllowed, describeOutcome(outcome));
    }

    var onPurpose = await settle(function () {
      return emptyGate.preview({ desired: [
        { type: "TXT", name: "_mta-sts." + DOMAIN, content: "v=STSv1; id=20260917" },
        { type: "TXT", name: "_smtp._tls." + DOMAIN,
          content: "v=TLSRPTv1; rua=mailto:tls-reports@" + DOMAIN },
        { type: "TXT", name: DOMAIN, content: "v=spf1 -all" },
        dmarc("v=DMARC1; p=none"),
      ], reason: "publish the posture records" });
    });
    count("and each address still takes the record it is for",
      onPurpose.error === null && onPurpose.value.changes.length === 4,
      describeOutcome(onPurpose));
    count("with nothing written by previewing it", empty.writes().length === 0,
      describeRequests(empty));
  } finally {
    emptyGate.close();
    empty.close();
  }
}

// ---- the names an operator adds ---------------------------------------------------------------

async function anAddedNameIsHeldToTheTypesTheGateWrites() {
  var fake = await standIn.start();
  try {
    var address = settleSync(function () {
      return gateOver(fake, { additionalNames: [{ type: "A", name: "www." + DOMAIN }] });
    });
    count("an added name of a type the gate does not write is refused at construction",
      address.error instanceof TypeError,
      address.error === null ? JSON.stringify(address.value.allowlist().addresses)
        : describeOutcome(address));
    if (address.error === null) address.value.close();

    var exchanger = settleSync(function () {
      return gateOver(fake, { additionalNames: [{ type: "MX", name: "mail." + DOMAIN }] });
    });
    count("and so is an added MX name while MX writes are off",
      exchanger.error instanceof TypeError,
      exchanger.error === null ? JSON.stringify(exchanger.value.allowlist().addresses)
        : describeOutcome(exchanger));
    if (exchanger.error === null) exchanger.value.close();

    var note = settleSync(function () {
      return gateOver(fake, { additionalNames: [{ type: "TXT", name: "_note." + DOMAIN }] });
    });
    count("while an added name of a type the gate writes is accepted and listed",
      note.error === null && note.value.allowlist().addresses.some(function (entry) {
        return entry.type === "TXT" && /operator added/.test(entry.describes);
      }), describeOutcome(note));
    if (note.error === null) note.value.close();
  } finally {
    fake.close();
  }
}

// ---- runner --------------------------------------------------------------------------------------

var CASES = [
  anEditedChangeSetWritesNothingApplyDidNotReadItself,
  anIdentifierFromTheProviderIsNeverAPathSegment,
  aCredentialTheProviderQuotesBackReachesNoMessage,
  anEnvelopeThatContradictsItselfIsNotReadAsSuccess,
  aWriteWhoseOutcomeIsUnknownIsNotReportedAsUnwritten,
  anEndpointOnAnInternalAddressIsRefusedWhenTheServerIsAssembled,
  theDiffShowsAStoredValueAsVisibleText,
  aValueSealedForSomethingElseIsNotACredential,
  aTokenThatCannotAuthenticateIsNotStored,
  anAddressAdmitsOnlyTheRecordItIsFor,
  anAddedNameIsHeldToTheTypesTheGateWrites,
];

async function run() {
  var root    = helpers.tempDir("dns-untrusted-input");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });
  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;
  try {
    await b.vault.init({ dataDir: nodePath.join(root, "vault"), mode: "plaintext" });
    sealedToken = dns.sealToken(TOKEN, b.vault);

    var failed = [];
    for (var i = 0; i < CASES.length; i += 1) {
      try {
        await CASES[i](root);
      } catch (e) {
        failed.push(CASES[i].name);
        console.log("  FAIL in " + CASES[i].name + ": " + helpers.formatErr(e));
      }
    }
    if (failed.length > 0) {
      throw new Error(failed.length + " of " + CASES.length + " case(s) failed: " +
        failed.join(", "));
    }
    return helpers.getChecks();
  } finally {
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "dns-untrusted-input", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
