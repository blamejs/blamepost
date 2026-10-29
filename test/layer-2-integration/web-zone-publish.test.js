// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * web-zone-publish: publishing a DMARC record from the administration
 * console into the hosted zone.
 *
 * The write gate in `lib/dns` computes a change set and performs it, and
 * this is the surface an operator drives both halves from. So every
 * claim here is about the path a browser actually takes: a real session
 * over the version a browser negotiates, the rendered form, the
 * confirmation page, and the provider on the other side reporting what
 * it received.
 *
 * ## What is measured
 *
 *   - The record each policy level would be published as is on the page,
 *     and only the levels this server will publish carry a form.
 *   - Preparing writes nothing. The provider is asked to read and is
 *     never asked to write until the operator has confirmed against the
 *     diff that was shown.
 *   - The change set that is performed is the one that was displayed.
 *     Naming a different held set from the same form is refused, and a
 *     zone that moved under a prepared set stops the write rather than
 *     being overwritten by it.
 *   - A removal takes a record the change set already names and nothing
 *     else, and any set at all takes the operator typing the domain back.
 *   - A change set larger than the gate performs is refused before a
 *     write leaves.
 *   - After a write the record is read back at the provider and through a
 *     resolver. A resolver answering with something else and a resolver
 *     that has not answered yet are reported apart, because the first
 *     does not clear on its own and the second does.
 *   - Every publish leaves an audit row naming the operator, the domain
 *     and the reason they gave.
 *   - What the provider said an address is holding is screened before it
 *     is shown, so a value written to reorder or hide part of the line
 *     the operator confirms against cannot do either.
 *   - Every refusal is an RFC 9457 problem document under its own
 *     `urn:blamepost:problem:` type.
 *   - An account holding no operator role reaches none of it.
 *
 * The provider is the stand-in in `test/helpers/dns-provider.js`, bound
 * on loopback and speaking TLS, the same one the command-line run and
 * the gate's own file drive. It records every request, which is what
 * lets the cases that assert nothing was written measure that rather
 * than assume it.
 *
 * The credential is sealed through the running vault, so the sealed form
 * is what the configuration carries and what is opened per request.
 *
 * Run standalone: node test/layer-2-integration/web-zone-publish.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var browser   = require("../helpers/browser");
var certs     = require("../helpers/certs");
var dnsZone   = require("../helpers/dns-zone");
var standIn   = require("../helpers/dns-provider");
var wire      = require("../helpers/wire");
var b         = require("../../lib/vendor/blamejs");
var config    = require("../../lib/config");
var store     = require("../../lib/store");
var dns       = require("../../lib/dns");
var provider  = require("../../lib/dns/cloudflare");
var blamepost = require("../../lib");

var check = helpers.check;
var count = helpers.count;

var LOOPBACK = wire.LOOPBACK;

var HOSTNAME = "mx.example.com";

// Four hosted domains, one per state this file has to drive. Separate
// domains rather than one reused, because each case leaves the zone in a
// state the next would have to unpick, and a fixture that unpicks is a
// fixture whose later cases run against whatever the earlier ones left.
var SETTLED  = "example.com";      // a publish that removes a record and reads back clean
var STEPDOWN = "example.org";      // a step down whose read-back disagrees
var MOVED    = "example.net";      // a zone that moves under a prepared set
var CROWDED  = "crowded.example";  // an address holding more records than one set may carry
var HOSTILE  = "hostile.example";  // an address holding a value written to mislead a reader
var UNSEEN   = "unseen.example";   // a write no resolver has answered with yet

var VAULT_PASSPHRASE  = "a long enough vault passphrase for one test run";
var OPERATOR_ADDRESS  = "operator@" + SETTLED;
var OPERATOR_PASSWORD = "quiet lantern bicycle 4291";
var READER_ADDRESS    = "quillfeather@" + SETTLED;
var READER_PASSWORD   = "amber kettle rowboat 7715";

// A second administrator, for the question of who may perform a change set
// the first operator prepared.
var SECOND_OPERATOR_ADDRESS  = "deputy@" + SETTLED;
var SECOND_OPERATOR_PASSWORD = "copper meadow lantern 6630";

// A credential shaped like the provider's. It is a fixture and never
// leaves this process.
var TOKEN = "fixtureDnsTokenZ8bC3dF6gH1jL5nS0aE2uT9iO";

// Where this server collects aggregate reports. The stepper puts it in
// the `rua` tag of a record offered to a domain that publishes none, so
// it is named here rather than left to the default, which is built from
// the MX hostname and is not a domain this run hosts.
var POSTMASTER = "dmarc@" + SETTLED;

// What each domain's DMARC record says to the world. These are the
// authority for what the stepper reads and for what the read-back after
// a write compares against, so they are named here rather than derived
// from anything the console produced.
var SETTLED_SERVED  = "v=DMARC1; p=none; rua=mailto:dmarc@" + SETTLED;
var STEPDOWN_SERVED  = "v=DMARC1; p=quarantine; rua=mailto:dmarc@" + STEPDOWN;
var MOVED_SERVED     = "v=DMARC1; p=none; rua=mailto:dmarc@" + MOVED;
var CROWDED_SERVED   = "v=DMARC1; p=none; rua=mailto:dmarc@" + CROWDED;
var HOSTILE_SERVED   = "v=DMARC1; p=none; rua=mailto:dmarc@" + HOSTILE;

// A stored record value written to mislead whoever reads it off the
// confirmation page: a right-to-left override that reorders the line, a
// zero-width joiner that hides part of it, and a tag that would execute
// if the page rendered it raw. It reaches the page only as the value the
// address is HOLDING, which is the half that comes back from the
// provider rather than the half this server composed.
// The single-byte CSI, built rather than written. A C1 control cannot be
// carried through a source file: an editor writing this file replaces it
// with a space, so a literal here would assert nothing and pass.
var CSI = String.fromCharCode(0x9b);

var HOSTILE_STALE = "v=DMARC1; p=none; rua=mailto:HOSTILE-MARKER‮moc.elpmaxe@‍x" +
  CSI + "31m" + "<script>alert(1)</script>";

// What each provider zone is holding before anything is published. The
// settled domain holds two records at one address, which is a permanent
// error to every receiver that reads it and the case publishing has to
// reduce rather than add to.
var SETTLED_STALE = "v=DMARC1; p=none; rua=mailto:old@" + SETTLED;

// How many records the crowded address holds. One more than the ceiling
// the gate performs, so the change set it produces is one update and a
// removal for every extra.
var CROWDED_RECORDS = 26;

// The reason an operator types on the form. Asserted against the audit
// row afterwards, because a row with somebody else's sentence in it
// answers nothing about this act.
var PUBLISH_REASON = "receivers were reading two policy records for this domain";

// How long the server is given to come down. Nothing is connected to the
// listeners, so this is a ceiling rather than a wait.
var STOP_MS = 8000;

// ---------------------------------------------------------------------------
// Reading a rendered page
// ---------------------------------------------------------------------------

function flat(body) {
  return String(body).replace(/\s+/g, " ");
}

// The block of the page that belongs to one heading. A claim asserted
// against the whole page passes on a value that belongs somewhere else.
function sectionFrom(body, heading) {
  var text = String(body);
  var at = text.indexOf(">" + heading + "<");
  if (at === -1) return "";
  var end = text.indexOf("class=\"keycard\"", at);
  return end === -1 ? text.slice(at) : text.slice(at, end);
}

// The two hidden values the confirmation form carries: the name of the
// held change set and the digest of the diff it was rendered from.
function heldFrom(body) {
  var name   = /name="changeset" value="([^"]*)"/.exec(String(body));
  var digest = /name="diff" value="([^"]*)"/.exec(String(body));
  return {
    changeset: name === null ? "" : name[1],
    diff:      digest === null ? "" : digest[1],
  };
}

// A problem document, parsed. A response that is not one is reported as
// itself rather than as a missing field.
function problemFrom(answer) {
  var parsed;
  try { parsed = JSON.parse(answer.body); }
  catch (_e) {
    return { type: "", title: "", detail: "",
      raw: String(answer.body).replace(/\s+/g, " ").slice(0, 300) };
  }
  return {
    type:   typeof parsed.type === "string" ? parsed.type : "",
    title:  typeof parsed.title === "string" ? parsed.title : "",
    detail: typeof parsed.detail === "string" ? parsed.detail : "",
    raw:    JSON.stringify(parsed).slice(0, 300),
  };
}

function isProblemDocument(answer) {
  var kind = String(answer.headers["content-type"] || "");
  return kind.indexOf("application/problem+json") !== -1;
}

// Every write the provider has taken so far, so a case can measure the
// difference across one act rather than the total.
function writeCount(fake) {
  return fake.writes().length;
}

// What the provider is holding at one address right now.
function heldAt(fake, name) {
  return fake.state.records
    .filter(function (row) { return row.name === name && row.type === "TXT"; })
    .map(function (row) { return row.content; });
}

// ---------------------------------------------------------------------------
// The cases
// ---------------------------------------------------------------------------

async function testThePageOffersTheRecordForEachLevel(operator) {
  var page = await operator.get("/admin/dmarc?domain=" + encodeURIComponent(SETTLED));
  count("the DMARC page narrowed to one domain answers to a signed-in operator",
    page.status === 200, String(page.status));
  if (page.status !== 200) return;

  var card = sectionFrom(page.body, "Policy");
  count("the page carries a policy block for the domain it was narrowed to",
    card.length > 0, flat(page.body).slice(0, 600));

  count("the record the weakest level would be published as is on the page",
    card.indexOf(SETTLED_SERVED) !== -1, flat(card).slice(0, 900));
  count("and so is the record the next level up would be published as, so an operator " +
    "reads what a step would publish before deciding to take it",
    card.indexOf("v=DMARC1; p=quarantine; rua=mailto:dmarc@" + SETTLED) !== -1,
    flat(card).slice(0, 900));

  count("the level the domain publishes today is marked as the one in force",
    /p=none<span class="pill">published<\/span>/.test(card.replace(/\s+/g, "")) ||
    card.indexOf("publishing p=none") !== -1,
    flat(card).slice(0, 600));

  // A step up is what the evidence rules exist for, and this domain has
  // no reports at all. Offering the form anyway would put the stepper
  // beside a button that ignores it.
  count("a level the evidence does not carry has no form beside it",
    card.indexOf("not offered") !== -1, flat(card).slice(0, 1200));

  var forms = card.match(/name="action" value="zone-prepare"/g) || [];
  count("exactly one level is offered, the one already in force, so nothing on this page " +
    "publishes a policy the evidence has not answered for",
    forms.length === 1, String(forms.length) + " prepare form(s)");
}

async function testPreparingReadsTheZoneAndWritesNothing(operator, fake) {
  var before = writeCount(fake);
  var answer = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: SETTLED,
    level:  "none",
    reason: PUBLISH_REASON,
  });
  count("preparing a record answers with the confirmation page",
    answer.status === 200, answer.status + " " + flat(answer.body).slice(0, 300));
  if (answer.status !== 200) return null;

  count("the confirmation page names the domain and the level being published",
    answer.body.indexOf("Publish p=none for " + SETTLED) !== -1,
    flat(answer.body).slice(0, 400));

  count("the change set is shown line by line rather than as a count, so the operator " +
    "confirms against what will happen",
    answer.body.indexOf("TXT _dmarc." + SETTLED) !== -1 &&
    answer.body.indexOf("replace ") !== -1 &&
    answer.body.indexOf("remove ") !== -1,
    flat(answer.body).slice(0, 1200));

  count("the record about to be published is in the change set",
    answer.body.indexOf(SETTLED_SERVED) !== -1, flat(answer.body).slice(0, 1200));
  count("and so is the record about to be removed",
    answer.body.indexOf(SETTLED_STALE) !== -1, flat(answer.body).slice(0, 1200));

  count("the page asks the operator to type the domain back rather than to press again",
    answer.body.indexOf("Type the domain to confirm") !== -1,
    flat(answer.body).slice(0, 800));

  check("preparing wrote nothing at the provider", writeCount(fake) === before);

  var held = heldFrom(answer.body);
  count("the form carries the name of the held change set and a digest of the diff it " +
    "was rendered from",
    held.changeset.length > 0 && held.diff.length > 0,
    JSON.stringify(held));
  return held;
}

async function testConfirmingWithTheWrongWordChangesNothing(operator, fake, held) {
  if (held === null) return;
  var before = writeCount(fake);

  var empty = await operator.form("/admin/dmarc", {
    action:    "zone-apply",
    changeset: held.changeset,
    diff:      held.diff,
  });
  count("a post carrying no confirmation asks again rather than publishing",
    empty.status === 200 && empty.body.indexOf("Type the domain to confirm") !== -1,
    empty.status + " " + flat(empty.body).slice(0, 300));
  check("and nothing was written", writeCount(fake) === before);

  var wrong = await operator.form("/admin/dmarc", {
    action:    "zone-apply",
    changeset: held.changeset,
    diff:      held.diff,
    confirm:   "some.other.domain",
  });
  count("a confirmation that is not the domain named on the page asks again and says so",
    wrong.status === 400 && wrong.body.indexOf("That is not the domain named above") !== -1,
    wrong.status + " " + flat(wrong.body).slice(0, 400));
  check("and still nothing was written", writeCount(fake) === before);
}

async function testNamingAnotherHeldChangeSetIsRefused(operator, fake, held) {
  if (held === null) return;
  var before = writeCount(fake);

  // A second change set, for a different domain, prepared and left
  // standing. It is a different change set against a different zone, so its
  // diff digest is not this one's.
  var other = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: STEPDOWN,
    level:  "none",
    reason: "step this domain down while its senders are fixed",
  });
  count("a second change set can be prepared and left standing",
    other.status === 200, String(other.status));
  if (other.status !== 200) return;
  var otherHeld = heldFrom(other.body);

  var swapped = await operator.form("/admin/dmarc", {
    action:    "zone-apply",
    changeset: otherHeld.changeset,
    diff:      held.diff,
    confirm:   STEPDOWN,
  });
  count("a form naming one held change set while carrying another's diff is refused",
    swapped.status === 409, String(swapped.status));
  count("and the refusal is a problem document under its own type",
    isProblemDocument(swapped) &&
    problemFrom(swapped).type === "urn:blamepost:problem:zone-change-set-moved",
    problemFrom(swapped).raw);
  check("nothing was written while the two were being told apart",
    writeCount(fake) === before);

  var unheld = await operator.form("/admin/dmarc", {
    action:    "zone-apply",
    changeset: "a-name-this-server-never-issued",
    diff:      held.diff,
    confirm:   SETTLED,
  });
  count("a change set this server is not holding is refused rather than recomputed",
    unheld.status === 409 && isProblemDocument(unheld) &&
    problemFrom(unheld).type === "urn:blamepost:problem:zone-change-set-not-held",
    unheld.status + " " + problemFrom(unheld).raw);
  check("and nothing was written for it either", writeCount(fake) === before);
}

// A second administrator holding every value the first operator's form
// carried: the name of the held set, the digest, and the domain typed back.
// The set is held for the account that prepared it, so the second
// administrator's post finds nothing to perform, and the first operator's
// set is still held afterwards.
async function testAnotherAdministratorCannotPerformAHeldChangeSet(other, fake, held) {
  if (held === null) return;
  var before = writeCount(fake);
  var answer = await other.form("/admin/dmarc", {
    action:    "zone-apply",
    changeset: held.changeset,
    diff:      held.diff,
    confirm:   SETTLED,
  });
  count("another administrator posting the first operator's held change set is refused as " +
    "a set this server does not hold for them",
    answer.status === 409 && isProblemDocument(answer) &&
    problemFrom(answer).type === "urn:blamepost:problem:zone-change-set-not-held",
    answer.status + " " + problemFrom(answer).raw);
  check("and nothing was written for it", writeCount(fake) === before);
}

async function testPublishingWritesTheRecordAndReadsItBack(operator, fake, held) {
  if (held === null) return;

  var answer = await operator.form("/admin/dmarc", {
    action:    "zone-apply",
    changeset: held.changeset,
    diff:      held.diff,
    confirm:   SETTLED,
  });
  count("confirming with the domain publishes the record and sends the operator back",
    answer.status === 302 || answer.status === 303,
    answer.status + " " + flat(answer.body).slice(0, 300));
  count("and the page it lands on reports that the provider and a resolver agree",
    String(answer.location || "").indexOf("notice=zone-published") !== -1,
    String(answer.location));

  var atAddress = heldAt(fake, "_dmarc." + SETTLED);
  count("the provider is left holding exactly the record that was published",
    atAddress.length === 1 && atAddress[0] === SETTLED_SERVED,
    JSON.stringify(atAddress));

  // The record that was NOT named by the change set has to survive. The
  // mechanism that saves it is that the gate never reads its address, so
  // what is asked is whether the provider was ever asked about it.
  var elsewhere = heldAt(fake, SETTLED);
  count("a record at an address the change set was silent about is still there",
    elsewhere.length === 1 && elsewhere[0].indexOf("site-verification") !== -1,
    JSON.stringify(elsewhere));

  var replayed = await operator.form("/admin/dmarc", {
    action:    "zone-apply",
    changeset: held.changeset,
    diff:      held.diff,
    confirm:   SETTLED,
  });
  count("the same change set cannot be performed twice",
    replayed.status === 409 && isProblemDocument(replayed) &&
    problemFrom(replayed).type === "urn:blamepost:problem:zone-change-set-not-held",
    replayed.status + " " + problemFrom(replayed).raw);
}

async function testThePublishIsOnTheAuditTrail(operatorAccount) {
  await b.audit.flush();
  var rows = await b.audit.query({
    action: "blamepost.dns.applied", resourceId: SETTLED, order: "desc", limit: 20,
  });
  count("the trail carries a row for the publish, filed against the domain it changed",
    rows.length >= 1, String(rows.length) + " row(s)");
  if (rows.length === 0) return;

  var mine = rows.filter(function (row) { return row.actorUserId === operatorAccount.id; });
  count("and it names the operator who made it rather than the process",
    mine.length >= 1, JSON.stringify(rows.map(function (row) { return row.actorUserId; })));
  count("and carries the reason that operator typed on the form",
    mine.some(function (row) {
      return typeof row.reason === "string" && row.reason.indexOf(PUBLISH_REASON) !== -1;
    }), JSON.stringify(mine.map(function (row) { return row.reason; })));
  count("and says what changed rather than only that something did",
    mine.some(function (row) {
      return typeof row.metadata === "string" && /"changes":\s*2/.test(row.metadata);
    }), JSON.stringify(mine.map(function (row) { return row.metadata; })));
}

// The value an address is holding came out of the provider's response,
// and the operator reads it and types a domain back on the strength of
// it. Escaping stops such a value executing; it does not stop a
// right-to-left override reordering the line the operator is reading, or
// a zero-width character hiding part of what is about to go.
async function testWhatTheProviderSaidIsScreenedBeforeItIsShown(operator, fake) {
  var answer = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: HOSTILE,
    level:  "none",
    reason: "reduce this address to the one record",
  });
  count("a change set naming a record whose stored value carries display controls prepares",
    answer.status === 200, answer.status + " " + flat(answer.body).slice(0, 300));
  if (answer.status !== 200) return;

  count("the override character does not reach the rendered page",
    answer.body.indexOf("‮") === -1 && answer.body.indexOf("&#x202E;") === -1,
    flat(answer.body).slice(0, 600));
  count("and neither does the zero-width joiner hiding part of the value",
    answer.body.indexOf("‍") === -1, flat(answer.body).slice(0, 600));
  // The C1 range is the half of this screen a reader cannot see. The
  // single-byte CSI is one byte that opens an escape sequence, so a
  // value carrying it colors or moves whatever reads the page as a
  // stream: the server log this row is also written to, and a terminal
  // an operator pipes it through.
  count("nor the C1 control that would open an escape sequence in anything reading this",
    answer.body.indexOf(CSI) === -1, flat(answer.body).slice(0, 600));
  count("the rest of the value is still shown, so the row is screened rather than dropped",
    answer.body.indexOf("p=none") !== -1 && answer.body.indexOf("HOSTILE-MARKER") !== -1,
    flat(answer.body).slice(0, 900));
  count("and the script tag in it is escaped rather than rendered",
    answer.body.indexOf("<script>alert") === -1,
    flat(answer.body).slice(0, 900));
}

// A zone already holding exactly what a level publishes, and nothing
// else at that address. There is no change to confirm, so answering with
// a confirmation page would be asking the operator to agree to nothing,
// and answering with a success would be reporting a write that never
// happened.
async function testAZoneAlreadyHoldingTheRecordIsSaidSoRatherThanRewritten(operator, fake) {
  var before = writeCount(fake);
  var answer = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: SETTLED,
    level:  "none",
    reason: "publish the record the zone already holds",
  });
  count("a level the zone already holds is reported rather than prepared",
    answer.status === 409 && isProblemDocument(answer) &&
    problemFrom(answer).type === "urn:blamepost:problem:zone-policy-step-not-carried",
    answer.status + " " + problemFrom(answer).raw);
  count("and the detail says the address already holds it rather than naming a rule",
    problemFrom(answer).detail.indexOf("already") !== -1,
    problemFrom(answer).detail.slice(0, 300));
  check("nothing was written", writeCount(fake) === before);
}

// The provider refusing is not the same as this server refusing, and the
// operator needs the provider's own words: a token without the scope, a
// zone the credential cannot see, and a throttled endpoint each need a
// different answer and only the provider knows which it was.
async function testAProviderRefusalReachesTheOperatorInItsOwnWords(operator, fake) {
  var before = writeCount(fake);
  var priorMode = fake.state.mode;
  fake.state.mode = "unauthorized";
  try {
    var answer = await operator.form("/admin/dmarc", {
      action: "zone-prepare",
      domain: MOVED,
      level:  "none",
      reason: "read the zone with a credential the provider will not accept",
    });
    count("a provider that refuses the credential is reported as the provider refusing",
      answer.status === 502 && isProblemDocument(answer) &&
      problemFrom(answer).type === "urn:blamepost:problem:zone-provider-refused",
      answer.status + " " + problemFrom(answer).raw);
    count("and the detail is the sentence that layer wrote rather than a generic failure",
      problemFrom(answer).detail.length > 40 &&
      /token|credential|accept/i.test(problemFrom(answer).detail),
      problemFrom(answer).detail.slice(0, 300));
    check("nothing was written", writeCount(fake) === before);
  } finally {
    fake.state.mode = priorMode;
  }
}

async function testAZoneThatMovedStopsTheWrite(operator, fake) {
  var prepared = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: MOVED,
    level:  "none",
    reason: "settle this domain's policy record",
  });
  count("a change set is prepared for the domain whose zone is about to move",
    prepared.status === 200, String(prepared.status));
  if (prepared.status !== 200) return;
  var held = heldFrom(prepared.body);
  var before = writeCount(fake);

  // Something else edits the zone between the page and the post. The
  // record the change set was computed against is still there; what has
  // changed is what the address is holding.
  fake.state.records.push({
    id: "movedunder0000000000000000000000", type: "TXT", name: "_dmarc." + MOVED,
    content: "v=DMARC1; p=reject", ttl: 300,
  });

  var answer = await operator.form("/admin/dmarc", {
    action:    "zone-apply",
    changeset: held.changeset,
    diff:      held.diff,
    confirm:   MOVED,
  });
  count("a zone that moved under a prepared change set stops the write",
    answer.status === 409, answer.status + " " + flat(answer.body).slice(0, 300));
  count("and says so under its own type rather than as a generic failure",
    isProblemDocument(answer) &&
    problemFrom(answer).type === "urn:blamepost:problem:zone-record-drift",
    problemFrom(answer).raw);
  count("the refusal tells the operator to read the new diff rather than to press again",
    problemFrom(answer).detail.indexOf("preview") !== -1 ||
    problemFrom(answer).detail.indexOf("again") !== -1,
    problemFrom(answer).detail.slice(0, 300));
  check("nothing was written while the zone was disagreeing",
    writeCount(fake) === before);
  count("and the record that arrived underneath is still there, untouched",
    heldAt(fake, "_dmarc." + MOVED).indexOf("v=DMARC1; p=reject") !== -1,
    JSON.stringify(heldAt(fake, "_dmarc." + MOVED)));
}

async function testAChangeSetLargerThanTheGatePerformsIsRefused(operator, fake) {
  var before = writeCount(fake);
  var answer = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: CROWDED,
    level:  "none",
    reason: "reduce this address to one policy record",
  });
  count("a change set larger than the gate performs is refused while it is being computed",
    answer.status === 422, answer.status + " " + flat(answer.body).slice(0, 300));
  count("and it is a problem document naming the ceiling rather than a rendered page",
    isProblemDocument(answer) &&
    problemFrom(answer).type === "urn:blamepost:problem:zone-too-many-changes",
    problemFrom(answer).raw);
  count("the refusal says how many changes the set carried",
    problemFrom(answer).detail.indexOf(String(CROWDED_RECORDS)) !== -1,
    problemFrom(answer).detail.slice(0, 300));
  check("nothing was written", writeCount(fake) === before);
  count("and the address still holds every record it held",
    heldAt(fake, "_dmarc." + CROWDED).length === CROWDED_RECORDS,
    String(heldAt(fake, "_dmarc." + CROWDED).length));
}

async function testAReadBackThatDisagreesIsReportedRatherThanHidden(operator, fake) {
  // Stepping down is not gated on evidence, which is the whole point of
  // it: an operator whose mail is being discarded publishes the weaker
  // record first. The resolver goes on answering with the old policy,
  // which is exactly the state a single read cannot see.
  var page = await operator.get("/admin/dmarc?domain=" + encodeURIComponent(STEPDOWN));
  var card = sectionFrom(page.body, "Policy");
  count("a domain at quarantine is offered the weaker policy with no evidence asked for",
    card.indexOf("v=DMARC1; p=none; rua=mailto:dmarc@" + STEPDOWN) !== -1 &&
    (card.match(/name="action" value="zone-prepare"/g) || []).length >= 2,
    flat(card).slice(0, 1200));

  var prepared = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: STEPDOWN,
    level:  "none",
    reason: "receivers are discarding mail this domain really sent",
  });
  count("the step down is prepared", prepared.status === 200, String(prepared.status));
  if (prepared.status !== 200) return;
  var held = heldFrom(prepared.body);

  var answer = await operator.form("/admin/dmarc", {
    action:    "zone-apply",
    changeset: held.changeset,
    diff:      held.diff,
    confirm:   STEPDOWN,
  });
  count("the step down is published", answer.status === 302 || answer.status === 303,
    answer.status + " " + flat(answer.body).slice(0, 200));
  count("and a resolver answering with something else is reported rather than folded " +
    "into a clean publish",
    String(answer.location || "").indexOf("notice=zone-published-conflict") !== -1,
    String(answer.location));

  var atAddress = heldAt(fake, "_dmarc." + STEPDOWN);
  count("the provider does hold the record that was published, which is what makes the " +
    "disagreement a resolver reading rather than a failed write",
    atAddress.length === 1 &&
    atAddress[0] === "v=DMARC1; p=none; rua=mailto:dmarc@" + STEPDOWN,
    JSON.stringify(atAddress));

  var landed = await operator.get("/admin/dmarc?domain=" + encodeURIComponent(STEPDOWN) +
    "&notice=zone-published-conflict");
  count("the page the operator lands on says a resolver is answering with something else",
    landed.status === 200 &&
    flat(landed.body).indexOf("answering with something else") !== -1,
    flat(landed.body).slice(0, 600));
}

// The third of the four states the two reads can leave a write in, and
// the one an operator meets most: the provider took the record and no
// resolver has answered with it yet. It has to be told apart from a
// resolver answering with something else, because that one does not
// clear on its own and this one does.
async function testAWriteNoResolverHasSeenYetIsReportedAsWaiting(operator, fake) {
  var prepared = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: UNSEEN,
    level:  "none",
    reason: "publish the first policy record for this domain",
  });
  count("a domain whose name carries no TXT record is offered the weakest level",
    prepared.status === 200, prepared.status + " " + flat(prepared.body).slice(0, 300));
  if (prepared.status !== 200) return;
  var held = heldFrom(prepared.body);

  var answer = await operator.form("/admin/dmarc", {
    action:    "zone-apply",
    changeset: held.changeset,
    diff:      held.diff,
    confirm:   UNSEEN,
  });
  count("the record is published", answer.status === 302 || answer.status === 303,
    answer.status + " " + flat(answer.body).slice(0, 200));
  count("and a resolver that has not answered with it yet is reported as waiting rather " +
    "than as a disagreement",
    String(answer.location || "").indexOf("notice=zone-published-pending") !== -1,
    String(answer.location));

  var landed = await operator.get("/admin/dmarc?domain=" + encodeURIComponent(UNSEEN) +
    "&notice=zone-published-pending");
  count("the page says it clears on its own, which is what separates it from the other " +
    "warning",
    landed.status === 200 && flat(landed.body).indexOf("clears on its own") !== -1,
    flat(landed.body).slice(0, 600));

  var atAddress = heldAt(fake, "_dmarc." + UNSEEN);
  count("the provider does hold the record, so what is waiting is the resolver",
    atAddress.length === 1 &&
    atAddress[0] === "v=DMARC1; p=none; rua=mailto:" + POSTMASTER,
    JSON.stringify(atAddress));
}

async function testWhatTheRouteRefusesBeforeItReachesTheZone(operator, fake) {
  var before = writeCount(fake);

  var noReason = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: SETTLED,
    level:  "none",
    reason: "",
  });
  count("a change with no reason is refused before the zone is read",
    noReason.status === 400 && isProblemDocument(noReason) &&
    problemFrom(noReason).type === "urn:blamepost:problem:zone-reason-required",
    noReason.status + " " + problemFrom(noReason).raw);

  var stranger = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: "not-hosted.example",
    level:  "none",
    reason: "reach a zone this server does not host",
  });
  count("a domain this server does not host is refused before anything reads it",
    stranger.status === 400 && isProblemDocument(stranger) &&
    problemFrom(stranger).type === "urn:blamepost:problem:zone-domain-not-hosted",
    stranger.status + " " + problemFrom(stranger).raw);

  var badLevel = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: SETTLED,
    level:  "p=whatever",
    reason: "publish something that is not a policy",
  });
  count("a level that is not one of the three is refused",
    badLevel.status === 400 && isProblemDocument(badLevel) &&
    problemFrom(badLevel).type === "urn:blamepost:problem:zone-policy-level-refused",
    badLevel.status + " " + problemFrom(badLevel).raw);

  var jump = await operator.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: MOVED,
    level:  "reject",
    reason: "skip the evidence and publish the strongest policy",
  });
  count("a step up the evidence does not carry is refused rather than published",
    jump.status === 409 && isProblemDocument(jump) &&
    problemFrom(jump).type === "urn:blamepost:problem:zone-policy-step-not-carried",
    jump.status + " " + problemFrom(jump).raw);

  var nonsense = await operator.form("/admin/dmarc", {
    action: "publish-everything",
    domain: SETTLED,
  });
  count("an act this page does not perform is refused by name",
    nonsense.status === 400 && isProblemDocument(nonsense) &&
    problemFrom(nonsense).type === "urn:blamepost:problem:zone-action-refused",
    nonsense.status + " " + problemFrom(nonsense).raw);

  check("none of the refusals reached the provider as a write",
    writeCount(fake) === before);
}

async function testAnAccountWithoutTheRoleReachesNoneOfIt(reader, fake) {
  var before = writeCount(fake);

  var page = await reader.get("/admin/dmarc?domain=" + encodeURIComponent(SETTLED));
  count("an account that does not administer this server is refused the DMARC page",
    page.status === 403, String(page.status));

  var attempt = await reader.form("/admin/dmarc", {
    action: "zone-prepare",
    domain: SETTLED,
    level:  "none",
    reason: "publish without the role",
  });
  count("and is refused the zone verbs on it as well",
    attempt.status === 403, String(attempt.status));
  count("the refusal names the role rather than the zone",
    attempt.body.indexOf("does not administer this server") !== -1,
    flat(attempt.body).slice(0, 300));
  check("nothing reached the provider", writeCount(fake) === before);
}

// ---------------------------------------------------------------------------

// The identifiers are padded to a fixed width before the filler is
// added. Without that, "crowded1" followed by n zeros and "crowded10"
// followed by n-1 zeros are the same string, and the provider client
// refuses a listing that returns one identifier twice, which is a
// correct refusal about a fixture that made two records into one.
function crowdedRecords() {
  var rows = [];
  for (var i = 0; i < CROWDED_RECORDS; i += 1) {
    var tail = String(100 + i);
    rows.push({
      id:      "crowded" + tail + new Array(32 - 7 - tail.length + 1).join("0"),
      type:    "TXT",
      name:    "_dmarc." + CROWDED,
      content: "v=DMARC1; p=none; rua=mailto:dmarc@" + CROWDED + "; ri=" + (3600 + i),
      ttl:     300,
    });
  }
  return rows;
}

function seededZone() {
  return [
    // The settled domain: two policy records at one address, plus a
    // record at the apex that no change set here ever names.
    { id: "settledkeep00000000000000000000a", type: "TXT", name: "_dmarc." + SETTLED,
      content: "v=DMARC1; p=none", ttl: 300 },
    { id: "settledgone00000000000000000000b", type: "TXT", name: "_dmarc." + SETTLED,
      content: SETTLED_STALE, ttl: 300 },
    { id: "apexverify0000000000000000000000", type: "TXT", name: SETTLED,
      content: "some-vendor-site-verification=abc123", ttl: 300 },
    // The domain that steps down.
    { id: "stepdownnow000000000000000000000", type: "TXT", name: "_dmarc." + STEPDOWN,
      content: STEPDOWN_SERVED, ttl: 300 },
    // The domain whose zone moves between the page and the post.
    { id: "movednow00000000000000000000000c", type: "TXT", name: "_dmarc." + MOVED,
      content: "v=DMARC1; p=none", ttl: 300 },
    // The domain whose address is holding a value written to mislead the
    // operator reading it. Two records, so the misleading one reaches the
    // page as the removal line.
    { id: "hostilekeep000000000000000000000", type: "TXT", name: "_dmarc." + HOSTILE,
      content: "v=DMARC1; p=none", ttl: 300 },
    { id: "hostilegone000000000000000000000", type: "TXT", name: "_dmarc." + HOSTILE,
      content: HOSTILE_STALE, ttl: 300 },
    // The domain the provider holds a record for that no resolver
    // answers with. The resolver's own entry is empty rather than
    // absent, which is the difference between a name that does not exist
    // and one that exists holding no TXT record.
    { id: "unseennow0000000000000000000000d", type: "TXT", name: "_dmarc." + UNSEEN,
      content: "v=DMARC1; p=quarantine", ttl: 300 },
  ].concat(crowdedRecords());
}

// What the world can see. It is the fixture's own statement rather than
// anything the console produced, which is what makes the read-back after
// a write an independent reading: the provider says what the zone holds
// and this says what a resolver answers, and the two are not the same
// fact.
function servedZone() {
  var zone = {};
  zone["_dmarc." + SETTLED + "|TXT"]  = [{ type: 16, decoded: [SETTLED_SERVED] }];
  zone["_dmarc." + STEPDOWN + "|TXT"] = [{ type: 16, decoded: [STEPDOWN_SERVED] }];
  zone["_dmarc." + MOVED + "|TXT"]    = [{ type: 16, decoded: [MOVED_SERVED] }];
  zone["_dmarc." + CROWDED + "|TXT"]  = [{ type: 16, decoded: [CROWDED_SERVED] }];
  zone["_dmarc." + HOSTILE + "|TXT"]  = [{ type: 16, decoded: [HOSTILE_SERVED] }];
  // The name exists and carries no TXT record, which is what a resolver
  // answers before a newly created record has reached it. It is not the
  // same answer as a name that does not exist, and the read-back after a
  // write has to tell them apart.
  zone["_dmarc." + UNSEEN + "|TXT"]   = [];
  return zone;
}

async function run() {
  var root    = helpers.tempDir("web-zone-publish");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var hadTmp   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;

  var fake    = null;
  var client  = null;
  var server  = null;
  var running = false;

  try {
    process.env.BLAMEJS_TMPDIR = workDir;

    fake = await standIn.start({
      records: seededZone(),
      zones: [
        { id: "zonesettled00000000000000000001", name: SETTLED },
        { id: "zonestepdown0000000000000000002", name: STEPDOWN },
        { id: "zonemoved0000000000000000000003", name: MOVED },
        { id: "zonecrowded00000000000000000004", name: CROWDED },
        { id: "zonehostile00000000000000000005", name: HOSTILE },
        { id: "zoneunseen000000000000000000006", name: UNSEEN },
      ],
    });

    var material = await certs.writePair(nodePath.join(dataDir, "tls"),
      { hostname: HOSTNAME });

    var cfg = config.load({
      env: {
        BLAMEPOST_HOSTNAME:                     HOSTNAME,
        BLAMEPOST_DATA_DIR:                     dataDir,
        BLAMEPOST_VAULT_PASSPHRASE:             VAULT_PASSPHRASE,
        BLAMEPOST_DNS_ACKNOWLEDGED:             "1",
        BLAMEPOST_TLS_CERT:                     material.certFile,
        BLAMEPOST_TLS_KEY:                      material.keyFile,
        BLAMEPOST_ZONE_PROVIDER:                "cloudflare",
        BLAMEPOST_ZONE_ENDPOINT:                fake.baseUrl,
        BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT: "1",
        BLAMEPOST_POSTMASTER:                   POSTMASTER,
      },
      cwd: root,
    });

    var identity = await store.open(cfg);
    await identity.domains.add({ domain: SETTLED });
    await identity.domains.add({ domain: STEPDOWN });
    await identity.domains.add({ domain: MOVED });
    await identity.domains.add({ domain: CROWDED });
    await identity.domains.add({ domain: HOSTILE });
    await identity.domains.add({ domain: UNSEEN });
    var operatorAccount = await identity.accounts.create({
      address: OPERATOR_ADDRESS, password: OPERATOR_PASSWORD, isAdmin: true });
    await identity.accounts.create({
      address: READER_ADDRESS, password: READER_PASSWORD });
    await identity.accounts.create({
      address: SECOND_OPERATOR_ADDRESS, password: SECOND_OPERATOR_PASSWORD, isAdmin: true });

    // Sealed through the running vault, which is what the configuration
    // carries and what is opened for one request at a time. The gate
    // refuses a value that is not sealed before it reaches any client, so
    // this is the shape a deployment injecting the credential uses.
    var sealed = dns.sealToken(TOKEN, b.vault);

    // The provider client, built here so it can trust the stand-in's own
    // certificate authority. Its `readToken` opens the same sealed value
    // the configuration carries, per request, the way the gate's own
    // does.
    client = provider.create({
      readToken:             function () {
        return b.vault.aad.unseal(sealed, { purpose: "blamepost.dns.provider-token" });
      },
      baseUrl:               fake.baseUrl,
      agent:                 fake.agent,
      allowInternalEndpoint: true,
      maxAttempts:           2,
    });

    // Every mail listener off. This file is about the browser surface,
    // and a port taken is a port another file in the same run cannot
    // have.
    var names = ["mx", "submission", "submissions", "imap", "pop3", "managesieve"];
    var sections = {};
    for (var i = 0; i < names.length; i += 1) {
      sections[names[i]] = {
        enabled: false,
        port:    await wire.reservePort(),
        address: LOOPBACK,
      };
    }

    server = blamepost.create({
      config: Object.assign({}, cfg, {
        httpPort: 0, httpsPort: 0, listeners: sections, zoneApiToken: sealed }),
      store:        identity,
      mailStore:    identity.mailbox,
      messageStore: identity.messageStore,
      httpAddress:  LOOPBACK,
      resolver:     dnsZone.pinnedResolverOver(servedZone()),
      zoneClient:   client,
    });
    await server.start();
    running = true;

    var reading = server.describe().zone;
    count("the running server reports the zone writer as on, so what follows is being " +
      "asked of a console that holds a credential",
      reading !== null && reading.provider === "cloudflare",
      JSON.stringify(reading));

    var bound  = server.web.bound();
    var origin = "https://" + LOOPBACK + ":" + bound.https;

    var operator = browser.browserAt(origin, { ca: material.caPem, http2: true });
    var signedIn = await operator.signIn(OPERATOR_ADDRESS, OPERATOR_PASSWORD);
    count("the operator signs in to the console over HTTP/2",
      signedIn.status === 302 || signedIn.status === 303,
      signedIn.status + " " + String(signedIn.body).replace(/\s+/g, " ").slice(0, 200));

    await testThePageOffersTheRecordForEachLevel(operator);
    var held = await testPreparingReadsTheZoneAndWritesNothing(operator, fake);
    await testConfirmingWithTheWrongWordChangesNothing(operator, fake, held);
    await testNamingAnotherHeldChangeSetIsRefused(operator, fake, held);

    var secondOperator = browser.browserAt(origin, { ca: material.caPem, http2: true });
    var secondIn = await secondOperator.signIn(SECOND_OPERATOR_ADDRESS, SECOND_OPERATOR_PASSWORD);
    count("a second administrator signs in to the console",
      secondIn.status === 302 || secondIn.status === 303, String(secondIn.status));
    await testAnotherAdministratorCannotPerformAHeldChangeSet(secondOperator, fake, held);

    await testPublishingWritesTheRecordAndReadsItBack(operator, fake, held);
    await testThePublishIsOnTheAuditTrail(operatorAccount);
    await testWhatTheProviderSaidIsScreenedBeforeItIsShown(operator, fake);
    await testAZoneAlreadyHoldingTheRecordIsSaidSoRatherThanRewritten(operator, fake);
    await testAProviderRefusalReachesTheOperatorInItsOwnWords(operator, fake);
    await testAZoneThatMovedStopsTheWrite(operator, fake);
    await testAChangeSetLargerThanTheGatePerformsIsRefused(operator, fake);
    await testAReadBackThatDisagreesIsReportedRatherThanHidden(operator, fake);
    await testAWriteNoResolverHasSeenYetIsReportedAsWaiting(operator, fake);
    await testWhatTheRouteRefusesBeforeItReachesTheZone(operator, fake);

    // The credential the requests above authenticated with. A reader that
    // handed the sealed string on unopened would still reach the stand-in,
    // which does not judge the token, so the header is read here.
    count("every request the provider received carried the credential that was sealed",
      fake.state.requests.length > 0 && fake.state.requests.every(function (r) {
        return r.headers.authorization === "Bearer " + TOKEN;
      }), fake.state.requests.length + " request(s)");

    var reader = browser.browserAt(origin, { ca: material.caPem, http2: true });
    var readerIn = await reader.signIn(READER_ADDRESS, READER_PASSWORD);
    count("the account holding no operator role signs in to its own mailbox",
      readerIn.status === 302 || readerIn.status === 303,
      readerIn.status + " " + String(readerIn.body).replace(/\s+/g, " ").slice(0, 200));
    await testAnAccountWithoutTheRoleReachesNoneOfIt(reader, fake);

    await server.stop({ timeoutMs: STOP_MS });
    running = false;

    return helpers.getChecks();
  } finally {
    if (running && server !== null) {
      try { await server.stop({ timeoutMs: STOP_MS }); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (client !== null) {
      try { client.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (fake !== null) {
      try { fake.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (store.isOpen()) {
      try { store.close(); }
      catch (_e) { /* drop-silent by design: the run's verdict is already decided */ }
    }
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    helpers.removeTempDir(root);
  }
}

module.exports = {
  name:      "web-zone-publish",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
