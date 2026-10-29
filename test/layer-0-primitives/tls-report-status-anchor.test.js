// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * tls-report-status-anchor: the enhanced status a TLS report is
 * classified on is the one the composer underneath still writes.
 *
 * Every RFC 8460 report this server sends is an accusation about
 * somebody else's transport security, signed with this server's name.
 * What turns a failed delivery into one of the §4.3 result types is
 * `_tlsRptResultFor` in `lib/mail/delivery.js`, and two of its branches
 * decide on an enhanced status alone. One of those statuses this server
 * writes itself. The other is written by the vendored delivery composer,
 * which makes it a frozen contract this repository reads and does not
 * own.
 *
 * A contract read across the vendor boundary is the one that goes quiet
 * without saying so. The refresh script replaces `lib/vendor/blamejs/`
 * wholesale, so a status that moves there leaves the comparison here
 * matching nothing: no branch throws, no test fails, and the receiver
 * whose MTA-STS policy this server could not use simply stops being
 * told. An absence in reporting reads exactly like a receiver whose
 * transport security is fine.
 *
 * The two halves are not equally exposed, and the coverage was on the
 * wrong one. `sts-policy-fetch-error` is reached from a status this
 * repository produces in its own file, and it has vectors in
 * `test/layer-1-state/tlsrpt-reporting.test.js` and
 * `test/layer-2-integration/tlsrpt-outbound-report.test.js`.
 * `sts-policy-invalid` is reached from the vendored status, is the half
 * that can drift, and had none.
 *
 * WHY THIS IS READ AND NOT DRIVEN. What this file holds is the fact a
 * vendor refresh can change, which is that the literal the composer
 * writes is the literal this repository compares against. Nothing about
 * a delivery shows that: a run reads whatever the composer writes today,
 * so the two agree by construction however far either has moved.
 *
 * The refusals themselves are driven elsewhere, as far as they can be.
 * `test/layer-1-state/outbound-sts-verdict.test.js` reaches the fetch
 * failure over a resolver transport pointed at a port nothing listens
 * on. The mail exchanger mismatch needs the policy document, which RFC
 * 8461 section 3.3 puts behind an HTTPS fetch of `mta-sts.<domain>` the
 * framework refuses to direct at a loopback address, so
 * `test/layer-1-state/tlsrpt-refusal-cause.test.js` puts it in front of
 * the classification instead.
 *
 * Run standalone: node test/layer-0-primitives/tls-report-status-anchor.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers = require("../helpers");

var count = helpers.count;

var ROOT = nodePath.join(__dirname, "..", "..");
var DELIVERY  = nodePath.join(ROOT, "lib", "mail", "delivery.js");
var COMPOSER  = nodePath.join(ROOT, "lib", "vendor", "blamejs", "lib", "mail-send-deliver.js");

// The enhanced statuses `lib/mail/delivery.js` classifies a report on,
// read out of the declarations rather than out of the comparisons. The
// comparisons name variables, so a reader that scanned them would find
// no literal at all; the declaration is where the value is.
var STATUS_DECLARATION = /\bvar\s+\w*STATUS\w*\s*=\s*"(\d\.\d\.\d+)"/g;

// The reasonCode the composer writes when applying a receiver's MTA-STS
// policy throws. Anchored on the call rather than on a line number, and
// on the first `reasonCode` after it rather than on any in the file, so a
// body that grows around it is still read.
//
// The bound is a backstop against a pattern that grows faster than its
// input, set far above the twenty-odd lines the real handler occupies. It
// is not what makes the match precise: the lazy quantifier and the
// required literal after it are.
var COMPOSER_MTA_STS_CODE =
  /_applyMtaStsPolicy\([\s\S]{0,600}?reasonCode:\s*"(\d\.\d\.\d+)"/;

// Everything `_applyMtaStsPolicy` itself throws, read inside its own body.
// The body ends at the first closing brace in the first column, which is
// a structural boundary rather than a count of the lines it happens to
// have today.
var COMPOSER_BODY =
  /function _applyMtaStsPolicy\((?:(?!\n\})[\s\S])*/;
var THROWN_CONDITION = /throw new DeliverError\(\s*"([^"]+)"/g;

function read(file) {
  return nodeFs.readFileSync(file, "utf8");
}

function allMatches(text, pattern) {
  var found = [];
  var match;
  pattern.lastIndex = 0;
  while ((match = pattern.exec(text)) !== null) found.push(match[1]);
  return found;
}

function theStatusTheComposerWritesIsTheStatusThisServerReads() {
  var deliveryText = read(DELIVERY);
  var composerText = read(COMPOSER);

  var declared = allMatches(deliveryText, STATUS_DECLARATION);
  // An empty set answers every question below with a yes, which is the
  // shape of a check whose reader stopped finding anything. Both sides
  // are measured before either is compared.
  count("the classification declares the enhanced statuses it decides on",
    declared.length >= 2, JSON.stringify(declared));

  var written = COMPOSER_MTA_STS_CODE.exec(composerText);
  count("and the vendored composer still answers an MTA-STS refusal with one of its own",
    written !== null, written === null ? "no reasonCode found after the call" : written[1]);

  count("which is a status the classification compares against, so the branch is reachable",
    written !== null && declared.indexOf(written[1]) !== -1,
    written === null ? "unmatched" : written[1] + " against " + JSON.stringify(declared));

  // The second half of the contract. The status is not one condition:
  // the composer reaches it from every refusal applying the policy
  // raises, and RFC 8460 §4.3 gives those separate result types, so a
  // classification that decided on the status alone would tell a
  // receiver their policy is invalid when what happened is that this
  // server could not fetch it. The classification reads the composer's
  // reason beside the status for that, and this count is what says the
  // status still needs it.
  var body = COMPOSER_BODY.exec(composerText);
  count("the composer's policy step is readable, so the conditions under it can be counted",
    body !== null, body === null ? "body not matched" : String(body[0].length) + " characters");

  var conditions = body === null ? [] : allMatches(body[0], THROWN_CONDITION);
  count("and more than one condition reaches that one status, so it names a family rather " +
    "than an event",
    conditions.length > 1, JSON.stringify(conditions));
}

// ---------------------------------------------------------------------------

function run() {
  theStatusTheComposerWritesIsTheStatusThisServerReads();
  return helpers.getChecks();
}

module.exports = {
  name:      "tls-report-status-anchor",
  run:       run,
  getChecks: helpers.getChecks,
};

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  try {
    console.log("CHECKS " + run());
  } catch (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  }
}
