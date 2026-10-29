// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * retention-floor-arrival: what the floor does with a message whose
 * arrival time it cannot establish.
 *
 * Every hard delete on this server routes through `b.mail.agent.expunge`
 * so the retention floor is enforced once rather than three times: IMAP
 * `EXPUNGE`, POP3 `DELE` and JMAP `Email/set` `destroyed` all arrive
 * there. The floor decides by age, and age needs an arrival time, so the
 * whole control rests on what happens when there is not one.
 *
 * The answer has to be a refusal. An absent arrival read as zero is an
 * age of five decades, which clears every window an operator can
 * configure, so the one input the check cannot verify becomes the one
 * input that always passes it, and the failure falls toward destroying
 * records on exactly the volumes a floor is configured to protect.
 *
 * The shipped store stamps the column on every message it accepts, so
 * this is not reachable through an ordinary APPEND. What reaches it is a
 * row written by an older build, a migration that left the column null,
 * or a caller passing its own metadata. None of those is exotic, and all
 * of them end in a silent destruction rather than an error.
 *
 * Three rows drive three verdicts, and the second and third are what
 * stop the first passing for the wrong reason. A build that refused
 * every deletion would satisfy the unknown-arrival case and destroy
 * nothing; a build that permitted every deletion would satisfy the aged
 * case and protect nothing. The floor has to separate them.
 *
 * The fourth row carries a client-chosen date and no server stamp. RFC
 * 9051 section 6.3.12 lets a client choose a message's internal date on
 * APPEND, so a floor that read that value would take its input from the
 * account holder: a message dated to the epoch clears a window of any
 * size. Such a row is refused as an arrival nothing established, the
 * same as a row carrying no date at all. This server never reads the
 * client-supplied date on its own paths, and `blamepost.mail.mailbox`
 * reads only the arrival time it stamped.
 *
 * A stand-in store rather than a real one, because the input under test
 * is a row the real store cannot produce. No disk and no sockets.
 *
 * Run standalone: node test/layer-0-primitives/retention-floor-arrival.test.js
 */

var helpers = require("../helpers");
var b       = require("../../lib/vendor/blamejs");

var count = helpers.count;

var FOLDER = "mbx_retention_probe";

// A posture with a real floor behind it, so the check has something to
// refuse against. HIPAA's is six years.
var POSTURE = "hipaa";

var HOUR = 3600000;

// An actor the agent will accept for a destructive verb under a
// compliance posture. `purposeOfUse` is required there and its absence
// is a different refusal, which would pass every assertion below while
// measuring nothing about the floor.
var ACTOR = Object.freeze({
  id:           "retention-floor-probe",
  roles:        ["mail:expunge"],
  purposeOfUse: "operations",
});

// The four rows, and what each one is for.
function rows() {
  return {
    // No arrival time of any kind. The row the report was about.
    unknown:     { objectId: "unknown",     legalHold: false },
    // Stamped an hour ago, so it is inside every floor. The control that
    // proves the floor is running at all.
    recent:      { objectId: "recent",      legalHold: false, receivedAt: Date.now() - HOUR },
    // Stamped at the start of the epoch, so it is outside every floor.
    // The control that proves the floor still lets anything through.
    aged:        { objectId: "aged",        legalHold: false, receivedAt: 1 },
    // No server stamp, and a client-chosen internal date old enough to
    // clear the floor.
    clientDated: { objectId: "clientDated", legalHold: false, internalDate: 1 },
  };
}

function standInStore(table) {
  return {
    fetchByObjectId: function (folder, objectId) {
      return Object.prototype.hasOwnProperty.call(table, objectId) ? table[objectId] : null;
    },
    hardExpunge: function (folder, objectIds) {
      return {
        rows:    objectIds.map(function (id) { return { objectId: id }; }),
        deleted: objectIds.slice(),
        refused: [],
      };
    },
  };
}

function reasonFor(result, id) {
  var hit = (result.refused || []).filter(function (r) { return r.id === id; })[0];
  return hit ? hit.reason : null;
}

function wasDestroyed(result, id) {
  return (result.deleted || []).indexOf(id) !== -1;
}

// ---- the cases -------------------------------------------------------------

async function theFloorRefusesWhatItCannotDate() {
  var table = rows();
  var agent = b.mail.agent.create({ store: standInStore(table), posture: POSTURE });
  var result = await agent.expunge({
    folder:    FOLDER,
    objectIds: ["unknown", "recent", "aged", "clientDated"],
    actor:     ACTOR,
  });

  count("a message whose arrival time cannot be established is refused",
    reasonFor(result, "unknown") !== null, JSON.stringify(result.refused));
  count("and the refusal says that is why, rather than reporting it as too recent",
    reasonFor(result, "unknown") === "retention-floor-unknown-arrival",
    String(reasonFor(result, "unknown")));
  count("and it is not destroyed", !wasDestroyed(result, "unknown"),
    JSON.stringify(result.deleted));

  count("a message inside the floor is still refused on the floor",
    reasonFor(result, "recent") === "retention-floor", String(reasonFor(result, "recent")));
  count("a message past the floor is still destroyed, so the floor is not refusing everything",
    wasDestroyed(result, "aged"), JSON.stringify(result.deleted));
}

// The other half of the same question: a date the sender chose is not an
// arrival this server observed, and the floor may not read one for the
// other. A row carrying only the client's date is refused under the
// unknown-arrival name rather than dated from it.
async function theFloorDoesNotTrustAClientChosenDate() {
  var table = rows();
  var agent = b.mail.agent.create({ store: standInStore(table), posture: POSTURE });
  var result = await agent.expunge({
    folder:    FOLDER,
    objectIds: ["clientDated"],
    actor:     ACTOR,
  });
  count("a client-supplied internal date does not stand in for the arrival this server " +
    "stamped, so the floor's input is never the account holder's to choose",
    !wasDestroyed(result, "clientDated"),
    JSON.stringify({ deleted: result.deleted, refused: result.refused }));
  count("and it is refused as an arrival nothing established, rather than dated from the " +
    "value the client sent",
    reasonFor(result, "clientDated") === "retention-floor-unknown-arrival",
    String(reasonFor(result, "clientDated")));
}

// ---- runner ----------------------------------------------------------------

async function run() {
  await theFloorRefusesWhatItCannotDate();
  await theFloorDoesNotTrustAClientChosenDate();
  return helpers.getChecks();
}

module.exports = { name: "retention-floor-arrival", run: run, getChecks: helpers.getChecks };

if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
