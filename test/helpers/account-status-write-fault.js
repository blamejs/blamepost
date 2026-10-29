// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * A data volume that refuses a write to the account row.
 *
 * An erasure records itself on the account row twice: once in the status
 * column and once in the marker column beside it. `lib/store/tables.js`
 * says why there are two, and `lib/store/accounts.js` writes the second
 * on its own when the first is refused. A records-retention posture puts
 * a trigger on a status column and refuses the transition itself, so the
 * row carrying the marker and nothing else is a state a working server
 * reaches.
 *
 * Two faults, because they reach different states. The first refuses the
 * status transition and lets the marker through, which leaves a row whose
 * status column still reads whatever it read before the erasure ran. The
 * second refuses every write to one account row, which leaves a row
 * carrying neither.
 *
 * The seam is `tables.updateRow`, which is the only write path the
 * identity layer has. Everything ahead of the refused write runs exactly
 * as it runs in service, so what a test measures afterwards is the
 * shipped path rather than a fixture.
 *
 * Each install hands back the function that takes it off, and a caller
 * runs that in a `finally`, because a fault left armed reaches every
 * later case in the file.
 */

var tables = require("../../lib/store/tables");

/**
 * refuseErasingStatusWrite() refuses any write whose change set moves the
 * status column to `erasing`, and lets every other write through.
 */
function refuseErasingStatusWrite() {
  var real = tables.updateRow;
  tables.updateRow = function (table, id, values) {
    if (values && values.status === "erasing") {
      throw new Error("the data volume refused this write");
    }
    return real.apply(null, arguments);
  };
  return function () { tables.updateRow = real; };
}

/**
 * refuseEveryWriteTo(accountId) refuses every write to one account row,
 * whatever the change set names. A mount that has gone read-only under a
 * running server does this, and so does a write-once posture applied to
 * the table rather than to one column.
 */
function refuseEveryWriteTo(accountId) {
  var real = tables.updateRow;
  tables.updateRow = function (table, id) {
    if (table === tables.ACCOUNTS && id === accountId) {
      throw new Error("the data volume refused this write");
    }
    return real.apply(null, arguments);
  };
  return function () { tables.updateRow = real; };
}

module.exports = {
  refuseErasingStatusWrite: refuseErasingStatusWrite,
  refuseEveryWriteTo:       refuseEveryWriteTo,
};
