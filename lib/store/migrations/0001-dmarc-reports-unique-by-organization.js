// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Drops the unique index on `blamepost_dmarc_reports (orgKey, reportId)`
// where a volume carries it.
//
// `blamepost.store.tables` declares a unique index on
// `(verifiedOrgDomain, orgKey, reportId)`, and the schema reconcile at boot
// adds the `verifiedOrgDomain` column and that index before this runs. The
// reconcile only adds indexes, so without this migration the index on
// `(orgKey, reportId)` stays and refuses an authenticated report whose name
// and identifier another report already used.
//
// Rows already on the volume keep the empty value the column declares and
// count toward no organization. Nothing here derives an organization for
// them from `orgName`.
//
// The framework runs this once, inside a transaction, and records it in
// `_blamejs_migrations`. `IF EXISTS` makes the statement do nothing on a
// volume that never carried the index. There is no `down`, because the
// index on `(orgKey, reportId)` would refuse rows the new index admits.

var NAME_KEYED_UNIQUE_INDEX = "idx_blamepost_dmarc_reports_id";

module.exports = {
  description: "drop the DMARC report uniqueness rule keyed on the reporter's own name",
  up: function (database) {
    database.prepare("DROP INDEX IF EXISTS \"" + NAME_KEYED_UNIQUE_INDEX + "\"").run();
  },
};
