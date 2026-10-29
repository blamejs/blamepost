// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One invocation of every command that may answer from a read-only open
 * of the data volume, for the files that drive all of them through the
 * binary.
 *
 * `lib/store` publishes those commands as `SNAPSHOT_VERBS`, and
 * `store-snapshot-reporting` reconciles this table against it in both
 * directions. Every other file that drives the same commands takes them
 * from here, so a command added to the store's table is a command each
 * of those files drives once the reconciliation has made someone add it.
 *
 * Each entry names the group and verb it stands for and the argv that
 * runs it. `provider` marks a command that refuses before opening
 * anything unless a DNS provider is configured, so the caller runs it
 * with one named. `answers` marks a command that reaches the copy and
 * exits zero; `stopsOn` is the text a command prints when it reaches the
 * copy and stops on its own subject instead.
 *
 * The arguments keep every command off the network. The zone reads name
 * a domain the volume does not host, or find no sealed token, and stop
 * there, and `doctor` is scoped to the hosted domain.
 */

var config = require("../../lib/config");

// A domain this server does not host, for the two reads that answer
// about a zone at the provider.
var UNHOSTED = "nothosted.example";

// A provider the schema accepts, read from the schema rather than
// written out, so a provider renamed there is still a provider here.
var ZONE_PROVIDER = config.ZONE_PROVIDERS.filter(function (name) {
  return name !== config.ZONE_PROVIDER_NONE;
})[0];

/**
 * vectors({ address, domain, hostname }) returns the table.
 *
 * `address` is an account on the volume, `domain` the domain it belongs
 * to, and `hostname` the MX hostname the run configures, which is what
 * `doctor` names when it stops. All three are required, because a vector
 * built around an absent value drives a command that refuses on its
 * argument rather than on the volume.
 */
function vectors(opts) {
  if (!opts || typeof opts.address !== "string" || typeof opts.domain !== "string" ||
      typeof opts.hostname !== "string") {
    throw new TypeError("helpers/snapshot-verbs.vectors: address, domain and hostname are required");
  }
  var address  = opts.address;
  var domain   = opts.domain;
  var hostname = opts.hostname;
  return [
    { group: "account", verb: "list",
      argv: ["account", "list"], answers: true },
    { group: "account", verb: "show",
      argv: ["account", "show", address], answers: true },
    { group: "domain", verb: "list",
      argv: ["domain", "list"], answers: true },
    { group: "domain", verb: "show",
      argv: ["domain", "show", domain], answers: true },
    { group: "dkim", verb: "list",
      argv: ["dkim", "list", domain], answers: true },
    { group: "dkim", verb: "records",
      argv: ["dkim", "records", domain], answers: true },
    { group: "reports", verb: "list",
      argv: ["reports", "list"], answers: true },
    { group: "blobs", verb: "report",
      argv: ["blobs", "report", "--verify"], answers: true },
    { group: "audit", verb: "verify-chain",
      argv: ["audit", "verify-chain"], answers: true },
    // The three sending-credential reads. The volume holds no credential,
    // so the two that answer report an empty domain and the third stops
    // on the identifier.
    { group: "credential", verb: "list",
      argv: ["credential", "list", domain], answers: true },
    { group: "credential", verb: "bounces",
      argv: ["credential", "bounces", domain], answers: true },
    { group: "credential", verb: "show",
      argv: ["credential", "show", "0000000000000000"],
      stopsOn: "no sending credential" },
    { group: "reports", verb: "show",
      argv: ["reports", "show", "no-such-report-on-this-volume"],
      stopsOn: "no aggregate report on this volume" },
    { group: "zone", verb: "preview",
      argv: ["zone", "preview", UNHOSTED, "--reason", "checking the records"],
      provider: true, stopsOn: "does not host " + UNHOSTED },
    { group: "zone", verb: "verify",
      argv: ["zone", "verify", UNHOSTED, "--reason", "checking the records"],
      provider: true, stopsOn: "does not host " + UNHOSTED },
    // It names no domain, so what keeps it off the network is the volume
    // holding no sealed token: it opens the copy, finds no credential to
    // ask with, and stops on that.
    { group: "zone", verb: "verify-token",
      argv: ["zone", "verify-token", "--reason", "checking the credential"],
      provider: true, stopsOn: "no provider token is available" },
    { group: "doctor", verb: "",
      argv: ["doctor", "--domain", domain], stopsOn: hostname },
  ];
}

module.exports = {
  vectors:       vectors,
  UNHOSTED:      UNHOSTED,
  ZONE_PROVIDER: ZONE_PROVIDER,
};
