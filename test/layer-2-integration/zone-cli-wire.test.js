// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * `blamepost zone preview` and `blamepost zone verify`, run as an
 * operator runs them, against a provider that answers on a socket.
 *
 * Everything between the configuration and the wire is composed rather
 * than written down, and each join is a place a defect is invisible from
 * both sides. The settings have to reach the writer, the writer has to
 * build a gate for the right domain, the gate has to be handed the
 * records this server expects that domain to publish, and the answer has
 * to come back rendered. A unit check of any one of those passes while
 * the next one along is wrong: a records reader that returns the zone
 * line rather than the record value, or a verify call handed a shape it
 * reads a different field out of, both produce a clean run and a wrong
 * answer.
 *
 * So this drives the shipped binary. The provider is the same stand-in
 * `dns-write-gate.test.js` uses, bound on loopback and speaking TLS,
 * because the client has no cleartext mode; the spawned process is told
 * to trust its certificate authority through `NODE_EXTRA_CA_CERTS`,
 * which is the only way to hand a child process the trust an in-process
 * caller passes as an agent.
 *
 * The resolver is pointed at a port nothing listens on, through the
 * preload `cli-doctor-unresolved.test.js` already uses. That is not a
 * convenience: `verify` asks a resolver by design, and a run that asked
 * a real one would make this file's verdict depend on the network and on
 * whatever `example.com` publishes. Pointed at a closed port, every
 * lookup fails immediately and lands on the verdict that says so, which
 * is a reading this file can assert on.
 *
 * Nothing here writes a record. `preview` is read-only by construction
 * and no verb on this command line applies one, so the provider's write
 * log is asserted empty at the end rather than assumed to be.
 *
 * Run standalone: node test/layer-2-integration/zone-cli-wire.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers   = require("../helpers");
var cliHelper = require("../helpers/cli");
var dnsQuiet  = require("../helpers/dns-quiet");
var standIn   = require("../helpers/dns-provider");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = standIn.DOMAIN;

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// A credential shaped like the provider's. It travels to the stand-in in
// the authorization header and nowhere else, which the gate suite
// measures; here it only has to be a token the seal round-trips.
var TOKEN = "fixtureDnsTokenmV7cX2gJ5dR9fL0yA";

// What a JSON answer parses to, or a failure naming the transcript that
// would not parse. A verb that refused prints prose, so a bare
// `JSON.parse` here would report a syntax error where the useful
// information is the refusal. A run that hit its ceiling is reported as
// itself rather than as unreadable output, because the two need opposite
// fixes.
function answerOf(label, said) {
  if (said.ceilingHit) {
    throw new Error("FAIL: " + label + ": the run never finished: " +
      said.both.slice(0, 400));
  }
  try {
    return JSON.parse(said.both);
  } catch (_e) {
    throw new Error("FAIL: " + label + ": expected JSON, got exit " +
      said.status + " and: " + said.both.slice(0, 400));
  }
}

// ---- cases -----------------------------------------------------------------

// The composition, end to end and in the direction that matters: the
// records this server expects are the records the diff proposes. Both
// halves are read off the binary, so a change to either the DKIM reader
// or the zone verb has to move both together or this fails.
async function previewProposesTheRecordsThisServerExpects(run, fake) {
  var listed = answerOf("dkim records", await run(["dkim", "records", DOMAIN, "--json"]));
  count("the domain publishes DKIM selector records, so there is something to preview",
    Array.isArray(listed) && listed.length >= 2, JSON.stringify(listed).slice(0, 200));

  var said = await run(["zone", "preview", DOMAIN, "--reason", "checking the DKIM records",
    "--json"]);
  count("`zone preview` answers against a provider on the wire", said.status === 0,
    "exit " + said.status + " " + said.both.slice(0, 300));
  var preview = answerOf("zone preview", said);

  count("and it proposes one change per record this server expects to be published",
    preview.changes.length === listed.length,
    preview.changes.length + " change(s) against " + listed.length + " record(s)");

  count("every change is a create, because the zone holds none of them yet",
    preview.changes.every(function (c) { return c.action === "create"; }),
    preview.changes.map(function (c) { return c.action; }).join(", "));

  // The value, not the zone file line. A records reader that handed over
  // the rendered `name. IN TXT (...)` line would produce a preview that
  // looks entirely reasonable and publishes a record no verifier reads.
  var wanted = {};
  listed.forEach(function (record) { wanted[record.dnsName] = record.dnsTxtValue; });
  var mismatched = preview.changes.filter(function (change) {
    return wanted[change.name] !== change.after.content;
  });
  count("and each one carries the record's value rather than the zone-file line that " +
    "renders it", mismatched.length === 0,
    mismatched.map(function (c) { return c.name + " -> " + c.after.content.slice(0, 60); })
      .join(" ; "));

  count("the diff an operator reads names each address",
    preview.changes.every(function (c) { return preview.diff.indexOf(c.name) !== -1; }),
    preview.diff.slice(0, 300));

  count("and nothing was written to reach that answer", fake.writes().length === 0,
    fake.writes().length + " write(s)");
  return listed;
}

// The other reading verb, against a zone that holds none of the records.
// This is the state an operator is in right after `dkim rotate`, and the
// answer has to name the provider rather than the resolver: a record the
// provider does not hold is not a propagation delay.
async function verifyReportsRecordsTheProviderDoesNotHold(run) {
  var said = await run(["zone", "verify", DOMAIN, "--reason", "confirming the DKIM records",
    "--json"]);
  var verdict = answerOf("zone verify", said);
  count("`zone verify` reports a zone holding none of the records as not ok",
    verdict.ok === false, JSON.stringify(verdict).slice(0, 200));
  count("and every check names the provider as the side that is missing it, rather than " +
    "reporting a resolver that has not caught up",
    verdict.checks.length > 0 &&
    verdict.checks.every(function (c) { return c.verdict === "provider-missing"; }),
    verdict.checks.map(function (c) { return c.verdict; }).join(", "));
}

// The same verb once the provider holds them. The resolver is pointed at
// a closed port for this whole run, so what separates this from the case
// above is the provider read alone, and the resolver's own answer lands
// on the verdict that says it could not be read.
async function verifySeparatesTheProviderFromTheResolver(run, fake, listed) {
  listed.forEach(function (record, index) {
    fake.state.records.push({
      id:      "seeded" + index + "0000000000000000000000000",
      type:    "TXT",
      name:    record.dnsName,
      content: record.dnsTxtValue,
      ttl:     300,
    });
  });

  var settled = answerOf("zone preview after seeding",
    await run(["zone", "preview", DOMAIN, "--reason", "checking after publication", "--json"]));
  count("a zone that already holds every record previews as no change",
    settled.changes.length === 0, settled.diff);

  var verdict = answerOf("zone verify after seeding",
    await run(["zone", "verify", DOMAIN, "--reason", "confirming after publication",
      "--json"]));
  count("and verify no longer reports the provider as missing them",
    verdict.checks.every(function (c) { return c.verdict !== "provider-missing"; }),
    verdict.checks.map(function (c) { return c.verdict; }).join(", "));
  count("what it reports instead is that the resolver could not be read, which is the " +
    "reading a dead resolver produces rather than a record that disagrees",
    verdict.checks.length > 0 &&
    verdict.checks.every(function (c) { return c.verdict === "resolver-unread"; }),
    verdict.checks.map(function (c) { return c.verdict + ":" + c.resolverError; }).join(", "));
  count("so the run is not ok, because a check that could not be completed is not a check " +
    "that passed", verdict.ok === false, String(verdict.ok));
  count("and each check reports what the provider holds, so an operator can see the record " +
    "is there while the resolver cannot be asked",
    verdict.checks.every(function (c) { return c.providerValues.length > 0; }),
    JSON.stringify(verdict.checks.map(function (c) { return c.providerValues.length; })));
}

// The credential itself, over the wire this time. The gate suite proves
// the token reaches the authorization header and nothing else in
// process; what is asked here is that the sealed value on the volume is
// the one a spawned run authenticates with, which is the join a unit
// check cannot see.
function theSealedCredentialOnTheVolumeIsWhatAuthenticates(fake) {
  var authorized = fake.state.requests.filter(function (r) {
    return typeof r.headers.authorization === "string";
  });
  count("every request the provider received carried an authorization header",
    authorized.length === fake.state.requests.length,
    authorized.length + " of " + fake.state.requests.length);
  count("and it carried the token that was sealed onto the volume",
    authorized.length > 0 &&
    authorized.every(function (r) { return r.headers.authorization === "Bearer " + TOKEN; }),
    authorized.length === 0 ? "no request" : String(authorized[0].headers.authorization)
      .slice(0, 12) + "...");
  count("the token reached no other header, no address and no body",
    fake.state.requests.every(function (r) {
      if (String(r.body || "").indexOf(TOKEN) !== -1) return false;
      if (String(r.path || "").indexOf(TOKEN) !== -1) return false;
      return Object.keys(r.headers).every(function (name) {
        return name === "authorization" || String(r.headers[name]).indexOf(TOKEN) === -1;
      });
    }), fake.state.requests.length + " request(s) scanned");
  count("and no verb on this command line wrote a record", fake.writes().length === 0,
    fake.writes().length + " write(s)");
}

// A provider whose refusal quotes the credential it was handed. The
// refusal reaches the operator's terminal as the provider worded it, so
// this reads the transcript rather than the module.
async function aCredentialTheProviderQuotesBackIsNotPrinted(run, fake) {
  fake.state.onRequest = function (request) {
    var header = String(request.headers.authorization || "");
    return { status: 401, body: standIn.fail(10000,
      "Invalid API Token " + header.slice("Bearer ".length)) };
  };
  try {
    var said = await run(["zone", "verify-token", "--reason", "checking the credential"]);
    count("`zone verify-token` reports a provider that refused the credential",
      said.status !== 0, "exit " + said.status + " " + said.both.slice(0, 300));
    count("and the credential the provider quoted back is not in what it prints",
      said.both.indexOf(TOKEN) === -1, said.both.slice(0, 400));
  } finally {
    fake.state.onRequest = null;
  }
}

// A stored value carrying display controls, read back by `zone preview`
// and printed to a terminal. A right-to-left override reorders the line
// the operator reads, and a control sequence introducer is acted on by a
// terminal rather than shown.
async function thePreviewPrintsAStoredValueAsVisibleText(run, fake, listed) {
  var OVERRIDE   = String.fromCharCode(0x202e);
  var INTRODUCER = String.fromCharCode(0x9b);
  var held = fake.state.records.filter(function (r) { return r.name === listed[0].dnsName; })[0];
  var original = held.content;
  held.content = "v=DKIM1; k=ed25519; p=" + OVERRIDE + "reversed" + INTRODUCER + "2J";
  try {
    var said = await run(["zone", "preview", DOMAIN, "--reason", "reading a stored value"]);
    count("`zone preview` proposes replacing the stored value", said.status === 0 &&
      said.both.indexOf("holding") !== -1, "exit " + said.status + " " + said.both.slice(0, 300));
    count("and prints it with neither control character in the transcript",
      said.both.indexOf(OVERRIDE) === -1 && said.both.indexOf(INTRODUCER) === -1,
      said.both.slice(0, 400));
    count("while the rest of the value is still shown", said.both.indexOf("reversed") !== -1,
      said.both.slice(0, 400));
  } finally {
    held.content = original;
  }
}

// A sealed DKIM private key copied over the sealed credential. Both are
// sealed by the same volume, so the answer an operator needs is that the
// file at the credential's path is not a provider token, rather than a
// report that the provider could not be reached.
async function aSealedKeyInPlaceOfTheCredentialIsNamedAsTheCredential(run, fake, dataDir) {
  var keysDir = nodePath.join(dataDir, "keys");
  var tokenAt = nodePath.join(keysDir, "zone-token.sealed");
  var keyName = nodeFs.readdirSync(keysDir).filter(function (name) {
    return name !== "zone-token.sealed" && /\.sealed$/.test(name);
  })[0];
  count("the volume holds a sealed signing key to put in the credential's place",
    typeof keyName === "string", nodeFs.readdirSync(keysDir).join(", "));
  var original = nodeFs.readFileSync(tokenAt);
  nodeFs.writeFileSync(tokenAt, nodeFs.readFileSync(nodePath.join(keysDir, keyName)));
  var before = fake.state.requests.length;
  try {
    var said = await run(["zone", "verify-token", "--reason", "checking the credential"]);
    count("`zone verify-token` refuses a signing key sealed where the credential belongs",
      said.status !== 0, "exit " + said.status + " " + said.both.slice(0, 300));
    count("and names the credential as the problem rather than the provider",
      said.both.indexOf("has not been shown to be bad") === -1 &&
      said.both.indexOf("zone token set") !== -1, said.both.slice(0, 400));
    count("and no request carried it to the provider", fake.state.requests.length === before,
      (fake.state.requests.length - before) + " request(s)");
  } finally {
    nodeFs.writeFileSync(tokenAt, original);
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("zone-cli-wire");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  var fake = await standIn.start();
  try {
    // The trust an in-process caller passes as an agent, in the one form
    // a child process can be given.
    var caPath = nodePath.join(root, "provider-ca.pem");
    nodeFs.writeFileSync(caPath, fake.caPem, "utf8");

    var tokenPath = nodePath.join(root, "provider-token");
    nodeFs.writeFileSync(tokenPath, TOKEN + "\n", "utf8");

    // The non-blocking runner, and it has to be. The stand-in provider
    // answers on a socket in THIS process, so a spawn that stopped the
    // event loop would leave the child waiting on a reply the parent
    // cannot send until the child exits.
    var runCli = cliHelper.createAsync({
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
      // The resolver goes to a closed port for the whole run, so `verify`
      // asks a resolver and gets an answer this file can assert on rather
      // than one the network decides.
      execArgv: ["--require", dnsQuiet.PRELOAD],
      env: {
        [dnsQuiet.ARMED_VAR]:                    "1",
        BLAMEPOST_ZONE_PROVIDER:                 "cloudflare",
        BLAMEPOST_ZONE_ENDPOINT:                 fake.baseUrl,
        BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT:  "1",
        NODE_EXTRA_CA_CERTS:                     caPath,
      },
    });

    var added = await runCli(["domain", "add", DOMAIN]);
    count("the fixture hosts a domain with a freshly minted signing pair",
      added.status === 0, "exit " + added.status + " " + added.both.slice(0, 300));

    var sealed = await runCli(["zone", "token", "set", "--token-file", tokenPath,
      "--reason", "installing the provider credential"]);
    count("and the provider credential is sealed onto its volume", sealed.status === 0,
      "exit " + sealed.status + " " + sealed.both.slice(0, 300));

    var listed = await previewProposesTheRecordsThisServerExpects(runCli, fake);
    await verifyReportsRecordsTheProviderDoesNotHold(runCli);
    await verifySeparatesTheProviderFromTheResolver(runCli, fake, listed);
    theSealedCredentialOnTheVolumeIsWhatAuthenticates(fake);

    // Three cases that each restore what they change, so one failing does
    // not decide what the next one meets. Each runs and reports, and the
    // run fails afterwards naming every one that did not hold.
    var independent = [
      function () { return aCredentialTheProviderQuotesBackIsNotPrinted(runCli, fake); },
      function () { return thePreviewPrintsAStoredValueAsVisibleText(runCli, fake, listed); },
      function () {
        return aSealedKeyInPlaceOfTheCredentialIsNamedAsTheCredential(runCli, fake, dataDir);
      },
    ];
    var failed = [];
    for (var i = 0; i < independent.length; i += 1) {
      try {
        await independent[i]();
      } catch (e) {
        failed.push(helpers.formatErr(e));
        console.log("  " + helpers.formatErr(e));
      }
    }
    if (failed.length > 0) {
      throw new Error(failed.length + " independent case(s) failed");
    }

    return helpers.getChecks();
  } finally {
    fake.close();
    helpers.removeTempDir(root);
  }
}

module.exports = { name: "zone-cli-wire", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
