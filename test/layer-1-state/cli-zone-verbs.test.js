// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * The `zone` verbs, driven through the shipped binary.
 *
 * Two things are being measured, and neither is visible from the module
 * that does the work.
 *
 * The credential verbs have to write. `zone token set` seals a provider
 * API token onto the data volume and `zone token clear` erases it, and
 * both record a reason. A verb that took a reason and did not record it,
 * or that reported a credential installed without one reaching disk,
 * reads exactly like one that worked. So the file on the volume is
 * opened afterwards and the audit trail is read back.
 *
 * The reading verbs have to refuse for the right reason. `zone preview`
 * and `zone verify` are the two commands an operator runs when a zone is
 * not what they expected, so a refusal that names the wrong thing sends
 * them to fix something that is already correct. With no provider named
 * they say so and reach nothing.
 *
 * `zone verify-token` is the one verb here that has to hear from a
 * provider to answer at all, so it is driven against the stand-in the
 * other provider cases use. What it measures is the three endings kept
 * apart: a token the provider calls active, a token it refuses, and a
 * provider that could not be reached. The third is the one worth
 * pinning, because a token nothing managed to ask about must not be
 * reported as a token that failed.
 *
 * `zone allowlist` reports the reach of the gate every write goes
 * through. What is measured is that the list comes off the gate rather
 * than off a copy of it, and the two properties that make it usable
 * during an incident: it asks the provider nothing, and it opens no data
 * volume, so a running server holding one does not stand between an
 * operator and the answer. The second is measured against a held volume.
 *
 * Every other case either refuses before a provider client exists or
 * stops on a domain this server does not host.
 *
 * The raw token never appears in this file's assertions except as the
 * value that must NOT be on disk after sealing, which is the one thing
 * worth asserting about it.
 *
 * Run standalone: node test/layer-1-state/cli-zone-verbs.test.js
 */

var nodeFs   = require("node:fs");
var nodePath = require("node:path");

var helpers     = require("../helpers");
var cliHelper   = require("../helpers/cli");
var dnsProvider = require("../helpers/dns-provider");
var b           = require("../../lib/vendor/blamejs");
var config      = require("../../lib/config");
var store       = require("../../lib/store");

var count = cliHelper.count;

var HOSTNAME = "mx.example.com";
var DOMAIN   = "example.com";

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";

// A credential shaped like a provider's, which exists in this file for
// one purpose: to be absent from the volume after it has been sealed.
var TOKEN = "fixtureDnsTokennC8vF3jH6dL1sG0aY";

// Where the sealed credential lands. Spelled here rather than read from
// the module, because this is the promise the operator guide makes and a
// check that asked the module where it put the file would agree with the
// module about a path the document does not name.
var SEALED_AT = nodePath.join("keys", "zone-token.sealed");

function tokenFileAt(root, name, body) {
  var file = nodePath.join(root, name);
  nodeFs.writeFileSync(file, body, "utf8");
  return file;
}

// ---- the reason every verb here records ------------------------------------

// Each verb takes a reason and each has to refuse without one. The
// refusal is the operator's only notice that the row would have answered
// nothing, and a verb that quietly accepted an absent reason writes a row
// naming a credential change with no account of why it happened.
function everyVerbRefusesWithoutARecordedReason(run) {
  var lines = [
    { label: "zone preview", argv: ["zone", "preview", DOMAIN] },
    { label: "zone verify",  argv: ["zone", "verify", DOMAIN] },
    { label: "zone verify-token", argv: ["zone", "verify-token"] },
    { label: "zone token set",
      argv: ["zone", "token", "set", "--token-file", "no-such-token-file"] },
    { label: "zone token clear", argv: ["zone", "token", "clear", "--confirm"] },
  ];
  lines.forEach(function (entry) {
    var said = run(entry.argv);
    count("`" + entry.label + "` refuses without --reason rather than recording a change " +
      "nobody can account for", said.status === 2, "exit " + said.status + " " +
      said.both.slice(0, 160));
    count("and the refusal names the flag it wants",
      /give --reason/.test(said.both), said.both.slice(0, 200));
  });
}

// ---- the provider that is not named ----------------------------------------

// The shipped default, and the state an operator is in before they have
// decided anything. Both reads have to say which setting turns the writer
// on rather than reporting a zone problem.
function theReadingVerbsSayWhenNoProviderIsNamed(run) {
  // `verify-token` takes no domain, so the three are driven from the
  // argument each one wants rather than from a shared positional. All
  // three give the same sentence, which is the point: an operator who
  // reads a different refusal from each has two settings to look for and
  // one to find.
  var lines = [
    { label: "preview",      argv: ["zone", "preview", DOMAIN] },
    { label: "verify",       argv: ["zone", "verify", DOMAIN] },
    { label: "verify-token", argv: ["zone", "verify-token"] },
  ];
  lines.forEach(function (entry) {
    var said = run(entry.argv.concat(["--reason", "checking the records"]));
    count("`zone " + entry.label + "` refuses while no provider is named",
      said.status === 2, "exit " + said.status + " " + said.both.slice(0, 160));
    count("and names the setting that turns the writer on",
      said.both.indexOf("BLAMEPOST_ZONE_PROVIDER") !== -1, said.both.slice(0, 240));
    count("and names the command that prints the records to publish by hand instead",
      said.both.indexOf("blamepost dkim records") !== -1, said.both.slice(0, 240));
  });

  // `allowlist` reads nothing at the provider, so it takes no reason and
  // is driven without one. It still meets the same refusal, because a
  // configuration naming no provider has no gate to report the reach of:
  // the records stay the operator's to publish, and an allowlist printed
  // over that would describe writes this server will never make.
  var noGate = run(["zone", "allowlist", DOMAIN]);
  count("`zone allowlist` refuses while no provider is named", noGate.status === 2,
    "exit " + noGate.status + " " + noGate.both.slice(0, 160));
  count("and gives the same sentence as the other three, so there is one setting to find",
    noGate.both.indexOf("BLAMEPOST_ZONE_PROVIDER") !== -1 &&
      noGate.both.indexOf("blamepost dkim records") !== -1, noGate.both.slice(0, 300));

  var withReason = run(["zone", "allowlist", DOMAIN, "--reason", "checking the records"]);
  count("and a reason on it is refused as a flag the verb does not take rather than " +
    "accepted and dropped",
    withReason.status === 2 && /does not take|unknown flag/.test(withReason.both),
    "exit " + withReason.status + " " + withReason.both.slice(0, 240));
}

// ---- the credential, sealed onto the volume --------------------------------

// The file the token is read from, checked before anything is sealed. A
// path that names a directory or an empty file is a typo, and the answer
// has to arrive before a credential-shaped value is written anywhere.
function theTokenFileIsCheckedBeforeAnythingIsSealed(run, root, dataDir) {
  var missing = run(["zone", "token", "set", "--reason", "installing the credential"]);
  count("`zone token set` refuses without --token-file", missing.status === 2,
    "exit " + missing.status + " " + missing.both.slice(0, 160));
  count("and says why the token is not taken on the command line",
    missing.both.indexOf("process list") !== -1, missing.both.slice(0, 240));

  var absent = run(["zone", "token", "set", "--token-file",
    nodePath.join(root, "no-such-token"), "--reason", "installing the credential"]);
  count("a token file that is not there is refused, naming the path",
    absent.status === 2 && absent.both.indexOf("no-such-token") !== -1,
    absent.both.slice(0, 240));

  var empty = run(["zone", "token", "set", "--token-file",
    tokenFileAt(root, "empty-token", "\n"), "--reason", "installing the credential"]);
  count("an empty token file is refused rather than sealed", empty.status === 2,
    empty.both.slice(0, 240));

  var asDirectory = nodePath.join(root, "token-directory");
  nodeFs.mkdirSync(asDirectory, { recursive: true });
  var onDirectory = run(["zone", "token", "set", "--token-file", asDirectory,
    "--reason", "installing the credential"]);
  count("a directory in place of the token file is refused", onDirectory.status === 2,
    onDirectory.both.slice(0, 240));

  count("and none of those refusals left a sealed credential on the volume",
    !nodeFs.existsSync(nodePath.join(dataDir, SEALED_AT)),
    nodePath.join(dataDir, SEALED_AT));
}

// The verb that installs the credential, and the two facts about it that
// matter: the raw token is not what reaches disk, and the sealed value is
// under the name the guide tells an operator to back up and destroy.
function settingTheTokenSealsItOntoTheVolume(run, root, dataDir) {
  var source = tokenFileAt(root, "provider-token", TOKEN + "\n");
  var said = run(["zone", "token", "set", "--token-file", source,
    "--reason", "installing the provider credential"]);
  count("`zone token set` installs the credential", said.status === 0,
    "exit " + said.status + " " + said.both.slice(0, 240));

  var sealedPath = nodePath.join(dataDir, SEALED_AT);
  count("and the sealed value is at the path the operator guide names",
    nodeFs.existsSync(sealedPath), sealedPath);

  var onDisk = nodeFs.readFileSync(sealedPath, "utf8");
  count("what reaches disk carries the vault's authenticated-data seal",
    onDisk.indexOf(b.vault.aad.AAD_PREFIX) === 0, onDisk.slice(0, 24));
  count("and the token itself is not in the file, which is the whole point of sealing it",
    onDisk.indexOf(TOKEN) === -1, onDisk.length + " sealed byte(s)");

  count("the operator is told to delete the file the token was read from, which still " +
    "holds it in the clear", said.both.indexOf(source) !== -1, said.both.slice(0, 400));

  // The provider is still at its default here, so a credential installed
  // now reaches nothing. Saying so is the difference between an operator
  // who has one step left and one who believes they are finished.
  count("and told that nothing reads it while no provider is named",
    said.both.indexOf("BLAMEPOST_ZONE_PROVIDER") !== -1, said.both.slice(0, 400));
}

// The trail. A verb that takes a reason and records nothing is the shape
// this project names as its most frequent defect, so the row is read back
// through the verb an operator would use.
function theCredentialChangeIsOnTheAuditTrail(run, action, reason) {
  var read = run(["audit", "read", "--action", action, "--limit", "5", "--json"]);
  count("`" + action + "` is on the audit trail", read.status === 0 &&
    read.stdout.indexOf(action) !== -1, "exit " + read.status + " " +
    read.stdout.slice(0, 300));
  count("and the row carries the reason the operator gave",
    read.stdout.indexOf(reason) !== -1, read.stdout.slice(0, 400));
  count("and carries no credential",
    read.stdout.indexOf(TOKEN) === -1, "checked " + read.stdout.length + " character(s)");
}

// ---- the credential, asked of the provider ---------------------------------

// The verb that answers whether the sealed credential still works.
//
// It is driven with `createAsync` rather than the blocking runner every
// other case here uses. The stand-in answers a socket in THIS process,
// and a spawn that stops this event loop leaves the child asking and the
// parent unable to reply. A spawned binary also cannot be handed an
// agent, so the certificate authority goes to a file named in the
// child's NODE_EXTRA_CA_CERTS.
async function theTokenIsCheckedAgainstTheProvider(root, base) {
  var provider = await dnsProvider.start();
  var caFile = nodePath.join(root, "provider-ca.pem");
  nodeFs.writeFileSync(caFile, provider.caPem, "utf8");

  var run = cliHelper.createAsync(Object.assign({}, base, {
    env: {
      BLAMEPOST_ZONE_PROVIDER:                "cloudflare",
      BLAMEPOST_ZONE_ENDPOINT:                provider.baseUrl,
      BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT: "1",
      NODE_EXTRA_CA_CERTS:                    caFile,
    },
    ceilingMs: 60000,
  }));
  var asked = ["zone", "verify-token", "--reason", "checking the provider credential"];

  try {
    var live = await run(asked);
    count("`zone verify-token` reports a token the provider calls active",
      live.status === 0, "exit " + live.status + " " + live.both.slice(0, 300));
    count("and names the token the provider answered about, so two credentials can be " +
      "told apart", live.both.indexOf("tok0000") !== -1, live.both.slice(0, 300));
    count("and says an active token is not one shown to hold the scope to write, which is " +
      "the reading that would otherwise be taken from this answer",
      /scope/i.test(live.both), live.both.slice(0, 400));

    var reached = provider.state.requests.filter(function (entry) {
      return entry.path.indexOf("/user/tokens/verify") !== -1;
    });
    count("it asked the provider's token endpoint rather than reading a zone",
      reached.length === 1, reached.length + " request(s) to the token endpoint");
    count("and wrote nothing at the provider", provider.writes().length === 0,
      provider.writes().length + " write(s)");

    // The provider answering that the credential is not live. This is the
    // state a revoked token is in, and the verb exists so it is reported
    // as itself rather than as whatever the first record call fails with.
    provider.state.mode = "inactive";
    var refused = await run(asked);
    count("a token the provider reports as not active is refused",
      refused.status === 1, "exit " + refused.status + " " + refused.both.slice(0, 300));
    count("and the refusal carries the status the provider gave",
      refused.both.indexOf("disabled") !== -1, refused.both.slice(0, 300));
    count("and tells the operator to issue a replacement and reseal it",
      /reseal|replacement/i.test(refused.both), refused.both.slice(0, 300));

    // A token the provider does not recognize at all, which arrives as an
    // unauthorized reply rather than as a status field. Both endings are
    // the same verdict to an operator, so both have to reach it.
    provider.state.mode = "unauthorized";
    var unknown = await run(asked);
    count("a token the provider does not recognize is refused the same way",
      unknown.status === 1, "exit " + unknown.status + " " + unknown.both.slice(0, 300));

    // The ending that must not read as a bad credential. Nothing here
    // heard the provider say anything, so the token is unjudged.
    provider.state.mode = null;
    provider.close();
    var unreachable = await run(asked);
    count("a provider that cannot be reached is a refusal rather than a hang",
      unreachable.status === 1 && unreachable.ceilingHit !== true,
      "exit " + unreachable.status + " ceiling " + unreachable.ceilingHit);
    count("and it says the token has not been shown to be bad, so an operator does not " +
      "reissue a credential that was never the problem",
      unreachable.both.indexOf("has not been shown to be bad") !== -1,
      unreachable.both.slice(0, 400));
  } finally {
    provider.close();
  }
}

// Erasing it. The confirmation is required because the verb takes away
// this server's ability to edit any zone, and because erasing the file
// revokes nothing: a copy in a backup bundle taken while it was here is
// still live.
function clearingTheTokenTakesConfirmationAndErasesTheFile(run, dataDir) {
  var unconfirmed = run(["zone", "token", "clear", "--reason", "rotating the credential"]);
  count("`zone token clear` refuses without --confirm", unconfirmed.status === 2,
    "exit " + unconfirmed.status + " " + unconfirmed.both.slice(0, 200));
  count("and says that erasing it here revokes nothing at the provider",
    /revoke/i.test(unconfirmed.both), unconfirmed.both.slice(0, 300));

  var sealedPath = nodePath.join(dataDir, SEALED_AT);
  count("and the credential is still on the volume after that refusal",
    nodeFs.existsSync(sealedPath), sealedPath);

  var cleared = run(["zone", "token", "clear", "--reason", "rotating the credential",
    "--confirm"]);
  count("with --confirm the credential is erased", cleared.status === 0 &&
    !nodeFs.existsSync(sealedPath), "exit " + cleared.status + " " +
    cleared.both.slice(0, 240));
  count("and the operator is told to revoke it at the provider as well",
    /revoke/i.test(cleared.both), cleared.both.slice(0, 300));

  // Again, on a volume that now holds none. Reporting a removal that did
  // not happen would tell an operator a credential is gone when it never
  // was there, and the same words would cover the case where it is
  // somewhere else entirely.
  var again = run(["zone", "token", "clear", "--reason", "confirming it is gone",
    "--confirm"]);
  count("clearing a volume that holds no credential says so rather than reporting a removal",
    again.status === 0 && again.both.indexOf("held no sealed provider token") !== -1,
    again.both.slice(0, 300));
}

// ---- the writer that is named but has nothing to write ---------------------

// With a provider named and a credential installed, the refusals that
// still come before any provider request. This is the path that proves
// the verb reaches the store and stops on what it finds there, rather
// than the earlier refusal standing in for every case.
function aNamedProviderStopsOnADomainThisServerDoesNotHost(runNamed) {
  var said = runNamed(["zone", "preview", "nothosted.example",
    "--reason", "checking a domain that is not here"]);
  count("`zone preview` for a domain this server does not host refuses on that",
    said.status === 2 && said.both.indexOf("does not host") !== -1,
    "exit " + said.status + " " + said.both.slice(0, 240));

  var malformed = runNamed(["zone", "preview", "not a domain",
    "--reason", "checking a name that is not one"]);
  count("and a name that is not a domain is refused as an argument problem",
    malformed.status === 2 && malformed.both.indexOf("usable domain name") !== -1,
    "exit " + malformed.status + " " + malformed.both.slice(0, 240));

  var noSelector = runNamed(["zone", "preview", DOMAIN,
    "--reason", "checking a hosted domain with no keys"]);
  count("a hosted domain with no publishable selector says there is nothing to compare " +
    "rather than reaching the provider with an empty set",
    noSelector.status !== 0 && noSelector.both.indexOf("blamepost dkim generate") !== -1,
    "exit " + noSelector.status + " " + noSelector.both.slice(0, 300));
}

// ---- what the gate says it will write --------------------------------------

// The reach an operator is deciding whether to trust a provider token
// with. It is read off the gate every write goes through rather than off
// the source, so the list is what will actually be enforced, and a rule
// added or removed without this answer moving would be a list describing
// a gate that is no longer there.
//
// Three properties, and the third is the one that makes it usable during
// an incident. It reaches no provider, so nothing here has to be running.
// It opens no data volume, so it answers while the server holds one. And
// it names the addresses rather than only the record types, because TXT
// covers both the record this server writes and every record in the zone
// it must not touch.
function allowlistReportsTheGatesOwnReach(runNamed, provider) {
  var before = provider === null ? 0 : provider.state.requests.length;

  var said = runNamed(["zone", "allowlist", DOMAIN]);
  count("`zone allowlist` answers", said.status === 0,
    "exit " + said.status + " " + said.both.slice(0, 400));
  count("and names the domain it is reporting about",
    said.stdout.indexOf(DOMAIN) !== -1, said.stdout.slice(0, 300));
  count("and names the ceiling on one change set",
    /one change set:\s+at most \d+ change\(s\)/.test(said.stdout), said.stdout.slice(0, 600));
  count("and says whether the mail exchanger at the apex is one it may replace",
    /MX writes:\s+off/.test(said.stdout), said.stdout.slice(0, 600));

  var reach;
  try { reach = JSON.parse(runNamed(["zone", "allowlist", DOMAIN, "--json"]).stdout); }
  catch (_e) { reach = null; }
  count("the structured answer carries the record types the gate accepts",
    reach !== null && Array.isArray(reach.types) && reach.types.indexOf("TXT") !== -1,
    JSON.stringify(reach && reach.types));
  count("and one entry per address the gate is permitted at, each described in words",
    reach !== null && Array.isArray(reach.addresses) && reach.addresses.length >= 7 &&
      reach.addresses.every(function (entry) {
        return typeof entry.type === "string" && typeof entry.describes === "string" &&
          entry.describes.length > 0;
      }),
    JSON.stringify(reach && reach.addresses).slice(0, 400));
  count("and names the DKIM selector record, which is the one this server holds the only " +
    "authoritative value for",
    reach !== null && reach.addresses.some(function (entry) {
      return /DKIM selector/.test(entry.describes);
    }), JSON.stringify(reach && reach.addresses).slice(0, 400));
  count("and the MX rule is absent while MX writes are off, rather than listed and refused",
    reach !== null && reach.allowMxWrites === false &&
      !reach.addresses.some(function (entry) { return entry.type === "MX"; }),
    JSON.stringify(reach && reach.allowMxWrites));

  if (provider !== null) {
    count("and it asked the provider nothing, so it answers with the zone unreachable",
      provider.state.requests.length === before,
      (provider.state.requests.length - before) + " request(s)");
  }

  var malformed = runNamed(["zone", "allowlist", "not a domain"]);
  count("a name that is not a domain is refused as an argument problem",
    malformed.status === 2 && malformed.both.indexOf("usable domain name") !== -1,
    "exit " + malformed.status + " " + malformed.both.slice(0, 240));

  // A domain nothing hosts still answers. The reach is a property of the
  // gate rather than of a row, so refusing here would withhold the answer
  // from an operator deciding whether to host the domain at all.
  var unhosted = runNamed(["zone", "allowlist", "nothosted.example"]);
  count("a domain this server does not host is still reported on, because the reach is the " +
    "gate's rather than a row's", unhosted.status === 0,
    "exit " + unhosted.status + " " + unhosted.both.slice(0, 300));
}

// The property that makes it usable while a zone is failing: it opens no
// data volume, so the running server holding one does not stand between
// an operator and the answer. Measured against a held volume rather than
// assumed, because a verb that had started opening one would look exactly
// like this file passing.
async function allowlistAnswersWhileTheServerHoldsTheVolume(runNamed, cfg, workDir) {
  // The open below happens in THIS process, and an encrypted volume is
  // decrypted into a memory backed directory. Every other case here
  // spawns the binary, which is handed one; this is the only one that
  // needs the variable set where the test itself runs. It is restored
  // afterwards so nothing later in the run inherits it.
  var had   = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var prior = had ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;
  var held = null;
  try {
    held = await store.open(cfg);
    var said = runNamed(["zone", "allowlist", DOMAIN]);
    count("`zone allowlist` answers while the server holds the volume",
      said.status === 0, "exit " + said.status + " " + said.both.slice(0, 300));
    count("and says nothing about a copy, because it read no volume to take one of",
      !/snapshot/i.test(said.both), said.both.slice(0, 300));
  } finally {
    if (held !== null) held.close();
    if (had) process.env.BLAMEJS_TMPDIR = prior;
    else delete process.env.BLAMEJS_TMPDIR;
  }
}

// ---- runner ----------------------------------------------------------------

async function run() {
  var root    = helpers.tempDir("cli-zone-verbs");
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(dataDir, { recursive: true });
  nodeFs.mkdirSync(workDir, { recursive: true });

  try {
    var base = {
      dataDir:         dataDir,
      workDir:         workDir,
      hostname:        HOSTNAME,
      vaultPassphrase: VAULT_PASSPHRASE,
    };
    var plain = cliHelper.create(base);

    everyVerbRefusesWithoutARecordedReason(plain);
    theReadingVerbsSayWhenNoProviderIsNamed(plain);
    theTokenFileIsCheckedBeforeAnythingIsSealed(plain, root, dataDir);
    settingTheTokenSealsItOntoTheVolume(plain, root, dataDir);
    theCredentialChangeIsOnTheAuditTrail(plain, "blamepost.dns.credential_set",
      "installing the provider credential");

    // A second runner, differing only in the provider it names. The
    // credential is already on the volume, so this is the configuration
    // an operator ends up with, and the refusals below are the ones that
    // come after the writer exists.
    var named = cliHelper.create(Object.assign({}, base, {
      env: { BLAMEPOST_ZONE_PROVIDER: "cloudflare" },
    }));
    var added = named(["domain", "add", DOMAIN]);
    count("the fixture hosts a domain to ask about", added.status === 0,
      "exit " + added.status + " " + added.both.slice(0, 240));
    // Every selector minted with the domain is retired, so the domain is
    // hosted and has nothing publishable. `dkim retire` names the pair
    // and takes both halves, so one call clears the domain.
    var retired = named(["dkim", "retire", "--domain", DOMAIN, "--selector",
      _firstSelector(named, DOMAIN)]);
    count("and its selectors are retired, so it is a hosted domain with nothing to publish",
      retired.status === 0, "exit " + retired.status + " " + retired.both.slice(0, 240));
    var swept = named(["dkim", "sweep", "--domain", DOMAIN, "--immediate"]);
    count("and the retired records are withdrawn, which is what leaves the set empty",
      swept.status === 0, "exit " + swept.status + " " + swept.both.slice(0, 240));

    aNamedProviderStopsOnADomainThisServerDoesNotHost(named);
    allowlistReportsTheGatesOwnReach(named, null);
    await allowlistAnswersWhileTheServerHoldsTheVolume(named, config.load({
      env: {
        BLAMEPOST_HOSTNAME:         HOSTNAME,
        BLAMEPOST_DATA_DIR:         dataDir,
        BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
      },
      cwd: root,
    }), workDir);

    // Before the clear below, which takes the credential off the volume:
    // this is the only case here that needs one to be there.
    await theTokenIsCheckedAgainstTheProvider(root, base);
    theCredentialChangeIsOnTheAuditTrail(plain, "blamepost.dns.credential_verified",
      "checking the provider credential");

    clearingTheTokenTakesConfirmationAndErasesTheFile(plain, dataDir);
    theCredentialChangeIsOnTheAuditTrail(plain, "blamepost.dns.credential_cleared",
      "rotating the credential");

    return helpers.getChecks();
  } finally {
    helpers.removeTempDir(root);
  }
}

// The selector `domain add` minted, read back off the binary rather than
// guessed. The default name carries the month, so a name written here
// would be correct until the month turned.
function _firstSelector(run, domain) {
  var listed = run(["dkim", "list", domain, "--json"]);
  var rows;
  try { rows = JSON.parse(listed.stdout); } catch (_e) { rows = []; }
  for (var i = 0; i < rows.length; i += 1) {
    if (rows[i] && rows[i].algorithm === "ed25519") return rows[i].selector;
  }
  return "no-selector-found";
}

module.exports = { name: "cli-zone-verbs", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout.
if (require.main === module) {
  run().then(function (total) {
    console.log("CHECKS " + total);
  }).catch(function (e) {
    console.error(helpers.formatErr(e));
    process.exitCode = 1;
  });
}
