// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * Configuration and the identity store, driven the way the server
 * drives them: a real temporary data directory, a real vault, a real
 * encrypted database, real Argon2id hashing and real sealed columns.
 * Nothing is stubbed and no branch is skipped for the test, because a
 * suite that skips the sealing has not tested the thing that ships.
 *
 * Run standalone: node test/layer-1-state/store.test.js
 */

var nodeFs   = require("node:fs");
var nodeOs   = require("node:os");
var nodePath = require("node:path");

var helpers = require("../helpers");
var certs   = require("../helpers/certs");
var b      = require("../../lib/vendor/blamejs");
var config = require("../../lib/config");
var store  = require("../../lib/store");

// The listener composition, so a configured port can be followed all
// the way to the subsystem that reads it rather than only as far as the
// loaded object.
var listenerModule = require("../../lib/mail/listeners");

// The shared assertion that quotes the value which produced the verdict.
// It used to be a private function here, under a name the helpers
// already export for a function that takes no value at all, so one name
// meant two assertions with two ideas of how much of a failure to print.
var count = helpers.count;

// Assert a call refuses with one stable error code. Both halves matter:
// a refusal under the wrong code is a contract change a caller branching
// on the code would not survive.
async function refuses(label, code, fn) {
  var thrown = null;
  try {
    await fn();
  } catch (e) {
    thrown = e;
  }
  count(label,
    thrown !== null && thrown.code === code,
    thrown === null ? "nothing was thrown" : thrown.code + ": " + thrown.message);
}

// The same assertion, plus the fragments the message has to carry. A
// boot refusal that does not name the setting, the route into it and
// the value that failed sends an operator to read source, which is the
// failure the loader exists to avoid.
async function refusesNaming(label, code, needles, fn) {
  var thrown = null;
  try {
    await fn();
  } catch (e) {
    thrown = e;
  }
  var message = thrown === null ? "" : String(thrown.message);
  var missing = needles.filter(function (needle) { return message.indexOf(needle) === -1; });
  count(label,
    thrown !== null && thrown.code === code && missing.length === 0,
    thrown === null
      ? "nothing was thrown"
      : thrown.code + " missing " + JSON.stringify(missing) + " in: " + message);
}

var VAULT_PASSPHRASE = "a long enough vault passphrase for one test run";
var ALICE_PASSWORD   = "quiet lantern bicycle 4291";
var ALICE_NEW_PASSWORD = "another quiet lantern 7715";

function baseEnv(dataDir) {
  return {
    BLAMEPOST_HOSTNAME:         "mx.example.com",
    BLAMEPOST_DATA_DIR:         dataDir,
    BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE,
  };
}

function withEnv(dataDir, extra) {
  return Object.assign(baseEnv(dataDir), extra);
}

// ---- configuration ----

function testConfigDefaults(root, dataDir) {
  var cfg = config.load({ env: baseEnv(dataDir), cwd: root });

  count("blamepost.config.load returns the hostname it was given",
    cfg.hostname === "mx.example.com", cfg.hostname);
  count("blamepost.config.load defaults the HTTP port to 8080", cfg.httpPort === 8080);
  count("blamepost.config.load defaults the HTTPS port to 8443", cfg.httpsPort === 8443);
  count("blamepost.config.load defaults POP3 to off", cfg.pop3Enabled === false);
  // Loading tolerates a missing certificate so `init` and `doctor` run
  // on a host that has none yet. Refusing to serve without one is
  // blamepost.create's job, and server-boot.test.js holds that check.
  count("blamepost.config.load names no certificate of its own",
    cfg.tlsCert === null && cfg.tlsKey === null);
  count("blamepost.config.load carries no setting that claims to issue one",
    Object.keys(cfg).every(function (key) { return key.toLowerCase().indexOf("acme") === -1; }),
    Object.keys(cfg).join(", "));
  count("blamepost.config.load defaults the log level to info", cfg.logLevel === "info");
  count("blamepost.config.load leaves the DNS posture unacknowledged",
    cfg.dnsAcknowledged === false);
  count("blamepost.config.load resolves the data directory to an absolute path",
    nodePath.isAbsolute(cfg.paths.dataDir));
  count("blamepost.config.load resolves the keys directory under the data directory",
    cfg.paths.keys === nodePath.join(dataDir, "keys"), cfg.paths.keys);
  count("blamepost.config.load resolves the queue directory under the data directory",
    cfg.paths.queue === nodePath.join(dataDir, "queue"), cfg.paths.queue);
  count("blamepost.config.load freezes the result", Object.isFrozen(cfg));
}

function testConfigCoercion(root, dataDir) {
  var cfg = config.load({
    env: withEnv(dataDir, {
      BLAMEPOST_HTTP_PORT:       "7070",
      BLAMEPOST_POP3_ENABLED:    "yes",
      BLAMEPOST_DNS_ACKNOWLEDGED: "1",
      BLAMEPOST_LOG_LEVEL:       "warn",
      BLAMEPOST_HOSTNAME:        "MX.Example.COM.",
    }),
    cwd: root,
  });
  count("blamepost.config.load reads a port as a number", cfg.httpPort === 7070);
  count("blamepost.config.load reads yes as true", cfg.pop3Enabled === true);
  count("blamepost.config.load reads 1 as true", cfg.dnsAcknowledged === true);
  count("blamepost.config.load keeps a named log level", cfg.logLevel === "warn");
  count("blamepost.config.load folds the hostname", cfg.hostname === "mx.example.com", cfg.hostname);
}

async function testConfigRefusals(root, dataDir) {
  await refuses("blamepost.config.load refuses a missing hostname", "config/missing-required",
    function () {
      config.load({ env: { BLAMEPOST_VAULT_PASSPHRASE: VAULT_PASSPHRASE }, cwd: root });
    });

  await refuses("blamepost.config.load refuses a missing vault passphrase", "config/missing-required",
    function () {
      config.load({ env: { BLAMEPOST_HOSTNAME: "mx.example.com" }, cwd: root });
    });

  await refuses("blamepost.config.load refuses a short vault passphrase", "config/bad-value",
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_VAULT_PASSPHRASE: "short" }), cwd: root });
    });

  await refuses("blamepost.config.load refuses a port outside the TCP range", "config/bad-value",
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_HTTP_PORT: "0" }), cwd: root });
    });

  await refuses("blamepost.config.load refuses a single-label hostname", "config/bad-value",
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_HOSTNAME: "localhost" }), cwd: root });
    });

  await refuses("blamepost.config.load refuses a word that is not a boolean", "config/bad-value",
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_POP3_ENABLED: "maybe" }), cwd: root });
    });

  await refuses("blamepost.config.load refuses the same port twice", "config/port-collision",
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_HTTPS_PORT: "8080" }), cwd: root });
    });

  await refuses("blamepost.config.load refuses half an administrator", "config/incomplete-admin-pair",
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_ADMIN_EMAIL: "operator@example.com" }),
        cwd: root,
      });
    });

  await refuses("blamepost.config.load refuses a certificate named with no key",
    "config/incomplete-tls-pair", function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_TLS_CERT: nodePath.join(root, "cert.pem") }),
        cwd: root,
      });
    });

  await refuses("blamepost.config.load refuses a certificate path that does not exist",
    "config/bad-value", function () {
      config.load({
        env: withEnv(dataDir, {
          BLAMEPOST_TLS_CERT: nodePath.join(root, "absent.pem"),
          BLAMEPOST_TLS_KEY:  nodePath.join(root, "key.pem"),
        }),
        cwd: root,
      });
    });

  await refuses("blamepost.config.load refuses a setting it does not recognize",
    "config/unknown-key", function () {
      var filePath = nodePath.join(root, "acme-config.json");
      nodeFs.writeFileSync(filePath, JSON.stringify({ acmeEnabled: true }), "utf8");
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_CONFIG: filePath }),
        cwd: root,
      });
    });

  await refuses("blamepost.config.load refuses a config file that is not there",
    "config/file-missing", function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_CONFIG: nodePath.join(root, "absent.json") }),
        cwd: root,
      });
    });
}

function testConfigFileOverlay(root, dataDir) {
  var filePath = nodePath.join(root, "blamepost.config.json");
  nodeFs.writeFileSync(filePath, JSON.stringify({
    httpPort:    9090,
    pop3Enabled: true,
    logLevel:    "debug",
  }), "utf8");

  var fromFile = config.load({
    env: withEnv(dataDir, { BLAMEPOST_CONFIG: filePath }),
    cwd: root,
  });
  count("blamepost.config.load reads a setting out of the file", fromFile.httpPort === 9090);
  count("blamepost.config.load reads a boolean out of the file", fromFile.pop3Enabled === true);
  count("blamepost.config.load records which file it read", fromFile.configPath === filePath);

  var overridden = config.load({
    env: withEnv(dataDir, { BLAMEPOST_CONFIG: filePath, BLAMEPOST_HTTP_PORT: "7071" }),
    cwd: root,
  });
  count("blamepost.config.load lets the environment win over the file",
    overridden.httpPort === 7071, overridden.httpPort);
  count("blamepost.config.load keeps the file value the environment did not touch",
    overridden.logLevel === "debug");

  var strayPath = nodePath.join(root, "stray.config.json");
  nodeFs.writeFileSync(strayPath, JSON.stringify({ htpPort: 9090 }), "utf8");
  var thrown = null;
  try {
    config.load({ env: withEnv(dataDir, { BLAMEPOST_CONFIG: strayPath }), cwd: root });
  } catch (e) {
    thrown = e;
  }
  count("blamepost.config.load refuses an unknown key in the file",
    thrown !== null && thrown.code === "config/unknown-key");
  count("blamepost.config.load names the unknown key",
    thrown !== null && thrown.message.indexOf("htpPort") !== -1, thrown && thrown.message);
}

// ---- settings that carry structure ----
//
// A setting the loader never produced was a feature that silently did
// not exist: the read returned undefined, the subsystem fell back to
// its own default, and the operator's value was nowhere. These cover
// the settings whose value is an object or an array, because a scalar
// reader cannot check one.
//
// `relayAllowedFor` is absent from both bags below and that is not an
// oversight. It is the one structured setting this server declares and
// refuses, so a range written into either of these would stop the load
// and take every other assertion in the sweep down with it. What it
// does instead is asserted where it belongs, in the refusal cases and
// in test/layer-0-primitives/relay-grant-refusal.test.js.

// One environment holding every structured setting, so a run proves
// they are all reachable rather than proving one is and assuming.
var STRUCTURED_ENV = {
  BLAMEPOST_PROFILE:              "balanced",
  BLAMEPOST_LISTENERS:            '{"imap":{"port":1143,"address":"127.0.0.1"},"pop3":{"enabled":true}}',
  BLAMEPOST_INBOUND:              '{"mode":"monitor","onTemperror":"accept"}',
  BLAMEPOST_LIMITS:               '{"maxMessageBytes":1048576,"maxConcurrentConnectionsPerIp":32,' +
                                  '"connectionsPerIpPerMinute":120,' +
                                  '"authFailuresPerIpPer15Min":7,' +
                                  '"rcptFailuresPerIpPerMinute":20}',
  BLAMEPOST_POSTMASTER:           "postmaster@example.com",
  BLAMEPOST_OUTBOUND_POLICY:      '{"mtaSts":"testing","dane":"enforce","dnssecValidated":true}',
  BLAMEPOST_OUTBOUND_RETRY:       '{"maxAttempts":7,"backoffMs":[60000,300000]}',
  BLAMEPOST_OUTBOUND_TIMEOUTS:    '{"mxLookupMs":5000,"perHostMs":30000}',
  BLAMEPOST_SECURITY_CONTACT:     '["mailto:security@example.com"]',
  BLAMEPOST_SECURITY_POLICY_URL:  '["https://example.com/security"]',
  BLAMEPOST_SECURITY_TXT_EXPIRES: "2099-01-01T00:00:00Z",
  BLAMEPOST_MTA_STS_MODE:         "testing",
  BLAMEPOST_MTA_STS_MX:           '["mx1.example.com","*.mx.example.com"]',
  BLAMEPOST_MTA_STS_MAX_AGE:      "86400",
};

// The same values as the configuration file carries them: JSON in a
// JSON document rather than JSON inside a string.
var STRUCTURED_FILE = {
  profile:            "balanced",
  listeners:          { imap: { port: 1143, address: "127.0.0.1" }, pop3: { enabled: true } },
  inbound:            { mode: "monitor", onTemperror: "accept" },
  limits:             {
    maxMessageBytes:               1048576,
    maxConcurrentConnectionsPerIp: 32,
    connectionsPerIpPerMinute:     120,
    authFailuresPerIpPer15Min:     7,
    rcptFailuresPerIpPerMinute:    20,
  },
  postmaster:         "postmaster@example.com",
  outboundPolicy:     { mtaSts: "testing", dane: "enforce", dnssecValidated: true },
  outboundRetry:      { maxAttempts: 7, backoffMs: [60000, 300000] },
  outboundTimeouts:   { mxLookupMs: 5000, perHostMs: 30000 },
  securityContact:    ["mailto:security@example.com"],
  securityPolicyUrl:  ["https://example.com/security"],
  securityTxtExpires: "2099-01-01T00:00:00Z",
  mtaStsMode:         "testing",
  mtaStsMx:           ["mx1.example.com", "*.mx.example.com"],
  mtaStsMaxAge:       86400,
};

// Every assertion the two origins share, so a value honored from the
// environment and the same value honored from the file are checked
// against one expectation rather than two that could drift apart.
function checkStructured(where, cfg) {
  count("the wire profile is honored from " + where, cfg.profile === "balanced", cfg.profile);
  count("a listener port is honored from " + where,
    cfg.listeners.imap.port === 1143, JSON.stringify(cfg.listeners));
  count("a listener interface address is honored from " + where,
    cfg.listeners.imap.address === "127.0.0.1");
  count("a listener switch is honored from " + where,
    cfg.listeners.pop3.enabled === true);
  count("a listener the configuration does not name is left to its default from " + where,
    cfg.listeners.mx === undefined);
  count("a configuration that names no relay range loads from " + where,
    cfg.relayAllowedFor === null, JSON.stringify(cfg.relayAllowedFor));
  count("the inbound authentication posture is honored from " + where,
    cfg.inbound.mode === "monitor" && cfg.inbound.onTemperror === "accept");
  count("the listener resource ceilings are honored from " + where,
    cfg.limits.maxMessageBytes === 1048576 &&
    cfg.limits.maxConcurrentConnectionsPerIp === 32 &&
    cfg.limits.connectionsPerIpPerMinute === 120 &&
    cfg.limits.authFailuresPerIpPer15Min === 7, JSON.stringify(cfg.limits));
  // The bound on how many addresses one source may guess at per minute.
  // The MX listener refuses an address it does not host at RCPT, which
  // is an oracle as well as a courtesy, so this is what stands between
  // a stranger and a list of every mailbox here. A setting that did not
  // survive the load would leave the shipped ceiling in place while the
  // operator believed they had tightened it.
  count("the RCPT enumeration bound is honored from " + where,
    cfg.limits.rcptFailuresPerIpPerMinute === 20, JSON.stringify(cfg.limits));
  count("the report sender is honored from " + where,
    cfg.postmaster === "postmaster@example.com");
  count("the outbound transport policy is honored from " + where,
    cfg.outboundPolicy.mtaSts === "testing" && cfg.outboundPolicy.dane === "enforce");
  // The operator's statement that their resolver validates DNSSEC.
  // Enforcing DANE is refused at boot without it, so a setting that did
  // not survive the load would turn every enforcing deployment into a
  // boot failure the operator could not explain.
  count("the DNSSEC assertion behind an enforcing DANE posture survives " + where,
    cfg.outboundPolicy.dnssecValidated === true);
  count("the outbound retry budget is honored from " + where,
    cfg.outboundRetry.maxAttempts === 7 && cfg.outboundRetry.backoffMs.length === 2);
  count("the outbound timeouts are honored from " + where,
    cfg.outboundTimeouts.mxLookupMs === 5000 && cfg.outboundTimeouts.perHostMs === 30000);
  // REQUIRETLS is deliberately absent from the fixture above. Its only
  // non-default value is refused by the loader, because this server
  // cannot put the parameter on the wire, so asking for it here would
  // stop the load rather than round-trip. Its origin handling is not
  // untested: require-tls-refusal drives the refusal through the
  // environment, the configuration file and a composition object, and a
  // refusal that names the origin can only fire on a value the loader
  // read from that origin. The default is asserted below.
  count("the security contact is honored from " + where,
    cfg.securityContact.length === 1 && cfg.securityContact[0] === "mailto:security@example.com");
  count("the disclosure policy page is honored from " + where,
    cfg.securityPolicyUrl[0] === "https://example.com/security");
  count("the security.txt expiry is honored from " + where,
    cfg.securityTxtExpires === "2099-01-01T00:00:00Z");
  count("the MTA-STS mode is honored from " + where, cfg.mtaStsMode === "testing");
  count("an MTA-STS wildcard MX pattern survives validation from " + where,
    cfg.mtaStsMx.length === 2 && cfg.mtaStsMx[1] === "*.mx.example.com");
  count("the MTA-STS policy lifetime is honored from " + where, cfg.mtaStsMaxAge === 86400);
}

function testStructuredFromEnvironment(root, dataDir) {
  var cfg = config.load({ env: withEnv(dataDir, STRUCTURED_ENV), cwd: root });
  checkStructured("the environment", cfg);

  // The loaded configuration is handed to every subsystem, so a nested
  // section left mutable is a setting one of them could rewrite for all
  // the others.
  count("a nested listener section is frozen", Object.isFrozen(cfg.listeners.imap));
  count("a nested outbound retry list is frozen", Object.isFrozen(cfg.outboundRetry.backoffMs));

  var bare = config.load({ env: baseEnv(dataDir), cwd: root });
  count("an unset structured setting reads as null rather than undefined",
    bare.listeners === null && bare.relayAllowedFor === null && bare.inbound === null);
  count("an unset MTA-STS lifetime carries the documented default",
    bare.mtaStsMaxAge === 604800);
  count("an unset MTA-STS mode carries the documented default",
    bare.mtaStsMode === "enforce");
  count("an unset wire profile is the strict one", bare.profile === "strict");
  count("REQUIRETLS is off unless the operator asks", bare.requireTls === false);
}

function testStructuredFromFile(root, dataDir) {
  var filePath = nodePath.join(root, "structured.config.json");
  nodeFs.writeFileSync(filePath, JSON.stringify(STRUCTURED_FILE), "utf8");

  var cfg = config.load({ env: withEnv(dataDir, { BLAMEPOST_CONFIG: filePath }), cwd: root });
  checkStructured("the file", cfg);

  var overridden = config.load({
    env: withEnv(dataDir, {
      BLAMEPOST_CONFIG:    filePath,
      BLAMEPOST_LISTENERS: '{"imap":{"port":1144}}',
    }),
    cwd: root,
  });
  count("the environment replaces a structured setting the file also carries",
    overridden.listeners.imap.port === 1144, JSON.stringify(overridden.listeners));
  count("and leaves the structured settings it did not name alone",
    overridden.inbound.mode === "monitor" && overridden.mtaStsMx.length === 2,
    JSON.stringify(overridden.inbound) + " " + JSON.stringify(overridden.mtaStsMx));
}

async function testStructuredRefusals(root, dataDir) {
  await refusesNaming("a listener port that is not a number is refused at boot",
    "config/bad-value", ["BLAMEPOST_LISTENERS", "listeners.imap.port", "1143x"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_LISTENERS: '{"imap":{"port":"1143x"}}' }),
        cwd: root,
      });
    });

  await refusesNaming("a listener name nothing binds is refused rather than ignored",
    "config/unknown-key", ["BLAMEPOST_LISTENERS", "imapp"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_LISTENERS: '{"imapp":{"port":143}}' }),
        cwd: root,
      });
    });

  await refusesNaming("a listener field nothing reads is refused rather than ignored",
    "config/unknown-key", ["listeners.imap", "prt"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_LISTENERS: '{"imap":{"prt":143}}' }),
        cwd: root,
      });
    });

  await refusesNaming("an interface address that is not an address is refused",
    "config/bad-value", ["listeners.imap.address"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_LISTENERS: '{"imap":{"address":"not-an-ip"}}' }),
        cwd: root,
      });
    });

  await refusesNaming("a structured setting that is not JSON is refused, naming the variable",
    "config/bad-value", ["BLAMEPOST_LISTENERS", "JSON"],
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_LISTENERS: "imap=1143" }), cwd: root });
    });

  await refuses("two listeners on one port are refused before either binds",
    "config/port-collision", function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_LISTENERS: '{"imap":{"port":2525},"mx":{"port":2525}}' }),
        cwd: root,
      });
    });

  // The relay setting is declared and then refused, and its shape is
  // still checked first. The two answer different questions and the
  // order between them is what an operator reads: a range written as a
  // bare address or as a phrase is a typo, and it comes back named as a
  // typo rather than buried under a paragraph about which listener to
  // move the device to. That paragraph is the answer to a WELL FORMED
  // range, and it is asserted in
  // test/layer-0-primitives/relay-grant-refusal.test.js, from both
  // origins and from the listener composition beside them.
  await refusesNaming("a relay entry carrying no CIDR is refused",
    "config/bad-value", ["BLAMEPOST_RELAY_ALLOWED_FOR", "relayAllowedFor[0].cidr"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_RELAY_ALLOWED_FOR: '[{"scope":"branch"}]' }),
        cwd: root,
      });
    });

  await refusesNaming("a relay entry whose CIDR carries no mask is refused",
    "config/bad-value", ["relayAllowedFor[0].cidr", "192.0.2.7"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_RELAY_ALLOWED_FOR: '[{"cidr":"192.0.2.7"}]' }),
        cwd: root,
      });
    });

  await refusesNaming("a relay entry whose CIDR is not a range at all is refused",
    "config/bad-value", ["relayAllowedFor[0].cidr", "the office"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_RELAY_ALLOWED_FOR: '[{"cidr":"the office"}]' }),
        cwd: root,
      });
    });

  await refusesNaming("a relay entry that is a bare string rather than an entry is refused",
    "config/bad-value", ["relayAllowedFor[0]"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_RELAY_ALLOWED_FOR: '["192.0.2.0/24"]' }),
        cwd: root,
      });
    });

  await refuses("a relay allowlist that is not a list is refused", "config/bad-value",
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_RELAY_ALLOWED_FOR: '{"cidr":"192.0.2.0/24"}' }),
        cwd: root,
      });
    });

  // The file has to refuse exactly what the environment refuses, or an
  // operator moving a value from one to the other changes what is
  // checked.
  var relayFile = nodePath.join(root, "relay.config.json");
  nodeFs.writeFileSync(relayFile, JSON.stringify({
    relayAllowedFor: [{ cidr: "192.0.2.0/24" }, { scope: "no range here" }],
  }), "utf8");
  await refusesNaming("the file refuses a relay entry with no CIDR the same way",
    "config/bad-value", ["relay.config.json", 'key "relayAllowedFor[1].cidr"'],
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_CONFIG: relayFile }), cwd: root });
    });

  await refusesNaming("the permissive wire profile is not on offer",
    "config/bad-value", ["BLAMEPOST_PROFILE", "strict, balanced"],
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_PROFILE: "permissive" }), cwd: root });
    });

  await refusesNaming("an inbound posture nothing implements is refused",
    "config/bad-value", ["inbound.mode", "enforce, monitor"],
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_INBOUND: '{"mode":"loose"}' }), cwd: root });
    });

  await refusesNaming("a retry budget past the ceiling is refused",
    "config/bad-value", ["outboundRetry.maxAttempts"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_OUTBOUND_RETRY: '{"maxAttempts":500}' }),
        cwd: root,
      });
    });

  await refusesNaming("a backoff written in seconds rather than milliseconds is refused",
    "config/bad-value", ["outboundRetry.backoffMs[0]"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_OUTBOUND_RETRY: '{"backoffMs":[5]}' }),
        cwd: root,
      });
    });

  await refusesNaming("a security contact with no scheme is refused",
    "config/bad-value", ["securityContact[0]", "mailto:"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_SECURITY_CONTACT: '["security@example.com"]' }),
        cwd: root,
      });
    });

  await refusesNaming("a cleartext security contact is refused",
    "config/bad-value", ["securityContact[0]"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_SECURITY_CONTACT: '["http://example.com/report"]' }),
        cwd: root,
      });
    });

  // RFC 9116 section 2.5.5 requires a timestamp that has not passed, and
  // the middleware that publishes the file refuses one that has.
  // Refusing it here names the setting, which is what an operator needs.
  await refusesNaming("a security.txt expiry already in the past is refused",
    "config/bad-value", ["BLAMEPOST_SECURITY_TXT_EXPIRES", "has not already passed"],
    function () {
      config.load({
        env: withEnv(dataDir, { BLAMEPOST_SECURITY_TXT_EXPIRES: "2001-01-01T00:00:00Z" }),
        cwd: root,
      });
    });

  await refusesNaming("an MTA-STS lifetime under the floor is refused",
    "config/bad-value", ["BLAMEPOST_MTA_STS_MAX_AGE", "86400"],
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_MTA_STS_MAX_AGE: "60" }), cwd: root });
    });

  await refusesNaming("an MTA-STS MX entry that is not a hostname is refused",
    "config/bad-value", ["mtaStsMx[0]"],
    function () {
      config.load({ env: withEnv(dataDir, { BLAMEPOST_MTA_STS_MX: '["localhost"]' }), cwd: root });
    });
}

// The loader validates a listener section by name, and the mail stack
// owns the table those names come from. Two lists of the same thing
// drift, and the drift is silent: a listener added to the mail stack
// and not to the loader is refused as an unknown field the first time
// an operator configures it.
function testListenerNamesMatchTheMailStack() {
  var declared = config.LISTENER_NAMES.slice().sort().join(",");
  var built    = Object.keys(listenerModule.DEFAULTS).slice().sort().join(",");
  count("the loader knows exactly the listeners the mail stack builds",
    declared === built, declared + " against " + built);
}

// The point of declaring a setting is that it reaches the subsystem
// that reads it. Loading a configuration and composing the listeners
// over it proves the whole path rather than the loader alone.
function testConfiguredListenersReachTheMailStack(root, dataDir, handle) {
  var cfg = config.load({
    env: withEnv(dataDir, {
      BLAMEPOST_LISTENERS:         '{"imap":{"port":1143},"mx":{"enabled":false}}',
      BLAMEPOST_PROFILE:           "balanced",
    }),
    cwd: root,
  });

  var composed = listenerModule.create({
    config:     cfg,
    store:      handle,
    mailStore:  { appendMessage: function () { return { objectid: "obj_config_test" }; } },
    // The listeners read their certificate through an accessor, so a
    // renewal written to disk reaches them. Nothing binds in this case,
    // so the stand-in only has to answer that accessor.
    certificate: certs.handle({}),
    delivery:   helpers.standInDelivery(),
  });
  var described = composed.describe();

  count("the configured IMAP port reaches the listener composition",
    described.listeners.imap.port === 1143, JSON.stringify(described.listeners.imap));
  count("a listener the operator switched off reaches it too",
    described.listeners.mx.enabled === false);
  count("a listener the operator left alone keeps its documented port",
    described.listeners.managesieve.port === 4190);
  // Nothing about relay is reported, because there is no relay posture
  // to report. A key here holding an empty list would read to `doctor`
  // and to the admin surface as a capability switched off rather than
  // as one this server does not have.
  count("the composition describes no relay posture at all",
    described.relayAllowedFor === undefined, JSON.stringify(Object.keys(described)));
  count("the wire profile reaches the listener composition",
    described.profile === "balanced", described.profile);
  count("nothing bound while proving it", Object.keys(described.bound).length === 0);
}

function testConfigRedaction(root, dataDir) {
  var cfg = config.load({ env: baseEnv(dataDir), cwd: root });
  var shown = config.redacted(cfg);
  count("blamepost.config.redacted masks the vault passphrase",
    shown.vaultPassphrase === "[redacted]", shown.vaultPassphrase);
  count("blamepost.config.redacted keeps the settings that are not secret",
    shown.hostname === "mx.example.com" && shown.httpPort === 8080);
  count("blamepost.config.redacted leaves an unset secret alone",
    shown.adminPassword === null);
  count("the loaded config still holds the passphrase for the vault to use",
    cfg.vaultPassphrase === VAULT_PASSPHRASE);
}

function testEnsureDataDirectories(cfg) {
  var paths = config.ensureDataDirectories(cfg);
  count("blamepost.config.ensureDataDirectories creates the data directory",
    nodeFs.existsSync(paths.dataDir));
  count("blamepost.config.ensureDataDirectories creates the blobs directory",
    nodeFs.existsSync(paths.blobs));
  count("blamepost.config.ensureDataDirectories creates the queue directory",
    nodeFs.existsSync(paths.queue));
  count("blamepost.config.ensureDataDirectories creates the keys directory",
    nodeFs.existsSync(paths.keys));
  count("blamepost.config.ensureDataDirectories creates the tls directory",
    nodeFs.existsSync(paths.tls));
  count("blamepost.config.ensureDataDirectories does not create the database file",
    !nodeFs.existsSync(paths.database));
}

// ---- address handling ----

async function testAddress() {
  var addresses = store.address;

  var tagged = addresses.parse("Alice+Receipts@Example.COM");
  count("blamepost.store.address.parse folds the mailbox address",
    tagged.ok && tagged.address === "alice@example.com", tagged.address);
  count("blamepost.store.address.parse keeps the tag", tagged.tag === "receipts", tagged.tag);
  count("blamepost.store.address.parse keeps the address as written",
    tagged.written === "alice+receipts@example.com", tagged.written);

  var bracketed = addresses.parse("<bob@example.com>");
  count("blamepost.store.address.parse accepts an SMTP forward path",
    bracketed.ok && bracketed.address === "bob@example.com");

  var trailing = addresses.parse("bob@example.com.");
  count("blamepost.store.address.parse strips a trailing dot",
    trailing.ok && trailing.address === "bob@example.com", trailing.address);

  var leadingPlus = addresses.parse("+tagonly@example.com");
  count("blamepost.store.address.parse leaves a leading plus in the mailbox name",
    leadingPlus.ok && leadingPlus.address === "+tagonly@example.com" && leadingPlus.tag === null,
    leadingPlus.address);

  count("blamepost.store.address.parse refuses an IP literal",
    addresses.parse("user@[10.0.0.1]").ok === false);
  count("blamepost.store.address.parse refuses two at signs",
    addresses.parse("a@b@example.com").ok === false);
  count("blamepost.store.address.parse refuses a bare local part",
    addresses.parse("alice").ok === false);
  count("blamepost.store.address.parse refuses input that is not a string",
    addresses.parse(null).ok === false && addresses.parse(null).reason === "not-a-string");
  count("blamepost.store.address.parse refuses an over-long address",
    addresses.parse("a".repeat(300) + "@example.com").ok === false);

  count("blamepost.store.address.canonical returns the mailbox address",
    addresses.canonical("ALICE@example.com").address === "alice@example.com");
  await refuses("blamepost.store.address.canonical throws on a bad address", "store/bad-address",
    function () { addresses.canonical("not an address"); });

  count("blamepost.store.address.canonicalDomain folds a domain",
    addresses.canonicalDomain("Example.COM.") === "example.com");
  await refuses("blamepost.store.address.canonicalDomain refuses an address literal",
    "store/bad-domain", function () { addresses.canonicalDomain("192.0.2.1"); });

  count("blamepost.store.address.catchAllFor writes a catch-all key",
    addresses.catchAllFor("Example.com") === "@example.com");
}

// ---- domains and DKIM selectors ----

async function testDomains(handle) {
  var added = await handle.domains.add({ domain: "Example.COM" });
  count("blamepost.store.domains.add folds the domain", added.domain === "example.com");
  count("blamepost.store.domains.add starts a domain active", added.status === "active");
  count("blamepost.store.domains.add leaves the DNS posture unacknowledged",
    added.dnsAcknowledged === false);

  await refuses("blamepost.store.domains.add refuses a domain twice", "store/domain-taken",
    function () { return handle.domains.add({ domain: "example.com" }); });
  await refuses("blamepost.store.domains.add refuses an address literal", "store/bad-domain",
    function () { return handle.domains.add({ domain: "192.0.2.1" }); });
  await refuses("blamepost.store.domains.add refuses a single label", "store/bad-domain",
    function () { return handle.domains.add({ domain: "localhost" }); });

  count("blamepost.store.domains.get folds what it is asked",
    handle.domains.get("EXAMPLE.com.").domain === "example.com");
  count("blamepost.store.domains.get returns null for a domain not hosted here",
    handle.domains.get("example.net") === null);
  count("blamepost.store.domains.get returns null for something that is not a domain",
    handle.domains.get("not a domain") === null);

  await handle.domains.add({ domain: "example.org" });
  count("blamepost.store.domains.list returns both hosted domains",
    handle.domains.list().length === 2);
  count("blamepost.store.domains.list narrows by status",
    handle.domains.list({ status: "active" }).length === 2);

  var acknowledged = await handle.domains.acknowledgeDns({
    domain: "example.com",
    acknowledgedBy: "operator@example.com",
  });
  count("blamepost.store.domains.acknowledgeDns records the confirmation",
    acknowledged.dnsAcknowledged === true);
  count("blamepost.store.domains.acknowledgeDns records who confirmed it",
    acknowledged.dnsAcknowledgedBy === "operator@example.com");
  count("blamepost.store.domains.acknowledgeDns records when",
    typeof acknowledged.dnsAcknowledgedAt === "number");

  var withdrawn = await handle.domains.acknowledgeDns({
    domain: "example.com", acknowledged: false,
  });
  count("blamepost.store.domains.acknowledgeDns can withdraw the confirmation",
    withdrawn.dnsAcknowledged === false && withdrawn.dnsAcknowledgedBy === null);
  await handle.domains.acknowledgeDns({ domain: "example.com", acknowledgedBy: "operator@example.com" });

  await refuses("blamepost.store.domains.acknowledgeDns refuses a domain not hosted here",
    "store/no-such-domain",
    function () { return handle.domains.acknowledgeDns({ domain: "example.net" }); });
}

async function testSelectors(handle) {
  var rsa = await handle.domains.addSelector({
    domain:    "example.com",
    selector:  "bp1-rsa",
    algorithm: "rsa-sha256",
    publicKey: Buffer.from("rsa public key bytes").toString("base64"),
    keyRef:    "example.com.bp1-rsa.rsa-sha256.sealed",
  });
  count("blamepost.store.domains.addSelector records the algorithm",
    rsa.algorithm === "rsa-sha256");
  count("blamepost.store.domains.addSelector starts a selector active", rsa.status === "active");

  // The DKIM-Signature `a=` tag draws from an IANA registry with no ML-DSA
  // value, so a selector carrying one would produce signatures no receiver
  // could verify. The store refuses the value rather than letting a domain
  // be configured into that state.
  await refuses("blamepost.store.domains.addSelector refuses an algorithm the a= tag cannot carry",
    "store/bad-argument",
    function () {
      return handle.domains.addSelector({
        domain:    "example.com",
        selector:  "bp1-pq",
        algorithm: "ml-dsa-65",
        publicKey: Buffer.from("post quantum public key bytes").toString("base64"),
        keyRef:    "example.com.bp1-pq.ml-dsa-65.sealed",
      });
    });

  await handle.domains.addSelector({
    domain:    "example.com",
    selector:  "bp1",
    algorithm: "ed25519",
    publicKey: Buffer.from("classical public key bytes").toString("base64"),
    keyRef:    "example.com.bp1.ed25519.sealed",
  });
  count("blamepost.store.domains.listSelectors returns both halves of the dual signer",
    handle.domains.listSelectors({ domain: "example.com" }).length === 2);
  count("blamepost.store.domains.listSelectors narrows by status",
    handle.domains.listSelectors({ domain: "example.com", status: "active" }).length === 2);

  await refuses("blamepost.store.domains.addSelector refuses the same selector twice",
    "store/selector-taken", function () {
      return handle.domains.addSelector({
        domain: "example.com", selector: "bp1", algorithm: "ed25519",
        publicKey: Buffer.from("x").toString("base64"), keyRef: "again.sealed",
      });
    });
  await refuses("blamepost.store.domains.addSelector refuses a key reference with a path in it",
    "store/bad-argument", function () {
      return handle.domains.addSelector({
        domain: "example.com", selector: "bp2", algorithm: "ed25519",
        publicKey: Buffer.from("x").toString("base64"), keyRef: "../../etc/shadow",
      });
    });
  await refuses("blamepost.store.domains.addSelector refuses a selector that is not one label",
    "store/bad-selector", function () {
      return handle.domains.addSelector({
        domain: "example.com", selector: "bp1.extra", algorithm: "ed25519",
        publicKey: Buffer.from("x").toString("base64"), keyRef: "x.sealed",
      });
    });
  await refuses("blamepost.store.domains.addSelector refuses an algorithm it cannot sign with",
    "store/bad-argument", function () {
      return handle.domains.addSelector({
        domain: "example.com", selector: "bp2", algorithm: "md5",
        publicKey: Buffer.from("x").toString("base64"), keyRef: "x.sealed",
      });
    });
  await refuses("blamepost.store.domains.addSelector refuses a public key that is not base64",
    "store/bad-argument", function () {
      return handle.domains.addSelector({
        domain: "example.com", selector: "bp2", algorithm: "ed25519",
        publicKey: "not base64 at all!", keyRef: "x.sealed",
      });
    });

  var retiring = await handle.domains.retireSelector({
    domain: "example.com", selector: "bp1", algorithm: "ed25519",
  });
  count("blamepost.store.domains.retireSelector moves the selector to retiring",
    retiring.status === "retiring");
  count("blamepost.store.domains.retireSelector keeps the record published for a week",
    retiring.retiresAt > Date.now() + b.constants.TIME.days(6));

  await refuses("blamepost.store.domains.removeSelector refuses inside the overlap window",
    "store/selector-still-overlapping", function () {
      return handle.domains.removeSelector({
        domain: "example.com", selector: "bp1", algorithm: "ed25519",
        reason: "rotation finished",
      });
    });

  var removed = await handle.domains.removeSelector({
    domain: "example.com", selector: "bp1", algorithm: "ed25519",
    reason: "private key exposed", immediate: true,
  });
  count("blamepost.store.domains.removeSelector withdraws it when told to",
    removed.outcome === "removed");
  count("the withdrawn selector is gone",
    handle.domains.listSelectors({ domain: "example.com" }).length === 1);

  await handle.domains.addSelector({
    domain:    "example.org",
    selector:  "bp1",
    algorithm: "ed25519",
    publicKey: Buffer.from("only key for this domain").toString("base64"),
    keyRef:    "example.org.bp1.ed25519.sealed",
  });
  await refuses("blamepost.store.domains.removeSelector refuses to leave a domain unsigned",
    "store/last-selector", function () {
      return handle.domains.removeSelector({
        domain: "example.org", selector: "bp1", algorithm: "ed25519",
        reason: "tidying up",
      });
    });
  await refuses("blamepost.store.domains.removeSelector refuses a selector that is not published",
    "store/no-such-selector", function () {
      return handle.domains.removeSelector({
        domain: "example.org", selector: "absent", algorithm: "ed25519", reason: "tidying up",
      });
    });
}

// ---- accounts ----

async function testAccounts(handle) {
  var alice = await handle.accounts.create({
    address:     "Alice@Example.com",
    password:    ALICE_PASSWORD,
    displayName: "Alice Example",
  });
  count("blamepost.store.accounts.create folds the address",
    alice.address === "alice@example.com", alice.address);
  count("blamepost.store.accounts.create splits out the local part",
    alice.localPart === "alice" && alice.domain === "example.com");
  count("blamepost.store.accounts.create starts an account active", alice.status === "active");
  count("blamepost.store.accounts.create returns no credential material",
    Object.prototype.hasOwnProperty.call(alice, "passwordHash") === false);
  count("blamepost.store.accounts.create keeps the display name",
    alice.displayName === "Alice Example");
  count("blamepost.store.accounts.create records when the password was set",
    typeof alice.passwordChangedAt === "number");

  await refuses("blamepost.store.accounts.create refuses the same address twice",
    "store/address-taken", function () {
      return handle.accounts.create({ address: "alice@example.com", password: ALICE_PASSWORD });
    });
  await refuses("blamepost.store.accounts.create refuses a domain not hosted here",
    "store/no-such-domain", function () {
      return handle.accounts.create({ address: "alice@example.net", password: ALICE_PASSWORD });
    });
  await refuses("blamepost.store.accounts.create refuses an address carrying a tag",
    "store/bad-address", function () {
      return handle.accounts.create({ address: "alice+news@example.com", password: ALICE_PASSWORD });
    });
  await refuses("blamepost.store.accounts.create refuses a password from the breach list",
    "store/weak-password", function () {
      return handle.accounts.create({ address: "weak@example.com", password: "password1" });
    });
  await refuses("blamepost.store.accounts.create refuses a password that is too short",
    "store/weak-password", function () {
      return handle.accounts.create({ address: "weak@example.com", password: "short" });
    });
  await refuses("blamepost.store.accounts.create refuses a password holding the address",
    "store/weak-password", function () {
      return handle.accounts.create({
        address: "weak@example.com", password: "weak@example.com is my password",
      });
    });
  await refuses("blamepost.store.accounts.create refuses a display name with a control character",
    "store/bad-argument", function () {
      return handle.accounts.create({
        address: "ctl@example.com", password: ALICE_PASSWORD,
        displayName: "Alice" + String.fromCharCode(13) + "Bcc: victim@example.net",
      });
    });

  count("blamepost.store.accounts.get finds an account by address whatever the case",
    handle.accounts.get("ALICE@EXAMPLE.COM").id === alice.id);
  count("blamepost.store.accounts.get finds an account by id",
    handle.accounts.get(alice.id).address === "alice@example.com");
  count("blamepost.store.accounts.get strips a tag before looking up",
    handle.accounts.get("alice+news@example.com").id === alice.id);
  count("blamepost.store.accounts.get returns null for an address nobody holds",
    handle.accounts.get("nobody@example.com") === null);

  await handle.accounts.create({ address: "bob@example.com", password: "steady harbour cable 8820" });
  var listed = handle.accounts.list({ domain: "example.com" });
  count("blamepost.store.accounts.list returns the domain's accounts", listed.length === 2);
  count("blamepost.store.accounts.list sorts by address",
    listed[0].address === "alice@example.com" && listed[1].address === "bob@example.com");
  count("blamepost.store.accounts.list carries no credential material",
    Object.prototype.hasOwnProperty.call(listed[0], "passwordHash") === false);
  count("blamepost.store.accounts.list narrows by domain",
    handle.accounts.list({ domain: "example.org" }).length === 0);
  count("blamepost.store.accounts.list honors a limit",
    handle.accounts.list({ limit: 1 }).length === 1);
  count("blamepost.store.accounts.list honors an offset",
    handle.accounts.list({ offset: 1 })[0].address === "bob@example.com");

  return alice;
}

async function testAuthentication(handle, alice) {
  var good = await handle.accounts.authenticate({
    address: "Alice@example.com", password: ALICE_PASSWORD,
  });
  count("blamepost.store.accounts.authenticate accepts the right password", good.ok === true);
  count("blamepost.store.accounts.authenticate returns the account id",
    good.accountId === alice.id);
  count("blamepost.store.accounts.authenticate reports the administrator flag",
    good.isAdmin === false);

  var wrong = await handle.accounts.authenticate({
    address: "alice@example.com", password: "not the right one at all",
  });
  count("blamepost.store.accounts.authenticate refuses the wrong password", wrong.ok === false);
  count("blamepost.store.accounts.authenticate says only that the credentials were wrong",
    wrong.reason === "bad-credentials", wrong.reason);

  var unknown = await handle.accounts.authenticate({
    address: "nobody@example.com", password: ALICE_PASSWORD,
  });
  count("blamepost.store.accounts.authenticate gives an unknown address the same answer",
    unknown.ok === false && unknown.reason === "bad-credentials");

  var malformed = await handle.accounts.authenticate({ address: 42, password: null });
  count("blamepost.store.accounts.authenticate does not throw on wire garbage",
    malformed.ok === false && malformed.reason === "bad-credentials");

  var empty = await handle.accounts.authenticate({});
  count("blamepost.store.accounts.authenticate refuses an empty attempt", empty.ok === false);

  await handle.accounts.setPassword({ id: alice.id, password: ALICE_NEW_PASSWORD });
  var afterChange = await handle.accounts.authenticate({
    address: "alice@example.com", password: ALICE_NEW_PASSWORD,
  });
  count("blamepost.store.accounts.setPassword installs the new password", afterChange.ok === true);
  var afterChangeOld = await handle.accounts.authenticate({
    address: "alice@example.com", password: ALICE_PASSWORD,
  });
  count("blamepost.store.accounts.setPassword retires the old password",
    afterChangeOld.ok === false);
  await refuses("blamepost.store.accounts.setPassword refuses a weak replacement",
    "store/weak-password", function () {
      return handle.accounts.setPassword({ id: alice.id, password: "qwerty" });
    });
  await refuses("blamepost.store.accounts.setPassword refuses an account it cannot find",
    "store/no-such-account", function () {
      return handle.accounts.setPassword({ id: "absent", password: ALICE_NEW_PASSWORD });
    });
}

function testSealing(alice) {
  var raw = b.db.prepare(
    "SELECT address, addressHash, passwordHash, displayName FROM blamepost_accounts WHERE _id = ?"
  ).get(alice.id);

  count("the address column holds ciphertext, not an address",
    typeof raw.address === "string" && raw.address.indexOf("alice@example.com") === -1 &&
    raw.address.indexOf("@") === -1, raw.address);
  count("the password hash column holds ciphertext, not a hash",
    typeof raw.passwordHash === "string" && raw.passwordHash.indexOf("$argon2id$") === -1);
  count("the display name column holds ciphertext",
    typeof raw.displayName === "string" && raw.displayName.indexOf("Alice") === -1);
  count("the derived hash column carries a lookup key, not the address",
    typeof raw.addressHash === "string" && raw.addressHash.length > 0 &&
    raw.addressHash.indexOf("alice") === -1);
}

async function testAccountLifecycle(handle, alice) {
  var suspended = await handle.accounts.suspend({
    id: alice.id, reason: "credential reuse reported",
  });
  count("blamepost.store.accounts.suspend records the status", suspended.status === "suspended");
  count("blamepost.store.accounts.suspend records the reason",
    suspended.statusReason === "credential reuse reported");

  var whileSuspended = await handle.accounts.authenticate({
    address: "alice@example.com", password: ALICE_NEW_PASSWORD,
  });
  count("a suspended account cannot sign in",
    whileSuspended.ok === false && whileSuspended.reason === "account-suspended",
    whileSuspended.reason);

  var suspendedVerdict = handle.resolve("alice@example.com");
  count("blamepost.store.resolve calls a suspended mailbox local but undeliverable",
    suspendedVerdict.local === true && suspendedVerdict.deliverable === false &&
    suspendedVerdict.reason === "account-suspended", suspendedVerdict.reason);

  await refuses("blamepost.store.accounts.suspend needs a reason", "store/bad-argument",
    function () { return handle.accounts.suspend({ id: alice.id }); });

  var reinstated = await handle.accounts.reinstate({ id: alice.id });
  count("blamepost.store.accounts.reinstate returns the account to service",
    reinstated.status === "active" && reinstated.statusReason === null);
  count("a reinstated mailbox takes mail again",
    handle.resolve("alice@example.com").deliverable === true);

  var archived = await handle.accounts.delete({ id: alice.id, reason: "owner on leave" });
  count("blamepost.store.accounts.delete archives by default", archived.outcome === "archived");
  count("an archived account keeps its row",
    handle.accounts.get(alice.id).status === "archived");
  count("an archived mailbox stops taking mail",
    handle.resolve("alice@example.com").deliverable === false);
  count("blamepost.store.accounts.list leaves archived accounts out",
    handle.accounts.list({ domain: "example.com" }).length === 1);
  count("blamepost.store.accounts.list returns them when asked",
    handle.accounts.list({ domain: "example.com", includeArchived: true }).length === 2);

  await refuses("blamepost.store.accounts.delete needs a reason", "store/bad-argument",
    function () { return handle.accounts.delete({ id: alice.id }); });

  await handle.accounts.reinstate({ id: alice.id });
  count("an archived account can be brought back",
    handle.accounts.get(alice.id).status === "active");
}

async function testDestroy(handle) {
  var temp = await handle.accounts.create({
    address: "temp@example.com", password: "wandering thicket 5502",
  });
  await handle.aliases.add({ address: "tempname@example.com", destination: "temp@example.com" });
  count("the alias pointing at the account is there",
    handle.aliases.list({ destination: "temp@example.com" }).length === 1);

  var destroyed = await handle.accounts.delete({
    id: temp.id, destroy: true, reason: "erasure requested by the account owner",
  });
  count("blamepost.store.accounts.delete erases the row when told to",
    destroyed.outcome === "destroyed" && destroyed.rowsErased === 1, destroyed.rowsErased);
  count("blamepost.store.accounts.delete takes the aliases with it",
    destroyed.aliasesErased === 1);
  count("the erased account is gone", handle.accounts.get(temp.id) === null);
  count("the aliases pointing at it are gone",
    handle.aliases.list({ destination: "temp@example.com" }).length === 0);
}

// ---- aliases and routing ----

async function testAliases(handle) {
  var sales = await handle.aliases.add({
    address: "Sales@Example.com", destination: "alice+sales@example.com",
  });
  count("blamepost.store.aliases.add folds the source address",
    sales.address === "sales@example.com");
  count("blamepost.store.aliases.add keeps the tag on the destination",
    sales.destination === "alice+sales@example.com");
  count("blamepost.store.aliases.add remembers the untagged mailbox",
    sales.destinationMailbox === "alice@example.com");

  await refuses("blamepost.store.aliases.add refuses the same pair twice", "store/alias-exists",
    function () {
      return handle.aliases.add({
        address: "sales@example.com", destination: "alice+sales@example.com",
      });
    });
  await refuses("blamepost.store.aliases.add refuses to shadow a mailbox", "store/address-taken",
    function () {
      return handle.aliases.add({ address: "alice@example.com", destination: "bob@example.com" });
    });
  await refuses("blamepost.store.aliases.add refuses a tag on the source", "store/bad-address",
    function () {
      return handle.aliases.add({ address: "sales+eu@example.com", destination: "bob@example.com" });
    });
  await refuses("blamepost.store.aliases.add refuses a domain not hosted here",
    "store/no-such-domain", function () {
      return handle.aliases.add({ address: "sales@example.net", destination: "bob@example.com" });
    });
  await refuses("blamepost.store.aliases.add refuses an alias pointing at itself",
    "store/alias-loop", function () {
      return handle.aliases.add({ address: "self@example.com", destination: "self@example.com" });
    });

  await handle.aliases.add({ address: "sales@example.com", destination: "bob@example.com" });
  var salesVerdict = handle.resolve("sales@example.com");
  count("blamepost.store.resolve expands an alias that fans out",
    salesVerdict.kind === "alias" && salesVerdict.targets.length === 2, salesVerdict.targets.length);
  count("blamepost.store.resolve marks a fan-out deliverable",
    salesVerdict.deliverable === true);

  count("blamepost.store.aliases.list finds aliases by the mailbox they point at",
    handle.aliases.list({ destination: "alice@example.com" }).length === 1);
  count("blamepost.store.aliases.list finds aliases by source address",
    handle.aliases.list({ address: "sales@example.com" }).length === 2);
  count("blamepost.store.aliases.list narrows by domain",
    handle.aliases.list({ domain: "example.org" }).length === 0);

  await handle.aliases.add({ address: "news@example.com", destination: "someone@example.net" });
  var remote = handle.resolve("news@example.com");
  count("blamepost.store.resolve treats an address elsewhere as a forward",
    remote.targets.length === 1 && remote.targets[0].local === false &&
    remote.targets[0].deliverable === true);

  await handle.aliases.add({ address: "team@example.com", destination: "sales@example.com" });
  var chained = handle.resolve("team@example.com");
  count("blamepost.store.resolve follows an alias chain to its ends",
    chained.targets.length === 2, chained.targets.length);
  count("blamepost.store.resolve reports no loop on a straight chain",
    chained.loops.length === 0);

  await handle.aliases.add({ address: "loopa@example.com", destination: "loopb@example.com" });
  await handle.aliases.add({ address: "loopb@example.com", destination: "loopa@example.com" });
  var looped = handle.resolve("loopa@example.com");
  count("blamepost.store.resolve refuses to follow a loop",
    looped.loops.length > 0, looped.loops.join(","));
  count("blamepost.store.resolve calls a looping alias undeliverable",
    looped.deliverable === false && looped.reason === "alias-loop", looped.reason);

  var disabled = await handle.aliases.setStatus({
    address: "news@example.com", destination: "someone@example.net",
    status: "disabled", reason: "sending complaints",
  });
  count("blamepost.store.aliases.setStatus records the status", disabled.status === "disabled");
  var disabledVerdict = handle.resolve("news@example.com");
  count("a disabled alias stops resolving",
    disabledVerdict.deliverable === false && disabledVerdict.targets.length === 0,
    JSON.stringify(disabledVerdict.targets));
  count("and says the alias was disabled rather than that nobody holds the address",
    disabledVerdict.reason === "alias-disabled", disabledVerdict.reason);
  count("blamepost.store.aliases.list leaves disabled aliases out",
    handle.aliases.list({ address: "news@example.com" }).length === 0);
  count("blamepost.store.aliases.list returns them when asked",
    handle.aliases.list({ address: "news@example.com", includeDisabled: true }).length === 1);

  var removedAlias = await handle.aliases.remove({
    address: "news@example.com", destination: "someone@example.net", reason: "role retired",
  });
  count("blamepost.store.aliases.remove deletes one leg", removedAlias.outcome === "removed");
  count("the removed alias is gone",
    handle.aliases.list({ address: "news@example.com", includeDisabled: true }).length === 0);

  await refuses("blamepost.store.aliases.remove refuses a source with no destination named",
    "store/bad-argument", function () {
      return handle.aliases.remove({ address: "sales@example.com", reason: "tidying up" });
    });
  await refuses("blamepost.store.aliases.remove refuses an alias that is not there",
    "store/no-such-alias", function () {
      return handle.aliases.remove({
        address: "sales@example.com", destination: "nobody@example.net", reason: "tidying up",
      });
    });
}

async function testCatchAll(handle) {
  count("an unclaimed address has nowhere to go before a catch-all exists",
    handle.resolve("whoever@example.com").reason === "no-such-mailbox");

  var catchAll = await handle.aliases.add({
    domain: "example.com", catchAll: true, destination: "bob@example.com",
  });
  count("blamepost.store.aliases.add writes a catch-all under the domain key",
    catchAll.address === "@example.com" && catchAll.isCatchAll === true);

  var verdict = handle.resolve("whoever@example.com");
  count("blamepost.store.resolve falls through to the catch-all",
    verdict.kind === "catch-all" && verdict.deliverable === true, verdict.kind);
  count("blamepost.store.resolve sends the catch-all to its destination",
    verdict.targets.length === 1 && verdict.targets[0].mailbox === "bob@example.com");
  count("a real mailbox still wins over the catch-all",
    handle.resolve("bob@example.com").kind === "account");
  count("an alias still wins over the catch-all",
    handle.resolve("sales@example.com").kind === "alias");
  count("blamepost.store.aliases.list finds the catch-all by domain",
    handle.aliases.list({ catchAllFor: "example.com" }).length === 1);
}

async function testResolveEdges(handle) {
  var unknown = handle.resolve("someone@example.net");
  count("blamepost.store.resolve calls an unhosted domain not local",
    unknown.local === false && unknown.reason === "unknown-domain");

  var malformed = handle.resolve("not an address");
  count("blamepost.store.resolve refuses a malformed recipient without throwing",
    malformed.local === false && malformed.reason === "invalid-address");
  count("blamepost.store.resolve refuses a recipient that is not a string",
    handle.resolve(undefined).reason === "invalid-address");
  count("blamepost.store.resolve refuses the catch-all key as a recipient",
    handle.resolve("@example.com").reason === "invalid-address");

  var tagged = handle.resolve("Bob+Receipts@Example.com");
  count("blamepost.store.resolve routes a tagged address to its mailbox",
    tagged.kind === "account" && tagged.address === "bob@example.com");
  count("blamepost.store.resolve hands the tag on for filtering", tagged.tag === "receipts");

  await handle.domains.setStatus({
    domain: "example.org", status: "disabled", reason: "moving to another host",
  });
  count("blamepost.store.domains.setStatus disables a domain",
    handle.domains.get("example.org").status === "disabled");
  count("blamepost.store.resolve stops delivery to a disabled domain",
    handle.resolve("anyone@example.org").reason === "domain-disabled");
  await refuses("blamepost.store.accounts.create refuses a disabled domain",
    "store/domain-disabled", function () {
      return handle.accounts.create({
        address: "someone@example.org", password: "steady harbour cable 8820",
      });
    });
}

async function testDomainRemoval(handle) {
  await refuses("blamepost.store.domains.remove refuses while mailboxes remain",
    "store/domain-in-use", function () {
      return handle.domains.remove({ domain: "example.com", reason: "moving to another host" });
    });

  var removed = await handle.domains.remove({
    domain: "example.org", reason: "moving to another host",
  });
  count("blamepost.store.domains.remove drops an empty domain", removed.outcome === "removed");
  count("blamepost.store.domains.remove takes its selectors with it",
    removed.selectorsRemoved === 1, removed.selectorsRemoved);
  count("the removed domain is no longer hosted", handle.domains.get("example.org") === null);
  count("blamepost.store.domains.list is down to one domain",
    handle.domains.list().length === 1);
}

// ---- runner ----

async function run() {
  var root = nodeFs.mkdtempSync(nodePath.join(nodeOs.tmpdir(), "blamepost-store-"));
  var dataDir = nodePath.join(root, "data");
  var workDir = nodePath.join(root, "work");
  nodeFs.mkdirSync(workDir, { recursive: true });

  // The framework keeps the decrypted working copy of the database on a
  // memory-backed directory and reads this variable to find it. Pointing
  // it inside the test's own temporary tree keeps the encrypted-at-rest
  // path exactly as it ships rather than opting the test out of it.
  var hadTmp = Object.prototype.hasOwnProperty.call(process.env, "BLAMEJS_TMPDIR");
  var priorTmp = hadTmp ? process.env.BLAMEJS_TMPDIR : null;
  process.env.BLAMEJS_TMPDIR = workDir;

  // Two files that only have to exist: the configuration layer checks a
  // named certificate is on disk before the boot goes any further, and
  // that check is what these drive.
  nodeFs.writeFileSync(nodePath.join(root, "cert.pem"), "certificate bytes\n", "utf8");
  nodeFs.writeFileSync(nodePath.join(root, "key.pem"), "key bytes\n", "utf8");

  try {
    testConfigDefaults(root, dataDir);
    testConfigCoercion(root, dataDir);
    await testConfigRefusals(root, dataDir);
    testConfigFileOverlay(root, dataDir);
    testStructuredFromEnvironment(root, dataDir);
    testStructuredFromFile(root, dataDir);
    await testStructuredRefusals(root, dataDir);
    testListenerNamesMatchTheMailStack();
    testConfigRedaction(root, dataDir);

    var cfg = config.load({ env: baseEnv(dataDir), cwd: root });
    testEnsureDataDirectories(cfg);

    count("blamepost.store.isOpen says nothing is open yet", store.isOpen() === false);
    var handle = await store.open(cfg);
    count("blamepost.store.open returns a handle with the four surfaces",
      typeof handle.accounts === "object" && typeof handle.domains === "object" &&
      typeof handle.aliases === "object" && typeof handle.resolve === "function");
    count("blamepost.store.isOpen says the store is open", store.isOpen() === true);
    count("blamepost.store.open hands back the same handle a second time",
      (await store.open(cfg)) === handle);
    count("blamepost.store.StoreError is the class refusals carry",
      typeof store.StoreError === "function");

    testConfiguredListenersReachTheMailStack(root, dataDir, handle);

    await testAddress();
    await testDomains(handle);
    await testSelectors(handle);
    var alice = await testAccounts(handle);
    await testAuthentication(handle, alice);
    testSealing(alice);
    await testAccountLifecycle(handle, alice);
    await testDestroy(handle);
    await testAliases(handle);
    await testCatchAll(handle);
    await testResolveEdges(handle);
    await testDomainRemoval(handle);

    store.close();
    count("blamepost.store.close leaves nothing open", store.isOpen() === false);
    store.close();
    count("blamepost.store.close is safe to call when nothing is open",
      store.isOpen() === false);
  } finally {
    if (store.isOpen()) store.close();
    if (hadTmp) process.env.BLAMEJS_TMPDIR = priorTmp;
    else delete process.env.BLAMEJS_TMPDIR;
    try {
      nodeFs.rmSync(root, { recursive: true, force: true });
    } catch (_e) {
      // A temporary directory the platform will not release yet is not a
      // test result. The operating system reclaims it.
    }
  }

  return helpers.getChecks();
}

module.exports = { name: "store", run: run, getChecks: helpers.getChecks };

// The orchestrator parses `CHECKS <n>` out of this file's stdout to aggregate
// the suite total. Printing any other wording still exits zero, so the run
// reads as passing while contributing nothing to the count, which is the same
// output a file asserting nothing would produce. Keep the token.
if (require.main === module) {
  run().then(function (count) {
    console.log("CHECKS " + count);
  }).catch(function (e) {
    console.error(e && e.stack ? e.stack : String(e));
    // Set the code rather than calling process.exit, which would tear the
    // process down before the stack above is flushed. The orchestrator reads
    // this file's output to diagnose a failure, so losing it costs the run.
    process.exitCode = 1;
  });
}
