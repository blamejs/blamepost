// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module   blamepost.config
 * @nav      Server and configuration
 * @title    Configuration
 * @order    20
 * @featured true
 *
 * Boot configuration. An optional JSON file supplies the baseline and
 * the environment overrides it, so an image can ship a file and an
 * operator can change one value with an environment variable without
 * rebuilding anything.
 *
 * Every setting is checked the moment it is read, and anything the
 * server cannot honor stops the boot with a message naming the setting,
 * where the value came from, and what was expected. A hostname that is
 * not fully qualified, a port outside the TCP range, a certificate path
 * that does not exist: each of those is a boot failure rather than a
 * surprise at the first message.
 *
 * Some settings carry structure rather than one value: the listener
 * table, the relay allowlist, the inbound authentication posture, and
 * the outbound policy, retry and timeout blocks. Structure is checked
 * to the same depth. An object refuses a field it does not recognize,
 * an array checks every element, and the refusal names the path inside
 * the setting that failed rather than the setting alone.
 *
 * One setting is declared and then refused, and the two are not in
 * tension. `relayAllowedFor` names address ranges this server would
 * accept a recipient outside the hosted domains for, and this server
 * does not relay for a source address at all, so a range written into
 * it stops the boot with a message naming the setting and the listener
 * to use instead. It keeps its row because removing the row is the one
 * outcome worse than refusing: the file key would become an unknown key
 * and the environment variable would become a name nothing reads, and
 * the environment is a namespace shared with every other tool on the
 * host, so an operator who had set it would get a server that relays
 * for nobody and never mentions it. A row that refuses says so out
 * loud; a row that is gone says nothing.
 *
 * Both origins reach a structured setting. In the file it is written as
 * JSON, because the file already is JSON. In the environment it is the
 * same JSON on one line, parsed and then checked by the same code, so
 * the two forms cannot disagree about what is valid.
 *
 * The listener table also has a narrow form. Each listener carries a
 * port variable of its own, which is the shape that fits the one job an
 * operator most often has: moving a single listener off a privileged
 * port so the process can run unprivileged. It sets that listener's port
 * and touches nothing else, it wins over a port written in the file the
 * way every environment value does, and setting the same port through
 * both environment variables at once is refused rather than resolved,
 * because one of the two would be doing nothing.
 *
 * Every port the process will try to bind is counted once, listeners and
 * the browser surface together. A listener the configuration never names
 * is not absent from that count: it binds its documented port, so moving
 * another listener onto it is a collision with something nothing wrote
 * down, and it would otherwise surface at start as an operating system
 * error naming a number, after the earlier listeners were already
 * accepting connections.
 *
 * The certificate is the operator's to supply. `serve` refuses to start
 * without `tlsCert` and `tlsKey`, because every listener here requires
 * TLS and none has a plaintext mode. Loading tolerates their absence so
 * that `blamepost init` and `blamepost doctor` still run on a host that
 * has no certificate yet, which is exactly when an operator needs
 * `doctor` to say so.
 *
 * Loading is pure. Nothing here creates a directory, opens a socket or
 * reads a secret store, so `blamepost doctor` can validate an operator's
 * configuration without touching the running system. Creating the data
 * directories is the separate, explicit `ensureDataDirectories` call.
 *
 * @card
 *   Reads the optional JSON configuration file and the `BLAMEPOST_`
 *   environment variables, with the environment taking precedence. A
 *   setting the server cannot use stops the boot with a message naming the
 *   setting and where its value came from.
 */

var nodeFs   = require("node:fs");
var nodeNet  = require("node:net");
var nodePath = require("node:path");
var b        = require("../vendor/blamejs");
// The one derivation that decides which domain a name means. A hostname
// settled here is compared against hosted-domain rows and used to build  // allow:self-history-in-source the participle, meaning employed: the auxiliary is two words back
// the names this server publishes, so it has to be folded the way the
// identity layer folds one. The module reads the framework guards and
// nothing else, so naming it from here adds no cycle.
var address  = require("../store/address");

var C = b.constants;

var ConfigError = b.frameworkError.defineClass("ConfigError", { alwaysPermanent: true });
var _err = ConfigError.factory;

var DEFAULT_CONFIG_PATH = "/etc/blamepost/blamepost.config.json";
var DEFAULT_DATA_DIR    = "/var/lib/blamepost";

// A vault passphrase seals the DKIM private keys and every sealed
// column in the database. Losing it loses the data, and a short one is
// an offline-guessing target, so the floor is checked at boot where the
// operator can still change it.
var MIN_VAULT_PASSPHRASE_CHARS = 16;

// The configuration file is operator-owned and small. The cap stops a
// runaway or hostile file from being parsed at all.
var MAX_CONFIG_FILE_BYTES = C.BYTES.kib(256);

// A structured setting supplied through the environment travels as one
// line of JSON. The cap is far above any real listener table and far
// below anything that would be slow to parse.
var MAX_ENV_JSON_BYTES = C.BYTES.kib(64);

// A refused value is quoted back to the operator. A structured one can
// be long, and a boot failure nobody can read is a boot failure nobody
// can fix, so the quotation is bounded.
var MAX_SHOWN_CHARS = 200;

var LOG_LEVELS = ["debug", "info", "warn", "error", "fatal"];

// The level a configuration that says nothing runs at.
var DEFAULT_LOG_LEVEL = "info";

// The variable the framework's boot logger reads before it emits a
// `debug` line. `applyLogLevel` below writes the resolved level into it,
// which is what makes `BLAMEPOST_LOG_LEVEL` and the `logLevel` key in the
// file reach the logger at all. The framework name is used rather than
// the bare `LOG_LEVEL` the same reader falls back to, because the bare
// name is a namespace shared with every other tool on the host and this
// server has no business setting it for them.
var BOOT_LOG_LEVEL_VAR = "BLAMEJS_BOOT_LOG_LEVEL";

// The guard posture the wire protocols run under. `strict` is the
// default and `balanced` exists for one reason: strict refuses a
// punycode domain, so a server that has to accept mail from an
// internationalized domain needs the wider profile. The framework also
// offers `permissive`, which accepts credentials before TLS on IMAP and
// on submission; this server does not offer it, because relaxing the
// authentication state machine for a client that cannot do TLS is the
// change that turns a mail server into a credential leak.
var GUARD_PROFILES = ["strict", "balanced"];

// The listeners a section may name, the port each one binds when the
// configuration says nothing, whether it binds at all, and the variable
// that moves it on its own. `lib/mail/listeners.js` owns the table these
// come from and applies them; this is the same set spelled out so the
// loader does not have to reach into the mail stack to validate a key or
// to know which ports are already spoken for. A drift test compares the
// two, so a listener added there and not here fails a gate rather than
// silently refusing the new section as an unknown field.
//
// The narrow port variable exists because a listener table written as
// JSON is the wrong shape for the one job an operator most often has:
// moving a single listener off a privileged port so the process can run
// unprivileged. It sets that listener's port and nothing else.
// `maxLineBytes` is the longest command line each listener reads before
// it refuses one, and it is written here for the reason the ceilings
// table below gives: a listener handed no number applies the vendored
// framework's own, which is a number this repository would publish in
// the operator guide without choosing, and the two agree until a refresh
// moves one. Each value is the framework's current default, so declaring
// them moves no behavior; what changes is that a refresh that moves one
// fails a test instead of passing quietly.
//
// They differ per protocol because the standards do. RFC 5321 section
// 4.5.3.1.4 bounds an SMTP command line, RFC 2449 section 4 bounds a
// POP3 one, and IMAP and ManageSieve carry longer commands, so one
// number across all six would be wrong twice.
var LISTENER_DEFAULTS = Object.freeze({
  mx:          Object.freeze({ port: 25,   enabled: true,  portVar: "BLAMEPOST_MX_PORT",
                               maxLineBytes: C.BYTES.kib(1) }),
  submission:  Object.freeze({ port: 587,  enabled: true,  portVar: "BLAMEPOST_SUBMISSION_PORT",
                               maxLineBytes: C.BYTES.kib(1) }),
  submissions: Object.freeze({ port: 465,  enabled: true,  portVar: "BLAMEPOST_SMTPS_PORT",
                               maxLineBytes: C.BYTES.kib(1) }),
  imap:        Object.freeze({ port: 143,  enabled: true,  portVar: "BLAMEPOST_IMAP_PORT",
                               maxLineBytes: C.BYTES.kib(8) }),
  pop3:        Object.freeze({ port: 110,  enabled: false, portVar: "BLAMEPOST_POP3_PORT",
                               maxLineBytes: C.BYTES.kib(1) }),
  managesieve: Object.freeze({ port: 4190, enabled: true,  portVar: "BLAMEPOST_MANAGESIEVE_PORT",
                               maxLineBytes: C.BYTES.kib(8) }),
});

// The range an operator's own line ceiling has to sit in. The floor is
// the 512 octets RFC 5321 section 4.5.3.1.4 requires an SMTP server to
// accept, so no setting can put a listener below what its standard
// obliges it to read. The ceiling bounds what one connection can hold
// unterminated in memory, once per connection.
var MIN_LINE_BYTES = 512;
var MAX_LINE_BYTES = C.BYTES.kib(64);

var LISTENER_NAMES = Object.keys(LISTENER_DEFAULTS);

// What each ceiling under `limits` is when the operator names none.
//
// Every one of these is published in the operator guide's ceilings table
// beside the field that moves it, so each number is a promise this server
// makes twice: once to whoever reads the document, and once on the wire,
// where the message ceiling goes out as the SIZE keyword of RFC 1870 on
// every EHLO.
//
// Written out here rather than left to the layer that applies them. A
// ceiling an operator sets reaches the listener and the message store
// because they set it; a ceiling they leave alone reaches whatever those
// layers put there when nobody names one, and without this table what
// they put there is the vendored framework's own. That is a number this
// repository publishes and does not choose, and no configuration makes
// the difference visible: the two agree until a refresh moves one.
//
// The message ceiling is the one where the two layers can also disagree
// with each other. The listeners advertise it as SIZE and a message
// store built without it applies the framework's fifty mebibytes for the
// message and twenty-five for its body, so a thirty mebibyte message is
// invited by the keyword, transferred in full, and refused at the append
// after the peer has sent every octet.
var LIMIT_DEFAULTS = Object.freeze({
  // How many connections one source address may hold open at once, per
  // listener.
  maxConcurrentConnectionsPerIp: 10,
  // New connections one source address may open in a rolling minute.
  connectionsPerIpPerMinute:     60,
  // Failed sign-ins from one source address in a rolling fifteen
  // minutes before that address is refused outright.
  authFailuresPerIpPer15Min:     10,
  // Refused recipients from one source address in a rolling minute.
  // This one bounds address enumeration rather than load.
  rcptFailuresPerIpPerMinute:    50,
  // The largest message this server accepts, in octets: fifty
  // mebibytes. It is the SIZE keyword the two SMTP listeners advertise,
  // the ceiling the message store applies at append, and the message
  // and body caps every MIME parse in this server runs under.
  maxMessageBytes:               52428800,
});

// The one listener an operator opts into, which is why it carries a
// switch of its own as well as a section in the table.
var POP3_LISTENER = "pop3";

// The listener table variable, named here because two of the refusals
// below have to tell an operator which of the two forms to keep.
var LISTENERS_VAR = "BLAMEPOST_LISTENERS";

// The CIDR policy every address range in this file is held to. Two
// settings write one: the relay allowlist, which is refused, and the
// trusted proxy list, which is honored.
//
// The relay setting is refused, and its shape is still checked, because
// the two answer different questions and an operator gets more from both
// than from either. A range written as `192.0.2.7` or as `the office`
// is a typo, and reading it back in the refusal below tells the
// operator what the server thought they meant. Checking the shape first
// also keeps the refusal about the decision rather than about the
// spelling: the message names the listener to move the device to, which
// is useless advice attached to a value that was never a range.
//
// A mask is required because the range arithmetic never matches a bare
// address, and the reserved and private ranges are allowed because
// naming 10.0.0.0/8 is what an operator writing either setting means. A
// network address with host bits set is accepted and masked off.
var CIDR_OPTS = Object.freeze({
  requireMaskPolicy:      "reject-bare-ip",
  reservedRangesPolicy:   "allow",
  ipv4MappedIpv6Policy:   "allow",
  networkAlignmentPolicy: "audit",
  family:                 "either",
});

// The hosted DNS providers the zone writer speaks to, and the value that
// names none of them.
//
// `none` is the shipped answer and it is an absence rather than a
// provider: with it set, nothing builds a provider client, nothing opens
// the credential, and this server makes no request to a DNS provider at
// all. The other settings in the group are refused while it stands,
// because a sealed token and an MX switch that reach nothing are the
// shape an operator cannot tell apart from a zone writer that is on.
var ZONE_PROVIDER_NONE = "none";
var ZONE_PROVIDERS = [ZONE_PROVIDER_NONE, "cloudflare"];

var REDACTED = "[redacted]";

// The environment variable that selects the configuration file. It is
// the one setting the file itself cannot carry.
var CONFIG_PATH_VAR = "BLAMEPOST_CONFIG";

// RFC 3339 section 5.6, the profile RFC 9116 section 2.5.5 requires for
// the security.txt Expires field.
var RFC3339_RE = /^\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/;

// RFC 3986 section 3.1. A security.txt contact is a URI, so a bare
// address with no scheme is refused rather than published as one.
var URI_SCHEME_RE = /^[A-Za-z][A-Za-z0-9+.-]*:/;

// RFC 9116 section 4 forbids a field value carrying a line break, and a
// URI carries no unescaped space. Both are checked here so a value that
// would split one line into two is refused before it reaches the file.
var URI_FORBIDDEN_RE = /[\x00-\x20\x7f]/;

// An MTA-STS policy may name an MX host with a wildcard in the leftmost
// label (RFC 8461 section 3.1), which the domain guard refuses on its
// own, so the label is removed before validating what follows it.
var MX_WILDCARD_PREFIX = "*.";

// The canonical setting table. `key` is the JSON key in the file and
// the property on the loaded object; `env` is the environment variable
// that overrides it. Adding a setting means adding a row here, a
// default, and a line in docs/operator-guide.md.
//
// A row is also a shape. `kind` names the check, and the composite
// kinds carry the shape of what they hold: `fields` for an object whose
// field names are fixed, `keys` plus `value` for an object whose keys
// come from a known set and whose values share one shape, and `element`
// for an array.
var SETTINGS = [
  {
    key:      "hostname",
    env:      "BLAMEPOST_HOSTNAME",
    kind:     "hostname",
    required: true,
    describe: "the public MX hostname this server answers for, such as mx.example.com",
  },
  {
    key:      "dataDir",
    env:      "BLAMEPOST_DATA_DIR",
    kind:     "path",
    fallback: DEFAULT_DATA_DIR,
    describe: "the single data directory holding the database, message blobs, the outbound spool, DKIM keys and certificates",
  },
  {
    key:      "httpPort",
    env:      "BLAMEPOST_HTTP_PORT",
    kind:     "port",
    fallback: 8080,
    describe: "the TCP port serving webmail, the admin interface and JMAP over HTTP",
  },
  {
    key:      "httpsPort",
    env:      "BLAMEPOST_HTTPS_PORT",
    kind:     "port",
    fallback: 8443,
    describe: "the TCP port serving the same interfaces over HTTPS when TLS terminates in this process",
  },
  {
    key:      "trustedProxies",
    env:      "BLAMEPOST_TRUSTED_PROXIES",
    kind:     "array",
    element:  { kind: "cidr" },
    // A ceiling on the list rather than on what it can express. A
    // deployment puts one terminator in front of this server, or a small
    // pool of them, and a list running to dozens of ranges is a range
    // written one address at a time.
    maxLength: 32,
    expects:  "a JSON array of address ranges, such as [\"192.0.2.0/24\"]",
    fallback: null,
    describe: "the address ranges of the reverse proxies whose X-Forwarded-Proto this server " +
              "believes when it decides whether the browser reached it over TLS. A request " +
              "from any other peer is read from this process's own socket and the header is " +
              "ignored, so naming nobody, which is the default, means the browser port " +
              "accepts a password only over TLS or from this machine. It governs the " +
              "transport and nothing else: the source address stays the socket's, so every " +
              "browser behind one proxy counts as one source against a per-address bound",
  },
  {
    key:      "publicSiteEnabled",
    env:      "BLAMEPOST_PUBLIC_SITE_ENABLED",
    kind:     "boolean",
    fallback: false,
    // The value a first boot starts from, and nothing more. The
    // administration console writes the operator's answer to the
    // settings table, and the server reads the stored answer in front of
    // this one, so editing this after the console has been used changes
    // what a volume with no row would start from rather than what this
    // server serves.
    describe: "whether the root of the browser port serves a public page describing this " +
              "software, which it does not by default",
  },
  {
    key:      "vaultPassphrase",
    env:      "BLAMEPOST_VAULT_PASSPHRASE",
    kind:     "secret",
    required: true,
    minChars: MIN_VAULT_PASSPHRASE_CHARS,
    secret:   true,
    describe: "the passphrase that seals DKIM private keys and every sealed database column",
  },
  {
    key:      "adminEmail",
    env:      "BLAMEPOST_ADMIN_EMAIL",
    kind:     "email",
    fallback: null,
    describe: "the address of the administrator account created on first boot",
  },
  {
    key:      "adminPassword",
    env:      "BLAMEPOST_ADMIN_PASSWORD",
    kind:     "secret",
    fallback: null,
    secret:   true,
    describe: "the password for the administrator account, read on first boot only",
  },
  {
    key:      "tlsCert",
    env:      "BLAMEPOST_TLS_CERT",
    kind:     "file",
    fallback: null,
    describe: "the certificate chain every listener presents, set together with tlsKey; serve refuses to start without the pair",
  },
  {
    key:      "tlsKey",
    env:      "BLAMEPOST_TLS_KEY",
    kind:     "file",
    fallback: null,
    describe: "the private key matching tlsCert",
  },
  {
    key:      "dnsAcknowledged",
    env:      "BLAMEPOST_DNS_ACKNOWLEDGED",
    kind:     "boolean",
    fallback: false,
    describe: "the operator's confirmation that MX, SPF, DMARC, DKIM, MTA-STS and TLS-RPT records exist, which the MX listener refuses to bind without",
  },
  {
    key:      "logLevel",
    env:      "BLAMEPOST_LOG_LEVEL",
    kind:     "enum",
    values:   LOG_LEVELS,
    fallback: DEFAULT_LOG_LEVEL,
    describe: "whether the framework's own recovery diagnostics are written, which only " +
              "debug turns on; the levels above info select nothing further, because info, " +
              "warn and error are written whatever this says",
  },
  {
    key:      "pop3Enabled",
    env:      "BLAMEPOST_POP3_ENABLED",
    kind:     "boolean",
    fallback: false,
    describe: "whether the POP3 listeners bind, which they do not by default",
  },
  {
    key:      "profile",
    env:      "BLAMEPOST_PROFILE",
    kind:     "enum",
    values:   GUARD_PROFILES,
    fallback: "strict",
    describe: "how strictly the wire protocols judge a domain, a HELO name and a command line; " +
              "balanced widens strict to accept punycode and non-latin scripts, which a server " +
              "receiving mail from internationalized domains needs",
  },
  {
    key:      "listeners",
    env:      LISTENERS_VAR,
    kind:     "object",
    keys:     LISTENER_NAMES,
    value:    {
      kind:   "object",
      expects: "an object of { enabled, port, address, maxLineBytes }",
      fields: {
        enabled: { kind: "boolean" },
        port:    { kind: "port" },
        address: { kind: "address" },
        // The longest command line this listener reads before refusing
        // one. A listener the configuration does not name applies the
        // number in LISTENER_DEFAULTS above.
        maxLineBytes: { kind: "integer", min: MIN_LINE_BYTES, max: MAX_LINE_BYTES },
      },
    },
    expects:  "a JSON object keyed by listener name (" + LISTENER_NAMES.join(", ") +
              "), each holding { enabled, port, address, maxLineBytes }",
    fallback: null,
    describe: "which protocol listeners bind and on which port and interface; a listener the " +
              "configuration does not name takes the documented default port, and one listener's " +
              "port alone can be moved with the variable named for it instead",
  },
  {
    key:      "limits",
    env:      "BLAMEPOST_LIMITS",
    kind:     "object",
    fields:   {
      // The largest message this server accepts, which an operator may
      // lower and may not raise.
      //
      // The bound the shipped value answers to is memory rather than
      // processor time. Each arriving chunk is scanned once and the
      // whole body is assembled when the terminator lands, so the cost
      // of reading a message is proportional to its size. But that
      // assembled body is resident for the length of the transaction,
      // once per message in flight, and a listener accepts a great many
      // connections at once. The ceiling therefore bounds resident
      // bytes multiplied by concurrent transfers, which is the number
      // that decides whether a busy minute is survivable. The floor is
      // the other end of the same judgement, because a ceiling below a
      // few tens of kilobytes refuses ordinary mail carrying a
      // signature and a couple of headers.
      //
      // The ceiling is the shipped value itself, and the reason is what
      // sits downstream. A message this server accepts is sealed and
      // written as one file, and the seal puts base64 inside base64, so
      // the file is sixteen ninths of the message: fifty mebibytes of
      // mail is an eighty-nine mebibyte file, against the ninety-six the
      // read path serving IMAP BODY[] will open. A higher ceiling here
      // would be accepted at boot and would fail at delivery: the server
      // would store messages nothing can fetch afterwards. Raising it is
      // a change to that read cap first.
      maxMessageBytes:               { kind: "integer", min: C.BYTES.kib(64),
                                       max: LIMIT_DEFAULTS.maxMessageBytes },
      // How many connections one source address may hold open at once,
      // per listener. The framework defaults to ten, which suits a peer
      // delivering mail and does not suit a mailbox client: a single
      // mail client keeps several IMAP connections open, and a
      // household or an office reaches the whole server behind one
      // address, so the ceiling that protects port 25 from a stranger
      // is the one that locks the operator's own users out. Raise it
      // for a deployment whose users share an address; leave it for a
      // server whose peers are other mail servers.
      maxConcurrentConnectionsPerIp: { kind: "integer", min: 1, max: 1024 },
      connectionsPerIpPerMinute:     { kind: "integer", min: 1, max: 10000 },
      // Failed sign-ins from one address inside a rolling fifteen
      // minutes before that address is refused outright. It bounds
      // credential stuffing; it is not the per-account budget, which
      // the identity layer keeps separately so one hostile source
      // cannot spend an account holder's own allowance.
      authFailuresPerIpPer15Min:     { kind: "integer", min: 1, max: 1000 },
      // Refused recipients from one address inside a rolling minute
      // before that address is answered temporarily instead.
      //
      // This one is not about load. The MX listener answers an address
      // it does not host with a permanent refusal at RCPT, which is the
      // right answer for a legitimate sender and is also an oracle: a
      // stranger can walk a word list against it and learn which
      // addresses exist here. This is how many guesses a minute one
      // source gets, so the reason to lower it is a directory harvest
      // rather than a busy server.
      //
      // The floor is not one. A legitimate sender puts several
      // recipients on one connection, and a mailing list expanding to
      // this server can carry addresses that have since been closed, so
      // a ceiling set too low answers ordinary mail with temporary
      // failures and delays it. The shipped value leaves that traffic
      // alone and still makes enumeration slow enough to be worthless.
      rcptFailuresPerIpPerMinute:    { kind: "integer", min: 5, max: 10000 },
    },
    expects:  "a JSON object of { maxMessageBytes, maxConcurrentConnectionsPerIp, " +
              "connectionsPerIpPerMinute, authFailuresPerIpPer15Min, " +
              "rcptFailuresPerIpPerMinute }",
    fallback: null,
    describe: "the resource ceilings every listener holds against one source address: the " +
              "largest message accepted, how many connections that address may hold at once " +
              "and open per minute, how many failed sign-ins it gets in fifteen minutes, and " +
              "how many recipients it may have refused in a minute before it is answered " +
              "temporarily instead. That last one bounds address enumeration rather than " +
              "load. A field left unset keeps the shipped ceiling. Per-command line lengths " +
              "and idle timeouts are not settable: both have floors the mail RFCs require a " +
              "server to meet, and a value below one of them refuses correct clients",
  },
  {
    key:      "relayAllowedFor",
    env:      "BLAMEPOST_RELAY_ALLOWED_FOR",
    kind:     "array",
    element:  {
      kind:    "object",
      expects: "an object of { cidr, scope }",
      fields:  {
        cidr:  { kind: "cidr", required: true },
        scope: { kind: "text", maxChars: 64 },
      },
    },
    maxLength: 64,
    expects:  "a JSON array of { cidr, scope } entries, such as " +
              "[{\"cidr\":\"192.0.2.0/24\",\"scope\":\"branch office\"}]",
    fallback: null,
    describe: "the networks the MX listener would relay for, which this server refuses to do; " +
              "a device that needs to send through this server gets an account and uses the " +
              "submission listener instead",
    // Declared and refused. `refused` is the sentence an operator reads
    // when they set it, and it is a property of the row rather than a
    // branch somewhere in the loader so that the refusal travels with
    // the setting: whatever origin supplies the value, the same words
    // come back, and a second setting refused later needs no new code.
    refused:  "This server does not relay for a source address. Every listener it runs " +
              "requires STARTTLS before it will accept an envelope, so any device able to " +
              "reach this server is also able to authenticate to it: create an account for " +
              "the device and point it at the submission listener on port 587 or 465. Mail " +
              "sent that way is bound to the account that sent it, is signed for the domain " +
              "it claims, and produces a delivery report that account can read. A range " +
              "grants none of those, because an address says which network a message came " +
              "from and never which sender. Remove the setting to start the server.",
  },
  {
    key:      "inbound",
    env:      "BLAMEPOST_INBOUND",
    kind:     "object",
    fields:   {
      mode:        { kind: "enum", values: ["enforce", "monitor"] },
      onTemperror: { kind: "enum", values: ["defer", "accept"] },
    },
    expects:  "a JSON object of { mode, onTemperror }",
    fallback: null,
    describe: "how the MX listener acts on the SPF, DKIM and DMARC verdict it computes at the " +
              "end of DATA: enforce applies the sender's published policy and monitor records it " +
              "and delivers anyway, while onTemperror decides whether a DNS failure defers the " +
              "message or accepts it",
  },
  {
    key:      "postmaster",
    env:      "BLAMEPOST_POSTMASTER",
    kind:     "email",
    fallback: null,
    describe: "the envelope sender on every delivery status notification this server composes; " +
              "it defaults to mailer-daemon at this server's own hostname",
  },
  {
    key:      "outboundPolicy",
    env:      "BLAMEPOST_OUTBOUND_POLICY",
    kind:     "object",
    fields:   {
      mtaSts: { kind: "enum", values: ["enforce", "testing", "off"] },
      dane:   { kind: "enum", values: ["opportunistic", "enforce", "off"] },
      // The operator's statement that the resolver this server was given
      // validates DNSSEC. RFC 7672 §2.1.1 and §2.2 forbid using a TLSA
      // record that was not validated, so `dane: "enforce"` needs it and
      // is refused at boot without it.
      //
      // Nothing here can check the statement: it is a fact about the
      // resolver the operator pointed this server at, which may validate,
      // may forward to something that strips the authenticated-data bit,
      // or may be a public endpoint reached over DoH. Asserting it
      // falsely is worse than not running DANE, because it authenticates
      // peers against records anybody on the path could have rewritten
      // under a banner that says they were verified. So it is a
      // statement the operator makes, not one this server infers.
      dnssecValidated: { kind: "boolean" },
    },
    expects:  "a JSON object of { mtaSts, dane, dnssecValidated }",
    fallback: null,
    describe: "the transport security this server demands of the peers it delivers to: the " +
              "MTA-STS posture of RFC 8461 and the DANE posture of RFC 7672. Set " +
              "dnssecValidated only when the resolver this server uses really does validate " +
              "DNSSEC; dane \"enforce\" requires it, because a TLSA record that was not " +
              "validated must not be used",
  },
  {
    key:      "outboundRetry",
    env:      "BLAMEPOST_OUTBOUND_RETRY",
    kind:     "object",
    fields:   {
      maxAttempts: { kind: "integer", min: 1, max: 100 },
      backoffMs:   {
        kind:      "array",
        element:   { kind: "integer", min: C.TIME.seconds(1), max: C.TIME.days(7) },
        maxLength: 32,
        // The order is load-bearing, not a convention. The delivery path
        // indexes this by attempt number and reads the last entry as the
        // longest wait it may hold a message for, so a list that falls
        // rather than rises hands it the shortest one under that name.
        ascending: true,
        expects:   "an array of waits in milliseconds, each at least as long as the one before it",
      },
    },
    expects:  "a JSON object of { maxAttempts, backoffMs }",
    fallback: null,
    describe: "how long a message the peer deferred stays in the spool before its sender is " +
              "told it failed; the attempt count is bounded because a sender needs a delivery " +
              "status notification rather than an indefinite retry",
  },
  {
    key:      "outboundSpool",
    env:      "BLAMEPOST_OUTBOUND_SPOOL",
    kind:     "object",
    fields:   {
      // Waiting recipients rather than messages: the spool holds one
      // entry per recipient still to be delivered, because recipients on
      // different domains fail and recover independently. A message to
      // four people elsewhere is four entries.
      //
      // The ceiling on what an operator may raise it to is what the
      // sweep can walk on its schedule: every pass reads every
      // descriptor, so a depth in the millions spends the sweep's whole
      // interval reading files rather than delivering. The floor is one,
      // because a server that accepts no outbound mail at all is a
      // configuration nobody wants by accident, and zero would be it.
      maxMessages: { kind: "integer", min: 1, max: 1000000 },
      // The floor is the smallest message the listeners can be
      // configured to accept, since a queue that cannot hold one message
      // refuses every message. The ceiling is a whole ordinary volume;
      // past it the setting is not bounding anything.
      maxBytes:    { kind: "integer", min: C.BYTES.kib(64), max: C.BYTES.gib(512) },
    },
    expects:  "a JSON object of { maxMessages, maxBytes }",
    fallback: null,
    describe: "how much undelivered outbound mail this server holds before it starts refusing " +
              "new mail with a temporary code. The queue is what keeps a message a receiver " +
              "deferred, and it shares one volume with the mailboxes and the audit trail, so " +
              "it needs a bottom: past either ceiling a client is told to try again and keeps " +
              "its own copy, which is the one outcome that loses nothing. Mail arriving for " +
              "forwarding stops short of the ceiling so accounts on this server can still send",
  },
  {
    key:      "outboundTimeouts",
    env:      "BLAMEPOST_OUTBOUND_TIMEOUTS",
    kind:     "object",
    fields:   {
      mxLookupMs: { kind: "integer", min: 100,                max: C.TIME.minutes(5) },
      perHostMs:  { kind: "integer", min: C.TIME.seconds(1),  max: C.TIME.minutes(30) },
    },
    expects:  "a JSON object of { mxLookupMs, perHostMs }",
    fallback: null,
    describe: "how long an outbound attempt waits for the recipient domain's MX answer and for " +
              "the peer itself; the floors stop a value written in seconds from failing every " +
              "delivery and the ceilings stop one wedged peer from holding the spool",
  },
  {
    key:      "requireTls",
    env:      "BLAMEPOST_REQUIRE_TLS",
    kind:     "boolean",
    fallback: false,
    // Turning this on changes what happens to mail. RFC 8689 section 4.1
    // makes a peer that does not advertise REQUIRETLS an undeliverable
    // destination rather than one to fall back on, so the message is
    // offered to every MX host for the domain and then permanently
    // failed if none of them advertises it, and the sender is told. That
    // is the request being honored rather than a fault, and it is the
    // reason the default is off: a server that turns it on for every
    // envelope stops delivering to the many receivers that do not
    // implement the extension.
    describe: "whether every outbound envelope asks for REQUIRETLS (RFC 8689), which puts the " +
              "keyword on MAIL FROM for a peer that advertises it and permanently fails the " +
              "message when no MX host for the recipient's domain does; MTA-STS and DANE are " +
              "the transport protections applied to every outbound message whatever this is " +
              "set to",
  },
  {
    key:      "securityContact",
    env:      "BLAMEPOST_SECURITY_CONTACT",
    kind:     "array",
    element:  { kind: "uri" },
    maxLength: 16,
    expects:  "a JSON array of contact URIs, such as [\"mailto:security@example.com\"]",
    fallback: null,
    describe: "who a security researcher should write to, published at " +
              "/.well-known/security.txt; it defaults to postmaster at this server's hostname",
  },
  {
    key:      "securityPolicyUrl",
    env:      "BLAMEPOST_SECURITY_POLICY_URL",
    kind:     "array",
    element:  { kind: "url" },
    maxLength: 16,
    expects:  "a JSON array of HTTPS URLs",
    fallback: null,
    describe: "the disclosure policy page named in /.well-known/security.txt",
  },
  {
    key:      "securityTxtExpires",
    env:      "BLAMEPOST_SECURITY_TXT_EXPIRES",
    kind:     "timestamp",
    fallback: null,
    describe: "when the published /.well-known/security.txt stops being authoritative; leaving " +
              "it unset dates the file one year from the moment the server starts",
  },
  {
    key:      "compliancePosture",
    env:      "BLAMEPOST_COMPLIANCE_POSTURE",
    kind:     "enum",
    // One of the framework's four postures, plus this server's own
    // spelling for the setting being off. The reason the other three are
    // absent is worth more than the values themselves.
    //
    // Under hipaa, pci-dss or gdpr the mailbox agent refuses EVERY
    // operation whose actor does not carry a posture field it names:
    // purposeOfUse, pciScope, lawfulBasis. Those describe why a
    // particular access is lawful, which is a judgment about the
    // access rather than a property of the server, and this server has
    // no model that could supply one. The guard checks only that the
    // field is a non-empty string, so a constant would satisfy it, and
    // a constant is exactly what must not be written here: it would
    // manufacture an attestation nobody made and pass the control
    // while defeating it.
    //
    // soc2 names no actor field, so it is the one an operator can set
    // and still have a working mailbox. It is offered because a
    // retention floor is genuinely useful, not because this server is
    // making a claim about an audit.
    values:   ["none", "soc2"],
    fallback: "none",
    describe: "the regulatory posture the mailbox agent enforces when a message is expunged. " +
              "soc2 sets a one year floor below which a hard delete is refused, for the " +
              "account owner as much as for an administrator, so a message deleted today " +
              "stays on disk and stays readable until it is old enough to go. Set it only " +
              "if that is the promise you mean to make: the person pressing delete is not " +
              "told a regulator outranks them",
  },
  {
    key:      "dmarcForensicEnabled",
    env:      "BLAMEPOST_DMARC_FORENSIC_ENABLED",
    kind:     "boolean",
    fallback: false,
    // Off is the shipped answer, and it is a privacy posture rather than
    // a convenience. A forensic report is one failed message sent back at
    // the moment it failed, and its envelope belongs to somebody who has
    // no account on this server, was never told this server would hold
    // anything of theirs, and can reach no verb here to ask for it back.
    // The failing message itself is never stored on any setting, which
    // the store makes true by declaring no column it could go in; this
    // switch governs the envelope and the verdict beside it.
    describe: "whether the per-message DMARC failure reports of RFC 6591, which receivers " +
              "send to the address a ruf= tag names, are stored at all. Turning it on " +
              "stores third-party personal data: the sending address, the envelope sender " +
              "and the recipients of mail belonging to people who have no account here and " +
              "who cannot ask this server for it back. The failing message itself is never " +
              "stored whatever this says. Left off, a forensic report is refused rather " +
              "than filed",
  },
  {
    key:      "dmarcAggregateRetentionDays",
    env:      "BLAMEPOST_DMARC_AGGREGATE_RETENTION_DAYS",
    kind:     "integer",
    // A day is the floor because an aggregate report covers one, and a
    // window shorter than the period it measures destroys the counting
    // before it is complete. The ceiling is a little over a year, which
    // is the longest span a DMARC record's reporting interval makes any
    // sense over. Both are the bounds the store itself holds, in the unit
    // an operator writes.
    min:      1,
    max:      400,
    fallback: 30,
    describe: "how many days the counting from aggregate DMARC reports (RFC 7489 section " +
              "7.2) is kept before it is destroyed. It is the reading a policy is moved " +
              "on, so the window is how far back the console and the policy stepper can " +
              "look",
  },
  {
    key:      "dmarcForensicRetentionDays",
    env:      "BLAMEPOST_DMARC_FORENSIC_RETENTION_DAYS",
    kind:     "integer",
    // A month is the ceiling because these rows are somebody else's mail
    // and an operator who wants a year of them is asking for something
    // this server does not offer. The cross-field rule below is the other
    // half of the same bound.
    min:      1,
    max:      30,
    fallback: 7,
    describe: "how many days a stored forensic DMARC report is kept. It may not be longer " +
              "than dmarcAggregateRetentionDays, which is refused at start rather than at " +
              "the first sweep",
  },
  {
    key:      "mtaStsMode",
    env:      "BLAMEPOST_MTA_STS_MODE",
    kind:     "enum",
    values:   ["enforce", "testing", "none"],
    fallback: "enforce",
    describe: "the mode published in the MTA-STS policy this server serves (RFC 8461 section " +
              "3.2); testing collects reports without asking senders to refuse delivery",
  },
  {
    key:      "mtaStsMx",
    env:      "BLAMEPOST_MTA_STS_MX",
    kind:     "array",
    element:  { kind: "mxHost" },
    maxLength: 16,
    expects:  "a JSON array of MX hostnames, each optionally starting with a wildcard label",
    fallback: null,
    describe: "the MX hosts listed in the published MTA-STS policy; it defaults to this " +
              "server's own hostname, which is wrong the moment a second MX exists",
  },
  {
    key:      "mtaStsMaxAge",
    env:      "BLAMEPOST_MTA_STS_MAX_AGE",
    kind:     "integer",
    min:      86400,
    max:      31557600,
    fallback: 604800,
    describe: "how long in seconds a sender caches the published MTA-STS policy (RFC 8461 " +
              "section 3.2); a short lifetime is refreshed constantly and protects little, and " +
              "the ceiling is the one the specification sets",
  },
  {
    key:      "zoneProvider",
    env:      "BLAMEPOST_ZONE_PROVIDER",
    kind:     "enum",
    values:   ZONE_PROVIDERS,
    fallback: ZONE_PROVIDER_NONE,
    describe: "which hosted DNS provider this server may edit records at. Left at none, no " +
              "credential is opened, no provider client is built and nothing here makes an " +
              "outbound request to a DNS provider at all; the records stay the operator's to " +
              "publish by hand",
  },
  {
    key:      "zoneApiToken",
    env:      "BLAMEPOST_ZONE_API_TOKEN",
    kind:     "sealed",
    fallback: null,
    secret:   true,
    describe: "the provider API token, as this server's vault sealed it. It is the form " +
              "`blamepost zone token set` writes, and it is the only form this setting " +
              "accepts; supply it here when the deployment injects secrets through the " +
              "environment, and leave it unset to use the sealed token on the data volume",
  },
  {
    key:      "zoneAllowMxWrites",
    env:      "BLAMEPOST_ZONE_ALLOW_MX_WRITES",
    kind:     "boolean",
    fallback: false,
    // Off, and off is the whole posture. Repointing MX moves delivery
    // away from this server, so it is the one edit whose effect this
    // server cannot report on afterwards: mail stops arriving, and the
    // process that made the change is the process that would have said
    // so. Every other record in the write set fails visibly here.
    describe: "whether the zone writer may edit the mail exchanger record at a hosted " +
              "domain's apex. Repointing MX moves delivery away from this server, which is " +
              "the one change this server cannot report on afterwards, so it is a decision " +
              "an operator makes rather than a capability that arrives with the credential",
  },
  {
    key:      "zoneEndpoint",
    env:      "BLAMEPOST_ZONE_ENDPOINT",
    kind:     "url",
    fallback: null,
    describe: "the provider API address the zone writer sends to, for a deployment whose " +
              "outbound traffic goes through a proxy of its own; it defaults to the " +
              "provider's public API",
  },
  {
    key:      "zoneAllowInternalEndpoint",
    env:      "BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT",
    kind:     "boolean",
    fallback: false,
    // Separate from the address on purpose. The outbound guard refuses a
    // private, loopback or link-local address, and a proxy on one is
    // reached by an operator saying so rather than by naming an address
    // that happens to resolve there. Cloud metadata addresses stay
    // refused whatever this says.
    describe: "whether the address in zoneEndpoint may resolve inside a private, loopback " +
              "or link-local range, which is how a proxy on the operator's own network is " +
              "reached deliberately rather than by accident; it is refused without " +
              "zoneEndpoint, because the public API is not one of those addresses",
  },
];

var SETTING_BY_KEY = {};
for (var _si = 0; _si < SETTINGS.length; _si += 1) {
  SETTING_BY_KEY[SETTINGS[_si].key] = SETTINGS[_si];
}

// ---- value readers ----

// Environment values arrive as strings and file values arrive typed, so
// each reader accepts both shapes and refuses everything else. Every
// refusal is thrown by the caller with the origin attached, because the
// operator needs to know which of the two supplied the bad value.

var TRUE_WORDS  = ["1", "true", "yes", "on"];
var FALSE_WORDS = ["0", "false", "no", "off"];

function _readBoolean(value) {
  if (typeof value === "boolean") return value;
  if (typeof value !== "string") return null;
  var word = value.trim().toLowerCase();
  if (TRUE_WORDS.indexOf(word) !== -1)  return true;
  if (FALSE_WORDS.indexOf(word) !== -1) return false;
  return null;
}

function _readPort(value) {
  var n = null;
  if (typeof value === "number") n = value;
  else if (typeof value === "string" && /^[0-9]{1,5}$/.test(value.trim())) n = Number(value.trim());
  if (n === null || !Number.isInteger(n) || n < 1 || n > 65535) return null;
  return n;
}

function _readInteger(value) {
  var n = null;
  if (typeof value === "number") n = value;
  else if (typeof value === "string" && /^-?[0-9]{1,17}$/.test(value.trim())) n = Number(value.trim());
  if (n === null || !Number.isInteger(n)) return null;
  return n;
}

function _readString(value) {
  if (typeof value !== "string") return null;
  var text = value.trim();
  return text.length > 0 ? text : null;
}

// A guard reports every issue it found. The operator gets the kinds,
// which name the rule that fired, rather than a bare refusal.
function _issueKinds(issues) {
  var kinds = [];
  for (var i = 0; i < issues.length; i += 1) {
    var kind = issues[i] && issues[i].kind;
    if (kind && kinds.indexOf(kind) === -1) kinds.push(kind);
  }
  return kinds.join(", ");
}

// ---- error construction ----

// Where a value came from, phrased the way an operator would search for
// it: the variable name when the environment supplied it, the file path
// and key when the file did. `path` is the setting key for a plain
// value and the dotted route into it for a structured one, so a bad
// port inside a listener section says which listener.
function _origin(ctx, path) {
  if (ctx.from === "env") {
    return path === ctx.setting.key ? ctx.setting.env : ctx.setting.env + " at " + path;
  }
  if (ctx.from === "file") return ctx.configPath + ' key "' + path + '"';
  // The default is checked by the same code as an operator's value, so
  // a shipped default that its own shape refuses reads as what it is
  // rather than as a value the operator supplied and cannot find.
  if (ctx.from === "default") return "the built-in default for " + path;
  return path;
}

function _shown(value) {
  var text = JSON.stringify(value);
  if (typeof text !== "string") text = String(value);
  return text.length > MAX_SHOWN_CHARS ? text.slice(0, MAX_SHOWN_CHARS) + "..." : text;
}

function _bad(ctx, path, expected, value) {
  var shown = ctx.setting.secret ? REDACTED : _shown(value);
  return _err("config/bad-value",
    _origin(ctx, path) + ": expected " + expected +
    ", got " + shown + ". It sets " + ctx.setting.describe + ".");
}

// ---- file layer ----

function _resolveConfigPath(env, cwd) {
  var supplied = _readString(env[CONFIG_PATH_VAR]);
  return {
    path:     nodePath.resolve(cwd, supplied === null ? DEFAULT_CONFIG_PATH : supplied),
    explicit: supplied !== null,
  };
}

// Read the open file, refusing anything past the limit rather than
// materializing it first. The bound is on the READ, not on a size
// measured beforehand: a size and a later read of the same path are two
// separate lookups, and what satisfied the limit need not be what comes
// back. Reading through the descriptor that was measured, and stopping
// at the limit either way, removes both halves of that.
function _readBounded(fd, limit) {
  var buffer = Buffer.allocUnsafe(limit + 1);
  var filled = 0;
  while (filled < buffer.length) {
    var got = nodeFs.readSync(fd, buffer, filled, buffer.length - filled, null);
    if (got === 0) break;
    filled += got;
  }
  return {
    text:       buffer.toString("utf8", 0, Math.min(filled, limit)),
    overflowed: filled > limit,
  };
}

function _readConfigFile(resolved) {
  // One descriptor carries the whole read. Checking a path and then
  // reading it names the file twice, and the second name can resolve
  // somewhere else: the kind and the size that passed would then belong
  // to a file whose bytes were never the ones parsed.
  var fd;
  try {
    fd = nodeFs.openSync(resolved.path, "r");
  } catch (e) {
    if (e && e.code === "ENOENT") {
      if (resolved.explicit) {
        throw _err("config/file-missing",
          CONFIG_PATH_VAR + " names " + resolved.path + ", which does not exist. " +
          "Point it at a readable file, or unset it to configure the server from the environment alone.");
      }
      return {};
    }
    // Present and unreadable is not the same as absent, and treating it
    // as absent is how a server boots on defaults while the operator's
    // configuration sits on disk unread.
    throw _err("config/file-unreadable",
      resolved.path + " could not be opened: " + ((e && e.message) || String(e)) +
      ". The process needs read access to its own configuration file.");
  }

  var text;
  try {
    var stat = nodeFs.fstatSync(fd);
    if (!stat.isFile()) {
      throw _err("config/file-not-a-file",
        resolved.path + " is not a regular file. The configuration file is a single JSON document.");
    }
    var read = _readBounded(fd, MAX_CONFIG_FILE_BYTES);
    if (read.overflowed) {
      throw _err("config/file-too-large",
        resolved.path + " is larger than the " + MAX_CONFIG_FILE_BYTES +
        " byte limit for a configuration file.");
    }
    text = read.text;
  } finally {
    // Drop-silent by design: a descriptor that will not close must not
    // replace the refusal that is on its way out of this function.
    // allow:swallow-unverified a close that refuses cannot be induced without
    // faulting node:fs, and the descriptor goes with the process either way.
    try { nodeFs.closeSync(fd); } catch (_e) { /* the descriptor goes with the process */ }
  }

  var parsed;
  try {
    parsed = b.safeJson.parse(text, { maxBytes: MAX_CONFIG_FILE_BYTES });
  } catch (e) {
    throw _err("config/file-unparseable",
      resolved.path + " is not valid JSON: " + ((e && e.message) || String(e)));
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw _err("config/file-not-an-object",
      resolved.path + " must contain a JSON object mapping setting names to values.");
  }

  // The file is ours, so an unrecognized key in it is a typo worth
  // failing on. The environment is a shared namespace where other tools
  // legitimately keep their own variables, so only recognized names are
  // read from there.
  var keys = Object.keys(parsed);
  for (var i = 0; i < keys.length; i += 1) {
    if (!Object.prototype.hasOwnProperty.call(SETTING_BY_KEY, keys[i])) {
      throw _err("config/unknown-key",
        resolved.path + ' has no setting named "' + keys[i] + '". Recognized settings are: ' +
        Object.keys(SETTING_BY_KEY).sort().join(", ") + ".");
    }
  }
  return parsed;
}

// ---- per-setting resolution ----

function _isComposite(shape) {
  return shape.kind === "object" || shape.kind === "array";
}

function _resolveOne(setting, env, file, configPath, cwd) {
  var from  = "default";
  var value = setting.fallback === undefined ? null : setting.fallback;

  if (Object.prototype.hasOwnProperty.call(file, setting.key) && file[setting.key] !== null) {
    from  = "file";
    value = file[setting.key];
  }
  if (env[setting.env] !== undefined && String(env[setting.env]).trim().length > 0) {
    from  = "env";
    value = env[setting.env];
  }

  if (from === "default") {
    if (setting.required) {
      throw _err("config/missing-required",
        setting.env + " is required: it sets " + setting.describe +
        ". Set the environment variable, or the \"" + setting.key + '" key in ' + configPath + ".");
    }
    // A default that skipped the check would be the one value in the
    // loaded object nothing had looked at, and it would be the value
    // held by the operator who never touched the setting. It goes
    // through the same coercion, so a path is resolved and a bad
    // default is a boot failure naming itself rather than a surprise
    // downstream.
    if (value === null || value === undefined) return { value: null, from: from };
  }

  var ctx = { setting: setting, from: from, configPath: configPath, cwd: cwd };
  if (_isComposite(setting) && from === "env") {
    value = _parseEnvJson(ctx, setting.key, value);
  }
  return { value: _deepFreeze(_coerceShape(setting, value, ctx, setting.key)), from: from };
}

// ---- settings that are declared and refused ----

// Whether a resolved value asks for anything at all.
//
// A refused setting still has a spelling that means "I want none of
// this", and refusing that spelling would be a boot failure handed to an
// operator for agreeing with the server. An empty list and an empty
// object are that spelling; anything with an entry in it is a request.
//
// For a boolean the spelling is `false`, and it is the one case where
// the value carries the whole answer rather than its size. It is also
// the case that matters most, because a refused boolean's off position
// is normally the shipped default: an operator who reads the refusal and
// turns the setting off, or who writes the default down explicitly, must
// still boot. Falling through to the catch-all below would refuse them
// for complying.
function _asksForSomething(value) {
  if (value === null || value === undefined) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "boolean") return value;
  if (typeof value === "object") return Object.keys(value).length > 0;
  return true;
}

// Refuse a setting the server declares and does not honor, naming where
// the value came from and what to do instead.
//
// It runs after the value has been coerced, so the shape has already
// been checked and a malformed entry has already been refused as
// malformed. That ordering is deliberate: a range written as a
// hostname is a typo, and answering a typo with a paragraph about
// authenticated submission sends the operator to fix the wrong thing.
function _assertNotRefused(setting, value, from, configPath, cwd) {
  if (typeof setting.refused !== "string") return;
  if (!_asksForSomething(value)) return;
  var ctx = { setting: setting, from: from, configPath: configPath, cwd: cwd };
  throw _err("config/setting-refused",
    _origin(ctx, setting.key) + " is set, and this server does not honor it. " +
    setting.refused);
}

// A structured setting supplied through the environment is one line of
// JSON. Parsing it here rather than inventing a second grammar means
// the environment and the file are checked by the same code and cannot
// disagree about what a valid listener table looks like.
function _parseEnvJson(ctx, path, text) {
  var raw = String(text);
  try {
    return b.safeJson.parse(raw, { maxBytes: MAX_ENV_JSON_BYTES });
  } catch (e) {
    throw _bad(ctx, path,
      _expects(ctx.setting) + ", written as JSON (" + ((e && e.message) || String(e)) + ")",
      raw);
  }
}

function _expects(shape) {
  if (typeof shape.expects === "string") return shape.expects;
  if (shape.kind === "array")  return "a JSON array";
  return "a JSON object";
}

// ---- shape coercion ----

function _coerceShape(shape, value, ctx, path) {
  if (shape.kind === "object") return _coerceObject(shape, value, ctx, path);
  if (shape.kind === "array")  return _coerceArray(shape, value, ctx, path);
  return _coerceScalar(shape, value, ctx, path);
}

// The shape one field of an object is held to. A `fields` table names
// each field; a `keys` list plus a `value` shape covers an object whose
// keys come from a known set and whose values are all alike.
function _fieldShape(shape, name) {
  if (shape.fields) {
    return Object.prototype.hasOwnProperty.call(shape.fields, name) ? shape.fields[name] : null;
  }
  return shape.keys.indexOf(name) === -1 ? null : shape.value;
}

function _fieldNames(shape) {
  return shape.fields ? Object.keys(shape.fields) : shape.keys.slice();
}

function _coerceObject(shape, value, ctx, path) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw _bad(ctx, path, _expects(shape), value);
  }

  var out  = {};
  var seen = Object.keys(value);
  for (var i = 0; i < seen.length; i += 1) {
    var name  = seen[i];
    var child = _fieldShape(shape, name);
    if (child === null) {
      // The same reasoning as an unknown key in the file: a field this
      // server does not read is a typo, and accepting it silently is
      // how an operator ends up believing a setting took effect.
      throw _err("config/unknown-key",
        _origin(ctx, path) + ' has no field named "' + name + '". Recognized fields are: ' +
        _fieldNames(shape).sort().join(", ") + ".");
    }
    if (value[name] === undefined || value[name] === null) continue;
    out[name] = _coerceShape(child, value[name], ctx, path + "." + name);
  }

  if (shape.fields) {
    var names = Object.keys(shape.fields);
    for (var r = 0; r < names.length; r += 1) {
      if (shape.fields[names[r]].required !== true) continue;
      if (Object.prototype.hasOwnProperty.call(out, names[r])) continue;
      throw _bad(ctx, path + "." + names[r],
        "a value, because " + _expects(shape) + " carries it and this entry has none",
        value);
    }
  }
  return out;
}

function _coerceArray(shape, value, ctx, path) {
  if (!Array.isArray(value)) {
    throw _bad(ctx, path, _expects(shape), value);
  }
  if (shape.maxLength !== undefined && value.length > shape.maxLength) {
    throw _bad(ctx, path, "at most " + shape.maxLength + " entries", value.length);
  }
  var out = [];
  for (var i = 0; i < value.length; i += 1) {
    out.push(_coerceShape(shape.element, value[i], ctx, path + "[" + i + "]"));
  }
  if (shape.ascending === true) {
    for (var a = 1; a < out.length; a += 1) {
      if (out[a] >= out[a - 1]) continue;
      throw _bad(ctx, path + "[" + a + "]",
        "a value no smaller than the " + out[a - 1] + " before it, because the order is " +
        "what makes the last entry the longest", out[a]);
    }
  }
  return out;
}

function _coerceScalar(shape, value, ctx, path) {
  if (shape.kind === "boolean") {
    var flag = _readBoolean(value);
    if (flag === null) {
      throw _bad(ctx, path,
        "one of " + TRUE_WORDS.join(" / ") + " for true or " + FALSE_WORDS.join(" / ") + " for false",
        value);
    }
    return flag;
  }

  if (shape.kind === "port") {
    var port = _readPort(value);
    if (port === null) {
      throw _bad(ctx, path, "a TCP port number between 1 and 65535", value);
    }
    return port;
  }

  if (shape.kind === "integer") {
    var n = _readInteger(value);
    if (n === null || n < shape.min || n > shape.max) {
      throw _bad(ctx, path, "a whole number between " + shape.min + " and " + shape.max, value);
    }
    return n;
  }

  if (shape.kind === "enum") {
    var word = _readString(value);
    if (word === null || shape.values.indexOf(word) === -1) {
      throw _bad(ctx, path, "one of " + shape.values.join(", "), value);
    }
    return word;
  }

  var text = _readString(value);
  if (text === null) {
    throw _bad(ctx, path, "a non-empty string", value);
  }

  if (shape.kind === "text") {
    if (shape.maxChars && text.length > shape.maxChars) {
      throw _bad(ctx, path, "at most " + shape.maxChars + " characters", value);
    }
    return text;
  }

  if (shape.kind === "secret") {
    if (shape.minChars && text.length < shape.minChars) {
      throw _bad(ctx, path, "at least " + shape.minChars + " characters", value);
    }
    return text;
  }

  // A credential this server's vault already sealed. The prefix is the
  // only thing separating a sealed value from whatever somebody typed,
  // because opening a seal passes an unsealed value straight through: a
  // token written here in the clear would authenticate exactly as well
  // as the sealed one while being readable to everyone who can read the
  // file it sits in. The refusal quotes nothing back, since the row is
  // marked secret.
  //
  // The credential is sealed with `b.vault.aad`, bound to its purpose. A
  // value carrying the vault's plain seal is sealed, so it is not exposed,
  // and it is some other value the volume sealed rather than the token.
  if (shape.kind === "sealed") {
    if (text.indexOf(C.VAULT_PREFIX) === 0) {
      throw _bad(ctx, path,
        "a value sealed the way `blamepost zone token set` seals a provider token. This " +
        "one carries the vault's plain seal, so it is some other value this volume sealed, " +
        "such as a signing key, rather than the token. Seal the provider token with " +
        "`blamepost zone token set` and store what it writes", value);
    }
    if (!b.vault.aad.isAadSealed(text)) {
      throw _bad(ctx, path,
        "a value this server's vault sealed, which is what " +
        "`blamepost zone token set` writes. The credential itself is never a configuration " +
        "value. Treat whatever is here now as exposed: issue a replacement at the provider, " +
        "seal that one, and store the sealed form", value);
    }
    return text;
  }

  if (shape.kind === "hostname") {
    var host = address.parseDomain(text);
    if (!host.ok) {
      throw _bad(ctx, path,
        "a fully qualified domain name (refused for: " + _issueKinds(host.detail) + ")", value);
    }
    return host.domain;
  }

  if (shape.kind === "mxHost") {
    var wild = text.slice(0, MX_WILDCARD_PREFIX.length) === MX_WILDCARD_PREFIX;
    var mx   = address.parseDomain(wild ? text.slice(MX_WILDCARD_PREFIX.length) : text);
    if (!mx.ok) {
      throw _bad(ctx, path,
        "an MX hostname, optionally starting with a wildcard label such as *.example.com " +
        "(refused for: " + _issueKinds(mx.detail) + ")", value);
    }
    return (wild ? MX_WILDCARD_PREFIX : "") + mx.domain;
  }

  // An address, read through the same derivation the hostname above is
  // read through and the store keys its rows on. Asking the framework's
  // address guard and folding the answer by hand is most of a derivation
  // and is not one: a case fold settles what RFC 4343 says is not a
  // difference and leaves the DNS root's dot where it is, so it agrees
  // with the identity layer on three spellings of every name and
  // disagrees on the fourth. What is stored is what the derivation
  // returns, so a setting and the mailbox it names are one string.
  if (shape.kind === "email") {
    var addr = address.parse(text);
    if (!addr.ok) {
      // A refusal about the SHAPE carries guard issues and a refusal
      // about the string itself carries only the reason, so the reason
      // stands in rather than leaving an operator an empty parenthesis
      // where the cause should be.
      throw _bad(ctx, path,
        "an email address (refused for: " + (_issueKinds(addr.detail) || addr.reason) + ")",
        value);
    }
    return addr.written;
  }

  if (shape.kind === "url") {
    try {
      b.safeUrl.parse(text, { allowedProtocols: b.safeUrl.ALLOW_HTTP_TLS, errorClass: ConfigError });
    } catch (e) {
      throw _bad(ctx, path, "an HTTPS URL (" + ((e && e.message) || String(e)) + ")", value);
    }
    return text;
  }

  if (shape.kind === "uri") return _coerceUri(ctx, path, text, value);

  if (shape.kind === "cidr") {
    // The mask is what makes an entry matchable. A bare address, an
    // out of range prefix or anything the guard cannot parse would sit
    // in the allowlist matching nothing, which reads like a configured
    // range and is not one.
    var range = b.guardCidr.validate(text, CIDR_OPTS);
    if (!range.ok) {
      throw _bad(ctx, path,
        "an address range written as <address>/<prefix>, such as 192.0.2.0/24 or " +
        "2001:db8::/32 (refused for: " + _issueKinds(range.issues) + ")", value);
    }
    return text;
  }

  if (shape.kind === "address") {
    if (nodeNet.isIP(text) === 0) {
      throw _bad(ctx, path,
        "an interface address, such as 0.0.0.0 for every IPv4 interface, :: for every " +
        "interface, or one address of this host", value);
    }
    return text;
  }

  if (shape.kind === "timestamp") {
    if (!RFC3339_RE.test(text)) {
      throw _bad(ctx, path,
        "an RFC 3339 timestamp such as 2027-01-01T00:00:00Z", value);
    }
    var when = Date.parse(text);
    if (!isFinite(when)) {
      throw _bad(ctx, path, "an RFC 3339 timestamp naming a real instant", value);
    }
    if (when <= Date.now()) {
      // RFC 9116 section 2.5.5 requires a timestamp that has not passed,
      // and the middleware that publishes the file refuses one that has.
      // Refusing it here names the setting and where it came from, which
      // is what an operator needs in order to find it.
      throw _bad(ctx, path, "an RFC 3339 timestamp that has not already passed", value);
    }
    return text;
  }

  if (shape.kind === "file") {
    var filePath = nodePath.resolve(ctx.cwd, text);
    // Absent, or unreadable to this process. Either way there is no file
    // here to present, and the refusal below says so with the resolved
    // path an operator can check.
    var stat;
    try {
      stat = nodeFs.statSync(filePath);
    } catch (_e) {
      stat = null;
    }
    if (stat === null) {
      throw _bad(ctx, path,
        "a path to an existing readable file (resolved to " + filePath + ")", value);
    }
    // A directory passes an existence check and then fails at the first
    // read, inside whichever subsystem opened it, with an error naming
    // neither the setting nor the operator who set it.
    if (!stat.isFile()) {
      throw _bad(ctx, path,
        "a path to a regular file, not a directory or a device (resolved to " +
        filePath + ")", value);
    }
    return filePath;
  }

  // shape.kind === "path"
  //
  // A directory this server creates and writes under. The path need not
  // exist, because the first boot is the boot that makes it, so absence
  // is not a fault here. Something already sitting there that is not a
  // directory is, and it is read at the same door the certificate paths
  // above are read at. Without the check a regular file in this position
  // passes every reader in this file and fails inside `node:fs` as
  // `EEXIST: file already exists, mkdir '<path>'`, which names neither
  // the setting nor the entry under it.
  //
  // Whether the path can be READ is not asked. A value the process cannot
  // stat is left to `ensureDataDirectories`, which is the call that has to
  // act on it and names the entry when it cannot.
  var dirPath = nodePath.resolve(ctx.cwd, text);
  var dirStat;
  try {
    dirStat = nodeFs.statSync(dirPath);
  } catch (_e) {
    dirStat = null;
  }
  if (dirStat !== null && !dirStat.isDirectory()) {
    throw _bad(ctx, path,
      "a path to a directory, or to nothing yet (resolved to " + dirPath +
      ", which is not a directory)", value);
  }
  return dirPath;
}

// A security.txt contact. RFC 9116 section 2.5.3 requires a URI, so a
// bare address is refused rather than published as a line no client can
// act on. An https contact goes through the same URL check the rest of
// this file uses, and a mailto contact has its address checked, so a
// typo in either is a boot failure rather than an unreachable line in a
// published document.
function _coerceUri(ctx, path, text, value) {
  if (URI_FORBIDDEN_RE.test(text)) {
    throw _bad(ctx, path, "a URI carrying no spaces and no control characters", value);
  }
  if (!URI_SCHEME_RE.test(text)) {
    throw _bad(ctx, path,
      "a URI carrying a scheme, such as mailto:security@example.com or " +
      "https://example.com/security", value);
  }
  var scheme = text.slice(0, text.indexOf(":")).toLowerCase();
  if (scheme === "http" || scheme === "https") {
    try {
      b.safeUrl.parse(text, { allowedProtocols: b.safeUrl.ALLOW_HTTP_TLS, errorClass: ConfigError });
    } catch (e) {
      throw _bad(ctx, path, "an HTTPS URL (" + ((e && e.message) || String(e)) + ")", value);
    }
    return text;
  }
  if (scheme === "mailto") {
    // The address inside the URI, read through the identity layer's
    // derivation rather than the framework guard underneath it, so a
    // contact spelled with the DNS root's dot or in another case is the
    // legitimate URI it is rather than a boot failure. The URI is
    // published back to the reader as the operator wrote it: this is a
    // document they author, and nothing keys on the address, so the
    // check is a gate and the text stays theirs.
    var addr = text.slice("mailto:".length).split("?")[0];
    var verdict = address.parse(addr);
    if (!verdict.ok) {
      throw _bad(ctx, path,
        "a mailto URI naming an address (refused for: " +
        (_issueKinds(verdict.detail) || verdict.reason) + ")", value);
    }
    return text;
  }
  return text;
}

// The loaded configuration is shared by every subsystem, so a nested
// object left mutable is a setting one of them could rewrite for all
// the others.
function _deepFreeze(value) {
  if (value === null || typeof value !== "object") return value;
  var keys = Object.keys(value);
  for (var i = 0; i < keys.length; i += 1) _deepFreeze(value[keys[i]]);
  return Object.freeze(value);
}

// ---- the narrow per-listener port variables ----

// The shape one port variable is held to. It borrows the setting row's
// machinery so a bad value is refused by the same code, with the same
// message, as a port written anywhere else. The row it borrows names the
// variable the operator actually set rather than the table it lands in.
function _portVarSetting(name) {
  return {
    key:      "listeners." + name + ".port",
    env:      LISTENER_DEFAULTS[name].portVar,
    kind:     "port",
    describe: "the TCP port the " + name + " listener binds",
  };
}

// A frozen listener table cannot take an override, so the sections are
// copied out one level before one is written into.
function _thawSections(sections) {
  var out = {};
  if (sections === null || sections === undefined) return out;
  var names = Object.keys(sections);
  for (var i = 0; i < names.length; i += 1) {
    out[names[i]] = Object.assign({}, sections[names[i]]);
  }
  return out;
}

// Fold every per-listener port variable into the listener table.
//
// Against a port written in the configuration file the variable simply
// wins, which is the rule every other setting follows. Against the
// listener table in the same environment it refuses: two environment
// variables setting one port means one of them does nothing, and the
// operator who later edits the wrong one gets a server that ignores the
// change without saying so.
function _applyListenerPortVars(sections, listenersFrom, env, configPath, cwd) {
  var merged = null;
  for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
    var name = LISTENER_NAMES[i];
    var variable = LISTENER_DEFAULTS[name].portVar;
    var raw = env[variable];
    if (raw === undefined || String(raw).trim().length === 0) continue;

    var already = sections !== null && sections !== undefined &&
      sections[name] !== undefined && sections[name].port !== undefined;
    if (already && listenersFrom === "env") {
      throw _err("config/conflicting-settings",
        variable + " and " + LISTENERS_VAR + " both set the port of the " + name +
        " listener. One of the two is doing nothing, so the next change to it changes " +
        "nothing on the server. Keep one: " + variable + " moves this listener alone, and " +
        LISTENERS_VAR + " carries the whole table.");
    }

    if (merged === null) merged = _thawSections(sections);
    var setting = _portVarSetting(name);
    var ctx = { setting: setting, from: "env", configPath: configPath, cwd: cwd };
    merged[name] = Object.assign({}, merged[name], {
      port: _coerceScalar({ kind: "port" }, raw, ctx, setting.key),
    });
  }
  return merged === null ? sections : _deepFreeze(merged);
}

// ---- cross-setting rules ----

// What each listener will actually do, which is what a port collision is
// about. A listener the configuration never names is not absent: it
// binds its documented port, and that is the port a second listener
// moved onto it collides with.
function _effectiveListeners(out) {
  var sections = out.listeners || {};
  var table = {};
  for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
    var name = LISTENER_NAMES[i];
    var fallback = LISTENER_DEFAULTS[name];
    var section = sections[name] || {};
    var enabled = fallback.enabled;
    if (name === POP3_LISTENER) enabled = out.pop3Enabled === true;
    if (section.enabled !== undefined) enabled = section.enabled;
    table[name] = {
      enabled:  enabled === true,
      port:     section.port === undefined ? fallback.port : section.port,
      declared: section.port !== undefined,
    };
  }
  return table;
}

// Every port this process will try to bind, counted once. A duplicate is
// an operating system error at start, raised by whichever listener came
// second, naming a number and no listener. It is also raised after the
// earlier listeners are already accepting connections, so the failure
// leaves a server that is half up.
function _assertPortsAreClaimedOnce(out) {
  var effective = _effectiveListeners(out);
  var claims = [];
  for (var i = 0; i < LISTENER_NAMES.length; i += 1) {
    var name = LISTENER_NAMES[i];
    if (!effective[name].enabled) continue;
    claims.push({
      port:  effective[name].port,
      label: "the " + name + " listener" +
             (effective[name].declared ? "" : " on its default port"),
    });
  }
  claims.push({ port: out.httpPort,  label: "the browser and JMAP surface (BLAMEPOST_HTTP_PORT)" });
  claims.push({ port: out.httpsPort, label: "the same surface over TLS (BLAMEPOST_HTTPS_PORT)" });

  var byPort = {};
  for (var c = 0; c < claims.length; c += 1) {
    var claim = claims[c];
    var first = byPort[claim.port];
    if (first !== undefined) {
      throw _err("config/port-collision",
        "port " + claim.port + " is claimed twice: " + first.label + " and " + claim.label +
        ". One process cannot bind one port twice. A listener the configuration does not " +
        "name still binds its documented port, so moving another one onto it collides with " +
        "a listener nothing wrote down.");
    }
    byPort[claim.port] = claim;
  }
}

function _assertCoherent(out, origins, configPath) {
  if (out.httpPort === out.httpsPort) {
    throw _err("config/port-collision",
      "BLAMEPOST_HTTP_PORT and BLAMEPOST_HTTPS_PORT are both " + out.httpPort +
      ". One process cannot serve cleartext and TLS on the same port.");
  }

  if ((out.tlsCert === null) !== (out.tlsKey === null)) {
    var supplied = out.tlsCert === null ? "BLAMEPOST_TLS_KEY" : "BLAMEPOST_TLS_CERT";
    var absent   = out.tlsCert === null ? "BLAMEPOST_TLS_CERT" : "BLAMEPOST_TLS_KEY";
    throw _err("config/incomplete-tls-pair",
      supplied + " is set but " + absent + " is not. The listeners need both halves, so half " +
      "a pair is a typo rather than a posture. Point both at the certificate and key this " +
      "server should present.");
  }

  if ((out.adminEmail === null) !== (out.adminPassword === null)) {
    var half  = out.adminEmail === null ? "BLAMEPOST_ADMIN_PASSWORD" : "BLAMEPOST_ADMIN_EMAIL";
    var other = out.adminEmail === null ? "BLAMEPOST_ADMIN_EMAIL" : "BLAMEPOST_ADMIN_PASSWORD";
    throw _err("config/incomplete-admin-pair",
      half + " is set but " + other + " is not. Creating the administrator account on first boot needs both, " +
      "or leave both unset and create the account with the command line interface.");
  }

  if (out.adminEmail !== null && out.adminPassword === out.vaultPassphrase) {
    throw _err("config/reused-secret",
      "BLAMEPOST_ADMIN_PASSWORD and BLAMEPOST_VAULT_PASSPHRASE hold the same value. " +
      "One unlocks the sealed store and one logs in to a mailbox; sharing them turns a login " +
      "credential into the key for everything at rest.");
  }

  // POP3 is the one listener an operator opts into, so it has a switch
  // as well as a section, and the section is the more specific of the
  // two. An operator who set both to disagree wrote down one intention
  // and got the other, which is worth a refusal naming both rather than
  // a silent precedence rule nobody reads.
  var pop3Section = (out.listeners || {})[POP3_LISTENER];
  if (origins.pop3Enabled !== "default" && pop3Section !== undefined &&
      pop3Section.enabled !== undefined && pop3Section.enabled !== out.pop3Enabled) {
    throw _err("config/conflicting-settings",
      "BLAMEPOST_POP3_ENABLED says the POP3 listeners are " +
      (out.pop3Enabled ? "on" : "off") + " and listeners." + POP3_LISTENER +
      ".enabled says they are " + (pop3Section.enabled ? "on" : "off") +
      ". Set one of the two: the variable is the switch, and the listener section is for " +
      "the port and interface it binds.");
  }

  // The forensic window is the shorter of the two report windows, and the
  // two are not interchangeable. An aggregate row is a count; a forensic
  // row carries the sending address, the envelope sender and the
  // recipients of one message belonging to somebody with no account on
  // this server. Written the other way round, that envelope outlives the
  // counting it belongs to, which is the one ordering these settings must
  // not hold.
  //
  // It is refused whatever dmarcForensicEnabled says. Waiting for the
  // switch would leave the wrong pair on disk until the moment somebody
  // turns forensic reports on, and that is the moment they are least
  // placed to read a boot failure about retention.
  if (out.dmarcForensicRetentionDays > out.dmarcAggregateRetentionDays) {
    throw _err("config/retention-window-order",
      "BLAMEPOST_DMARC_FORENSIC_RETENTION_DAYS is " + out.dmarcForensicRetentionDays +
      " and BLAMEPOST_DMARC_AGGREGATE_RETENTION_DAYS is " + out.dmarcAggregateRetentionDays +
      ", so a stranger's message envelope would be kept after the counting it belongs to " +
      "has been destroyed. Forensic rows hold addresses belonging to people with no " +
      "account here; aggregate rows hold counts. Lower the forensic window to " +
      out.dmarcAggregateRetentionDays + " or fewer days, or raise the aggregate one.");
  }

  // The zone-writer group, refused as a group when it names no provider.
  //
  // Every one of these settings is read only after a provider client
  // exists, so with the provider at its default they are values nothing
  // consults. An operator who sealed a token and turned the MX switch on
  // and left the provider alone has a server that edits no zone and says
  // nothing about it, and the reading available to them from outside is
  // a zone writer that is configured and quiet. That is the shape this
  // refusal exists to remove.
  var zoneSet = [];
  if (out.zoneApiToken !== null)               zoneSet.push("BLAMEPOST_ZONE_API_TOKEN");
  if (out.zoneAllowMxWrites === true)          zoneSet.push("BLAMEPOST_ZONE_ALLOW_MX_WRITES");
  if (out.zoneEndpoint !== null)               zoneSet.push("BLAMEPOST_ZONE_ENDPOINT");
  if (out.zoneAllowInternalEndpoint === true)  zoneSet.push("BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT");
  if (out.zoneProvider === ZONE_PROVIDER_NONE && zoneSet.length > 0) {
    throw _err("config/conflicting-settings",
      zoneSet.join(" and ") + " " + (zoneSet.length === 1 ? "is" : "are") + " set and " +
      "BLAMEPOST_ZONE_PROVIDER names no provider, so nothing reads " +
      (zoneSet.length === 1 ? "it" : "them") + ". Name the provider to turn the zone writer " +
      "on, or remove " + (zoneSet.length === 1 ? "the setting" : "the settings") + " to leave " +
      "the records to be published by hand.");
  }

  // The address and the permission to reach a private one are a pair,
  // and only one order of the two means anything. The provider's public
  // API is not a private address, so permission granted over it changes
  // nothing this server would otherwise refuse, and an operator who set
  // it believes an egress proxy is in the path.
  if (out.zoneAllowInternalEndpoint === true && out.zoneEndpoint === null) {
    throw _err("config/conflicting-settings",
      "BLAMEPOST_ZONE_ALLOW_INTERNAL_ENDPOINT is set and BLAMEPOST_ZONE_ENDPOINT names no " +
      "address, so this server would still send to the provider's public API and the " +
      "permission would reach nothing. Set the address the proxy answers on, or unset the " +
      "permission.");
  }

  _assertPortsAreClaimedOnce(out);

  if (configPath === out.paths.dataDir) {
    throw _err("config/path-collision",
      "the configuration file and the data directory resolve to the same path, " + configPath + ".");
  }
}

/**
 * @primitive blamepost.config.load
 * @signature blamepost.config.load(opts?)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: docs/operator-guide.md)
 * @related   blamepost.config.redacted, blamepost.config.ensureDataDirectories
 *
 * Read the configuration file named by `BLAMEPOST_CONFIG`, overlay the
 * environment on top of it, check every setting, and return the frozen
 * result with absolute paths resolved. Throws on anything the server
 * cannot honor, naming the setting, its origin and what was expected,
 * so a typo costs a failed boot rather than a lost message hours later.
 *
 * A setting that carries structure is checked all the way down, and the
 * refusal names the route into it: a bad port inside a listener section
 * says which listener, and a relay allowlist entry says which entry.
 * Structured settings are written as JSON in the file and as the same
 * JSON on one line in the environment. One listener's port can also be
 * moved on its own, with the variable named for that listener.
 *
 * Reading nothing is not a failure: with no file present and the two
 * required variables set, the defaults carry the rest. Those defaults go
 * through the same check as an operator's value, so every setting in the
 * returned object has been read by the same code whatever supplied it.
 *
 * @opts
 *   env:  object,   // the environment bag, default process.env
 *   cwd:  string,   // the directory relative paths resolve against, default process.cwd()
 *
 * @example
 *   var config = require("./lib/config");
 *   var cfg = config.load({ env: {
 *     BLAMEPOST_HOSTNAME:         "mx.example.com",
 *     BLAMEPOST_VAULT_PASSPHRASE: "correct horse battery staple",
 *     BLAMEPOST_DATA_DIR:         "/var/lib/blamepost",
 *     BLAMEPOST_LISTENERS:        '{"imap":{"port":1143}}',
 *     BLAMEPOST_MX_PORT:          "2525",
 *   } });
 *   cfg.httpPort;
 *   // 8080
 *   cfg.listeners.imap.port;
 *   // 1143
 *   cfg.listeners.mx.port;
 *   // 2525
 *   cfg.paths.keys;
 *   // "/var/lib/blamepost/keys"
 */
function load(opts) {
  opts = opts || {};
  var env = opts.env || process.env;
  var cwd = opts.cwd || process.cwd();

  if (typeof env !== "object" || env === null) {
    throw _err("config/bad-env", "config.load: opts.env must be an object.");
  }
  if (typeof cwd !== "string" || cwd.length === 0) {
    throw _err("config/bad-cwd", "config.load: opts.cwd must be a non-empty string.");
  }

  var resolved = _resolveConfigPath(env, cwd);
  var file     = _readConfigFile(resolved);

  var out     = { configPath: resolved.path };
  var origins = {};

  for (var i = 0; i < SETTINGS.length; i += 1) {
    var setting = SETTINGS[i];
    var got = _resolveOne(setting, env, file, resolved.path, cwd);
    _assertNotRefused(setting, got.value, got.from, resolved.path, cwd);
    out[setting.key]     = got.value;
    origins[setting.key] = got.from;
  }

  out.listeners = _applyListenerPortVars(
    out.listeners, origins.listeners, env, resolved.path, cwd);

  out.paths = _pathsFor(out.dataDir);
  _assertCoherent(out, origins, resolved.path);

  out.paths = Object.freeze(out.paths);
  return Object.freeze(out);
}

// The data volume's layout. One directory per concern so a backup, a
// key rotation and a certificate renewal each have an obvious target.
// The database file name is the framework's own: b.backup and the vault
// rotation pipeline both look for it under that name, so renaming it
// would quietly break both.
function _pathsFor(dataDir) {
  return {
    dataDir:  dataDir,
    database: nodePath.join(dataDir, "db.enc"),
    blobs:    nodePath.join(dataDir, "blobs"),
    queue:    nodePath.join(dataDir, "queue"),
    keys:     nodePath.join(dataDir, "keys"),
    tls:      nodePath.join(dataDir, "tls"),
  };
}

/**
 * @primitive blamepost.config.redacted
 * @signature blamepost.config.redacted(cfg)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (secrets never reach a log or a support bundle)
 * @related   blamepost.config.load
 *
 * A copy of the loaded configuration with the vault passphrase and the
 * administrator password masked, safe to write to a log or hand to a
 * support bundle. Use it anywhere the configuration is printed: the
 * loaded object itself holds two secrets in cleartext, which is what a
 * boot line dumping it would publish.
 *
 * @example
 *   var cfg = require("./lib/config").load();
 *   require("./lib/config").redacted(cfg).vaultPassphrase;
 *   // "[redacted]"
 */
function redacted(cfg) {
  if (typeof cfg !== "object" || cfg === null) {
    throw _err("config/bad-config", "config.redacted: pass the object config.load returned.");
  }
  var out = {};
  var keys = Object.keys(cfg);
  for (var i = 0; i < keys.length; i += 1) {
    var key = keys[i];
    var setting = SETTING_BY_KEY[key];
    if (setting && setting.secret && cfg[key] !== null) out[key] = REDACTED;
    else out[key] = cfg[key];
  }
  return out;
}

/**
 * @primitive blamepost.config.limitInEffect
 * @signature blamepost.config.limitInEffect(limits, key)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 1870 (the message ceiling is the SIZE keyword)
 * @related   blamepost.config.load
 *
 * The ceiling in force for one field under `limits`: the operator's
 * number when they set one, and the shipped value when they did not.
 * `limits` takes the section as `load` returns it, which is `null` when
 * the configuration named none at all.
 *
 * Every layer that acts on a ceiling resolves it through here, so the
 * wire and the message store cannot reach different answers about an
 * unset field. A message store built without the number applies the
 * vendored framework's own instead, and a message the SIZE keyword
 * invites is then transferred in full and refused at the append.
 *
 * @example
 *   var config = require("./lib/config");
 *   config.limitInEffect(null, "maxMessageBytes");
 *   // 52428800
 */
function limitInEffect(limits, key) {
  if (!Object.prototype.hasOwnProperty.call(LIMIT_DEFAULTS, key)) {
    throw _err("config/unknown-limit", "config.limitInEffect: '" + key + "' is not a " +
      "ceiling this server holds. The settable ones are " +
      Object.keys(LIMIT_DEFAULTS).join(", ") + ".");
  }
  if (limits === null || limits === undefined) return LIMIT_DEFAULTS[key];
  if (typeof limits !== "object" || Array.isArray(limits)) {
    throw _err("config/bad-config", "config.limitInEffect: pass cfg.limits as config.load " +
      "returned it, which is an object or null.");
  }
  return limits[key] === undefined ? LIMIT_DEFAULTS[key] : limits[key];
}

/**
 * @primitive blamepost.config.ensureDataDirectories
 * @signature blamepost.config.ensureDataDirectories(cfg)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: docs/operator-guide.md)
 * @related   blamepost.config.load, blamepost.config.assertAbsoluteDataPaths
 *
 * Create the data directory and its subdirectories if they are absent,
 * and return the paths. Separate from loading because loading is pure:
 * a configuration check has no business creating anything on the way
 * past. The store calls this before opening the database.
 *
 * An entry that already holds something of the wrong kind stops the call
 * naming that entry and the path, and so does a creation the filesystem
 * refuses. A `node:fs` error carries the path alone, which leaves an
 * operator to work back from a path to whichever of the settings produced
 * it.
 *
 * @example
 *   var config = require("./lib/config");
 *   var cfg = config.load();
 *   config.ensureDataDirectories(cfg).queue;
 *   // "/var/lib/blamepost/queue"
 */
function ensureDataDirectories(cfg) {
  if (typeof cfg !== "object" || cfg === null || typeof cfg.paths !== "object" || cfg.paths === null) {
    throw _err("config/bad-config", "config.ensureDataDirectories: pass the object config.load returned.");
  }
  // Every entry is checked before any of them is created. This is the one
  // call that turns the table into directories, so a relative entry here
  // is a directory in whichever tree the process was started from, and a
  // check interleaved with the creation would leave the entries before
  // the bad one already made. The store runs the same check at each of
  // its two doors, so a table gets one answer wherever it is handed in.
  assertAbsoluteDataPaths("config.ensureDataDirectories: cfg.paths", cfg.paths);
  var names = Object.keys(cfg.paths);
  var i;
  // The kind check runs over the whole table first, for the reason the
  // absolute check above runs over the whole table first. It covers the
  // database entry as well, which the creation loop below skips: a
  // directory sitting where that file goes is invisible to a loop that
  // passes over the entry, and the first thing to report it is the store
  // failing to open a database.
  for (i = 0; i < names.length; i += 1) {
    _assertEntryKind(names[i], cfg.paths[names[i]]);
  }
  for (i = 0; i < names.length; i += 1) {
    if (names[i] === "database") continue;
    _makeDataDirectory(names[i], cfg.paths[names[i]]);
  }
  return cfg.paths;
}

// What each entry in the table may already be. Every name but `database`
// is a directory this server creates and writes under; `database` is the
// file the store opens.
//
// Absence passes, because the first boot is the boot that makes the
// volume. A path this process cannot stat passes too: that is a
// permission answer rather than a kind answer, and the creation below
// reports it with the entry attached.
function _assertEntryKind(name, dirPath) {
  var stat;
  try {
    stat = nodeFs.statSync(dirPath);
  } catch (_e) {
    return;
  }
  var wantsDirectory = name !== "database";
  if (wantsDirectory === stat.isDirectory()) return;
  throw _err("config/data-directory-unusable",
    "the data volume's " + name + " entry is " + dirPath + ", which is " +
    (stat.isDirectory() ? "a directory where this server keeps a file" :
      "not a directory") + ". Every entry under BLAMEPOST_DATA_DIR is created and " +
    "written to under the name it holds. Point the setting at a directory this server " +
    "owns, or move what is already there.");
}

// Create one entry, reporting a filesystem refusal against the entry that
// asked for it. `mkdir` names a path and nothing else, so a volume on a
// read-only mount, a parent that is a regular file and a directory this
// process may not write in all arrive as a line an operator has to trace
// back to a setting.
function _makeDataDirectory(name, dirPath) {
  try {
    nodeFs.mkdirSync(dirPath, { recursive: true, mode: 0o700 });
  } catch (e) {
    throw _err("config/data-directory-unusable",
      "the data volume's " + name + " entry, " + dirPath + ", could not be created: " +
      ((e && e.message) || String(e)) + ". Every entry under BLAMEPOST_DATA_DIR is " +
      "created and written to under the name it holds, so this server needs a directory " +
      "it can make and write there.");
  }
}

/**
 * @primitive blamepost.config.assertAbsoluteDataDir
 * @signature blamepost.config.assertAbsoluteDataDir(label, dataDir)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: docs/operator-guide.md)
 * @related   blamepost.config.assertAbsoluteDataPaths, blamepost.config.ensureDataDirectories
 *
 * Refuse a data directory that is not an absolute path, naming the
 * caller that was handed it. Returns the value so a caller can assign
 * through it.
 *
 * Every subsystem that keeps files builds its own directory by joining a
 * name onto this one, and `node:path` resolves a relative base against
 * the working directory of whatever process is running. So a relative
 * value does not fail: it succeeds somewhere else, writing the spool,
 * the blobs or the sealed keys into whichever tree the server happened to
 * be started from, and writing them somewhere different the next time it
 * is started from elsewhere. `load` resolves the setting before any of
 * that, so this speaks for the callers that build a configuration by
 * hand rather than reading one.
 *
 * A value of any other type is refused here. Nothing can be joined onto a
 * number and no directory can be created under one, so an unguarded value
 * fails inside whichever call first uses it as a path, naming neither the
 * entry nor the caller that was handed it. Most callers name their own
 * data directory and reject a non-string before reaching this;
 * `assertAbsoluteDataPaths` hands over whatever the table holds, so for a
 * table entry this is the only check standing between a wrong type and
 * that failure.
 *
 * The absent case belongs to the caller. Each one has a sentence naming
 * what it keeps under the directory, and that sentence is more use to an
 * operator than a shared one would be, so `undefined` passes through.
 * `assertAbsoluteDataPaths` is the caller that owns it for a whole table.
 *
 * @example
 *   var config = require("./lib/config");
 *   config.assertAbsoluteDataDir("blamepost.mail.dkim.create: opts.dataDir", "keys");
 *   // TypeError: ... must be an absolute path ...
 */
function assertAbsoluteDataDir(label, dataDir) {
  if (dataDir !== undefined && typeof dataDir !== "string") {
    throw new TypeError(label + " must be an absolute path, and " + _shapeOf(dataDir) +
      " is not a path at all: nothing can be joined onto it and no directory can be " +
      "created under it. Received " + _describeValue(dataDir) + ".");
  }
  if (typeof dataDir === "string" && !nodePath.isAbsolute(dataDir)) {
    throw new TypeError(label + " must be an absolute path. A relative one is resolved " +
      "against the directory this process was started from, so the files land in that tree " +
      "and land somewhere else the next time the process starts from elsewhere. Received " +
      JSON.stringify(dataDir) + ".");
  }
  return dataDir;
}

// What to call the type in a refusal. `typeof null` is "object" and
// `typeof []` is too, and an operator reading either back as "an object"
// learns less about what they wrote than the two words that name it.
function _shapeOf(value) {
  if (value === null) return "null";
  if (Array.isArray(value)) return "an array";
  return "a " + typeof value;
}

// The value as the refusal prints it. `JSON.stringify` answers with
// `undefined` rather than a string for a function or a symbol, so those
// fall back to their own spelling.
function _describeValue(value) {
  var written = JSON.stringify(value);
  return written === undefined ? String(value) : written;
}

/**
 * @primitive blamepost.config.assertAbsoluteDataPaths
 * @signature blamepost.config.assertAbsoluteDataPaths(label, paths)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: docs/operator-guide.md)
 * @related   blamepost.config.assertAbsoluteDataDir, blamepost.config.ensureDataDirectories
 *
 * Hold every entry in a resolved paths table to the rule
 * `assertAbsoluteDataDir` states, naming the caller and the entry that is
 * wrong. Returns the table so a caller can assign through it.
 *
 * Each entry is a directory or a file the server creates and writes, and
 * they are checked before any of them is used, so a table with one bad
 * entry is refused whole rather than part way through with the entries
 * before it already made.
 *
 * Entries are checked as the table carries them. A name the table does
 * not hold is not a fault here, because the two doors onto a volume need
 * different subsets of it, and each names what it dereferences itself. A
 * name the table DOES hold with nothing in it is refused: an entry with
 * no value has nowhere to write.
 *
 * @example
 *   var config = require("./lib/config");
 *   config.assertAbsoluteDataPaths("store.open: cfg.paths", cfg.paths);
 */
function assertAbsoluteDataPaths(label, paths) {
  if (typeof paths !== "object" || paths === null || Array.isArray(paths)) {
    throw _err("config/bad-config", label + " must be the resolved paths table, which is " +
      "what config.load returns as cfg.paths.");
  }
  var names = Object.keys(paths);
  for (var i = 0; i < names.length; i += 1) {
    var name = names[i];
    if (paths[name] === undefined) {
      throw _err("config/bad-config", label + "." + name + " is named in the paths table " +
        "with nothing in it. Every entry the table carries is created and written to under " +
        "the name it holds, so an entry with no value has nowhere to write.");
    }
    assertAbsoluteDataDir(label + "." + name, paths[name]);
  }
  return paths;
}

/**
 * @primitive blamepost.config.applyLogLevel
 * @signature blamepost.config.applyLogLevel(cfg)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: docs/operator-guide.md)
 * @related   blamepost.config.load
 *
 * Publish the resolved log level to the variable the framework's boot
 * logger reads, and return the level that was published. Separate from
 * loading for the reason `ensureDataDirectories` is: loading is pure,
 * and this writes to the process environment.
 *
 * WHAT IT CONTROLS. The framework's boot logger consults
 * `BLAMEJS_BOOT_LOG_LEVEL` before it emits a `debug` line, so a level of
 * `debug` turns on the diagnostics the framework writes when it recovers
 * from something on its own: a stale lock file it could not unlink, a
 * migration whose rollback failed, a cascade reset that did not
 * complete. Those lines are suppressed at every other level.
 *
 * WHAT IT DOES NOT CONTROL. `info`, `warn` and `error` are emitted
 * unconditionally by that logger, so `warn` and `error` do not make a
 * running server quieter, and `fatal` does not silence it. Setting a
 * level above `info` therefore selects nothing that a level of `info`
 * does not already give. Only `debug` changes what is written.
 *
 * @example
 *   var config = require("./lib/config");
 *   var cfg = config.load();
 *   config.applyLogLevel(cfg);
 *   // process.env.BLAMEJS_BOOT_LOG_LEVEL === cfg.logLevel
 */
function applyLogLevel(cfg) {
  if (typeof cfg !== "object" || cfg === null || typeof cfg.logLevel !== "string" ||
      LOG_LEVELS.indexOf(cfg.logLevel) === -1) {
    throw _err("config/bad-config",
      "config.applyLogLevel: pass the object config.load returned. Its logLevel has to be " +
      "one of " + LOG_LEVELS.join(", ") + ".");
  }
  process.env[BOOT_LOG_LEVEL_VAR] = cfg.logLevel;
  return cfg.logLevel;
}

/**
 * @primitive blamepost.config.logLevelInEffect
 * @signature blamepost.config.logLevelInEffect(env?)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: docs/operator-guide.md)
 * @related   blamepost.config.applyLogLevel
 *
 * The level that is in effect right now, whether or not a configuration
 * has been loaded yet. It reads what `applyLogLevel` published, so a
 * level written in the configuration file is honored, and falls back to
 * `BLAMEPOST_LOG_LEVEL` so a failure that happens before the file is read
 * still answers from the environment. An unrecognized value in either
 * place reads as the shipped default rather than stopping the caller,
 * because the callers are the ones reporting a failure and a second
 * failure there would replace the first.
 *
 * @example
 *   require("./lib/config").logLevelInEffect();
 *   // "info"
 */
function logLevelInEffect(env) {
  var source = (env && typeof env === "object") ? env : process.env;
  var candidates = [source[BOOT_LOG_LEVEL_VAR], source.BLAMEPOST_LOG_LEVEL];
  for (var i = 0; i < candidates.length; i += 1) {
    var name = String(candidates[i] === undefined ? "" : candidates[i]).trim().toLowerCase();
    if (LOG_LEVELS.indexOf(name) !== -1) return name;
  }
  return DEFAULT_LOG_LEVEL;
}

module.exports = {
  load:                  load,
  redacted:              redacted,
  assertAbsoluteDataDir: assertAbsoluteDataDir,
  assertAbsoluteDataPaths: assertAbsoluteDataPaths,
  applyLogLevel:         applyLogLevel,
  logLevelInEffect:      logLevelInEffect,
  limitInEffect:         limitInEffect,
  ensureDataDirectories: ensureDataDirectories,
  ConfigError:           ConfigError,
  SETTINGS:              Object.freeze(SETTINGS.map(function (s) { return Object.freeze(s); })),
  DEFAULT_CONFIG_PATH:   DEFAULT_CONFIG_PATH,
  DEFAULT_DATA_DIR:      DEFAULT_DATA_DIR,
  LOG_LEVELS:            Object.freeze(LOG_LEVELS.slice()),
  GUARD_PROFILES:        Object.freeze(GUARD_PROFILES.slice()),
  // The hosted DNS providers the zone writer knows, and the value naming
  // none of them. Published so the module that builds the writer and the
  // module that validates the setting cannot hold two lists.
  ZONE_PROVIDERS:        Object.freeze(ZONE_PROVIDERS.slice()),
  ZONE_PROVIDER_NONE:    ZONE_PROVIDER_NONE,
  LISTENER_NAMES:        Object.freeze(LISTENER_NAMES.slice()),
  LISTENER_DEFAULTS:     LISTENER_DEFAULTS,
  MIN_LINE_BYTES:        MIN_LINE_BYTES,
  MAX_LINE_BYTES:        MAX_LINE_BYTES,
  // What every ceiling under `limits` is when the operator names none.
  // Read by the listeners, which build their per-source limiter and
  // their SIZE keyword from it, and by both places the message store is
  // built, which apply the message ceiling at append. One table, because
  // a shipped value the wire and the store each answered separately is
  // how a message came to be accepted on one and refused by the other.
  LIMIT_DEFAULTS:        LIMIT_DEFAULTS,
};
