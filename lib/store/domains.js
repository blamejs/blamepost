// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module blamepost.store.domains
 * @nav    Accounts and domains
 * @title  Hosted domains
 * @order  20
 *
 * The domains this server answers for, the DNS posture the operator has
 * confirmed for each, and the DKIM selectors published under them.
 *
 * Two records here gate other subsystems.
 *
 * The acknowledgement flag is what the MX listener refuses to bind
 * without. Acknowledging is the operator saying the MX, SPF, DMARC,
 * DKIM, MTA-STS and TLS-RPT records exist; it is not a claim that
 * anything resolved them. Checking that they actually resolve is the
 * `blamepost doctor` command's job, and it is a separate question on
 * purpose, because a boot gate that depends on a DNS lookup fails to
 * start the server every time a resolver is slow.
 *
 * The selector records are what a signer reads to know which keys to
 * sign with and what a rotation reads to know which key may still be
 * withdrawn. Only the public half is here. Private key material lives
 * sealed under the data directory's keys folder, and a selector row
 * carries nothing but the file name that finds it.
 *
 * That file name is also the ONLY thing that finds it. Nothing walks the
 * keys folder during normal operation, and the code that erases a key
 * reaches it through a selector row, so a row deleted on its own leaves
 * a signing key for the domain on the volume permanently and in every
 * backup bundle taken afterwards. Both verbs here that delete a selector
 * row therefore move the file out of its place first and delete the row
 * second, through the module that owns the keys folder, and refuse the
 * whole change when a file will not move: a key that could not be moved
 * still has the row that names it, and the operator runs the verb again.
 *
 * The order alone is not enough, because destroying a key is the only
 * thing either verb waits on, and a refusal decided before that wait and
 * raised after it is a refusal about a volume that has already changed.
 * That leaves the rows published and the keys gone, which is a domain
 * that signs nothing, cannot be repaired by running the verb again, and
 * refuses a replacement key for the rows that are still there. So the
 * decision travels WITH the erasure: the eraser renames the material
 * aside, runs the deciding function, and destroys or restores by its
 * answer. Every refusal either verb makes is taken in that function,
 * beside the row deletion it authorizes, with nothing able to run in
 * between.
 *
 * Every event recorded here names the domain's own row id as its
 * resource, selector events included. That id is a column an auditor
 * filters on, so a second identifier for the same domain would split one
 * history in two and give a correct filter half of it with nothing to
 * say the other half exists. The selector and the algorithm ride in the
 * metadata alongside it.
 */

var b       = require("../vendor/blamejs");
var address = require("./address");
var auditActor = require("./actor");
var errors  = require("./errors");
var tables  = require("./tables");
// For the one thing a selector row names outside the database: the
// sealed private key file its keyRef column points at. The module that
// writes those files owns where they live, so a deletion here reaches
// them through it rather than through a second spelling of the keys
// folder. A second answer to what a keyRef resolves to is a second
// answer to which file a row is talking about, and the row is the only
// thing on this server that can find the file at all.
var dkimKeys = require("../mail/dkim");

// The data volume's layout is settled in one place, and the guard that
// refuses a base path nothing can be joined onto safely lives with it.
var configModule = require("../config");

var err = errors.err;

// One DNS label, the shape RFC 1035 section 2.3.1 allows and RFC 6376
// section 3.1 expects a selector to be.
var SELECTOR_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;

// A plain file name under the data directory's keys folder. What a leaf
// name may be is `b.guardFilename`'s question, and the balanced profile
// is the one that fits: the shipped convention puts the domain, the
// selector and the algorithm in one name, so several dots are ordinary,
// while a path separator, a traversal segment, a Windows device name and
// an alternate data stream are all still refused. The regex beside it
// keeps the character set narrow, because a selector name reaches this
// field and a key file is not the place to find out what a filesystem
// makes of an unusual byte.
var KEY_REF_GUARD = { profile: "balanced" };
var KEY_REF_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

// An ML-DSA-65 public key is 1952 bytes, which is the largest of the
// three algorithms and about 2604 characters once base64 encoded. The
// cap leaves room and still refuses a file pasted into the field.
var MAX_PUBLIC_KEY_CHARS = 8192;

var MAX_ACTOR_CHARS = 200;

function _requireOpts(opts, fn) {
  if (typeof opts !== "object" || opts === null) {
    throw err("store/bad-argument", "domains." + fn + " takes an options object.");
  }
  return opts;
}

function _requireReason(value, fn) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw err("store/bad-argument", "domains." + fn + " needs a reason.");
  }
  return value.trim();
}

function _presentDomain(row) {
  if (!row) return null;
  return {
    id:                row._id,
    domain:            row.domain,
    status:            row.status,
    dnsAcknowledged:   row.dnsAcknowledged === 1,
    dnsAcknowledgedAt: row.dnsAcknowledgedAt === undefined ? null : row.dnsAcknowledgedAt,
    dnsAcknowledgedBy: row.dnsAcknowledgedBy === undefined ? null : row.dnsAcknowledgedBy,
    createdAt:         row.createdAt,
    updatedAt:         row.updatedAt,
  };
}

function _presentSelector(row) {
  if (!row) return null;
  return {
    id:        row._id,
    domain:    row.domain,
    selector:  row.selector,
    algorithm: row.algorithm,
    publicKey: row.publicKey,
    keyRef:    row.keyRef,
    status:    row.status,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    retiresAt: row.retiresAt === undefined ? null : row.retiresAt,
  };
}

function _rowFor(name) {
  return b.db.from(tables.DOMAINS).where({ domain: name }).first();
}

function _requireRowFor(name) {
  var row = _rowFor(name);
  if (!row) {
    throw err("store/no-such-domain", name + " is not hosted here.");
  }
  return row;
}

// Aliases anywhere on the server whose destination mailbox lives in this
// domain. The `domain` column names the source side, so a query scoped
// to it cannot see these, and they are the ones whose routing changes
// the moment the domain stops being hosted: an address in a hosted
// domain that holds no mailbox is refused at RCPT, and the same address
// in a domain this server no longer answers for is a forward, accepted
// and handed to the outbound chain. There is no column to key on, so the
// rows are read and their destinations parsed; this runs on an operator
// verb rather than on a delivery path.
function _aliasesPointingInto(name) {
  var rows = b.db.from(tables.ALIASES).all();
  var out = [];
  for (var i = 0; i < rows.length; i += 1) {
    var target = address.parse(rows[i].destinationMailbox);
    if (target.ok && target.domain === name) out.push(rows[i]);
  }
  return out;
}

// The sealed key file every selector a domain publishes points at, in a
// stable order so two readings taken either side of a change can be
// compared as sets rather than as counts.
function _keyRefsFor(name) {
  return b.db.from(tables.SELECTORS).where({ domain: name }).all()
    .map(function (selector) { return selector.keyRef; }).sort();
}

// Everything that has to be gone before a domain can be.
//
// It ANSWERS rather than throws, and both destructive verbs here are
// written the same way, because the answer is reached from inside the
// key erasure. What the caller does with it depends on what happened to
// the key material, and a refusal that raised itself from in there would
// leave the caller unable to say whether the keys came back.
function _whyInUse(name) {
  var accountCount = b.db.from(tables.ACCOUNTS).where({ domain: name }).count();
  var aliasCount   = b.db.from(tables.ALIASES).where({ domain: name }).count();
  var inboundCount = _aliasesPointingInto(name).length;
  if (accountCount === 0 && aliasCount === 0 && inboundCount === 0) return null;
  return {
    code: "store/domain-in-use",
    message:
      name + " still holds " + accountCount + " account(s) and " + aliasCount +
      " alias(es), and " + inboundCount + " alias(es) elsewhere point into it. Remove or " +
      "repoint those first, or disable the domain to stop mail without deleting anything. " +
      "Mail an alias aims at a name in this domain is refused today; once the domain is gone " +
      "the same alias forwards it off this server.",
  };
}

function _refuseWhileInUse(name) {
  var held = _whyInUse(name);
  if (held !== null) throw err(held.code, held.message);
}

// Why a domain is staying rather than going, or null when nothing is in
// the way. Every refusal the removal can make is here, so all of them are
// decided in one run beside the deletion they authorize.
//
// The selector set is compared as a SET rather than as a count, because
// the set is what the erasure answered for: one selector added and
// another withdrawn leaves the count where it was and the key files no
// longer the ones that went.
function _whyDomainStays(name, erasedFrom) {
  var held = _whyInUse(name);
  if (held !== null) return held;
  var nowPublished = _keyRefsFor(name);
  if (nowPublished.join("\n") === erasedFrom.join("\n")) return null;
  return {
    code: "store/domain-selectors-changed",
    message:
      name + " published " + erasedFrom.length + " DKIM selector(s) when this removal " +
      "began and publishes " + nowPublished.length + " now, and they are not the same " +
      "ones, so a selector was added or withdrawn while their sealed private keys were " +
      "being set aside. Nothing has been removed: deleting the rows now would drop one " +
      "whose key is still on the volume, with nothing left able to name it. Run this " +
      "again.",
  };
}

// Why a selector is staying rather than going, or null when nothing is
// in the way.
//
// The last-active refusal is a statement about the SET of selectors a
// domain still signs with, not about the one row being withdrawn, which
// is why it reads the set and takes this row out of it by identity. A
// count taken earlier and compared later answers a different question:
// the row is unchanged in each of two concurrent withdrawals, so both
// read two active selectors, both conclude they are not taking the last
// one, and the domain is left signing nothing.
function _whySelectorStays(row, immediate, now) {
  if (row.status === "active") {
    var others = b.db.from(tables.SELECTORS)
      .where({ domain: row.domain, status: "active" }).all()
      .filter(function (other) { return other._id !== row._id; });
    if (others.length === 0) {
      return {
        code: "store/last-selector",
        message:
          row.domain + " would be left with no active DKIM selector, so everything it sends " +
          "would go out unsigned. Add the replacement selector first, then remove this one.",
      };
    }
  }
  if (row.status === "retiring" && typeof row.retiresAt === "number" &&
      row.retiresAt > now && immediate !== true) {
    return {
      code: "store/selector-still-overlapping",
      message:
        "selector " + row.selector + " on " + row.domain + " is published until " +
        new Date(row.retiresAt).toISOString() + " so mail already in flight still verifies. " +
        "Pass immediate: true to withdraw it now, which is the right answer if the key is " +
        "exposed.",
    };
  }
  return null;
}

// A sealed private key that left its place and could not be put back or
// finished off, said in the words an operator can act on. It is the one
// outcome of either verb that needs somebody to go and look: no selector
// row points at the name the file is sitting under, so nothing on this
// server will find it again on its own.
function _leftAsideNames(swept) {
  return swept.leftAside.map(function (entry) {
    return entry.setAside + " (" + entry.reason + ")";
  }).join("; ");
}

// The eraser's word for the one stranding a rerun cannot clear on its
// own. It is the eraser's verdict rather than this module's, and it is
// matched rather than thrown here, so it is written down once instead of
// being spelled into each of the two refusals that branch on it.
var ALREADY_SET_ASIDE = "already-set-aside";

// What to tell an operator to do about a key that would not move, which
// is not the same sentence for every reason it would not.
//
// Nearly every reason is a property of the volume. The file is open, the
// mode is wrong, the disk went away: those clear on their own or under an
// operator who fixes them, so the honest instruction is to run the verb
// again and the rerun really does reach the key.
//
// One reason is not like that. `already-set-aside` means two files carry
// the key's name: the one the rows point at, and one an earlier run
// moved aside and could not finish moving. This server refuses to choose
// between them, because renaming either over the other destroys signing
// material nobody can mint again. Nothing about that changes between
// runs, so a rerun meets the same guard and answers the same, and an
// operator sent back for one is sent somewhere that cannot help them.
// What clears it is a person looking at both files and settling which is
// the live key, and only then is there a rerun worth running.
function _strandedAdvice(reasons) {
  if (reasons.indexOf(ALREADY_SET_ASIDE) === -1) {
    return "Nothing has been removed, so what is published still names what is on disk, " +
      "and running this again reaches it once the volume gives the file up.";
  }
  return "Nothing has been removed, so what is published still names what is on disk. A key " +
    "set aside is two files rather than one: the name the row points at, and the same name " +
    "with an erasure suffix that an earlier run left behind. This server will not rename " +
    "either over the other, because whichever it destroyed could be the half that signs, so " +
    "a rerun on its own meets this same refusal. Open both, keep the one that is the live " +
    "sealed key, take the other off the volume, and run this again once one file carries " +
    "the name.";
}

function _readSelectorName(value) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw err("store/bad-argument", "a selector name must be a non-empty string.");
  }
  var name = value.trim().toLowerCase();
  if (!SELECTOR_RE.test(name)) {
    throw err("store/bad-selector",
      "selector " + JSON.stringify(value) + " is not a single DNS label, which is what a " +
      "DKIM selector has to be for the record to be publishable.");
  }
  return name;
}

function _readAlgorithm(value) {
  if (tables.SELECTOR_ALGORITHMS.indexOf(value) === -1) {
    throw err("store/bad-argument",
      "algorithm must be one of " + tables.SELECTOR_ALGORITHMS.join(", ") +
      ", got " + JSON.stringify(value) + ".");
  }
  return value;
}

function _readPublicKey(value) {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw err("store/bad-argument", "publicKey must be a non-empty base64 string.");
  }
  var text = value.trim();
  if (text.length > MAX_PUBLIC_KEY_CHARS) {
    throw err("store/bad-argument",
      "publicKey is longer than the " + MAX_PUBLIC_KEY_CHARS + " characters a selector record may carry.");
  }
  if (!b.safeSchema.isBase64(text)) {
    throw err("store/bad-argument",
      "publicKey must be base64, which is how the p= tag of a DKIM record carries the key.");
  }
  return text;
}

function _readKeyRef(value) {
  if (typeof value !== "string" || !KEY_REF_RE.test(value.trim())) {
    throw err("store/bad-argument",
      "keyRef must be a plain file name inside the keys folder, with no path separator in it.");
  }
  var text = value.trim();
  var verdict = b.guardFilename.validate(text, KEY_REF_GUARD);
  if (!verdict.ok) {
    throw err("store/bad-argument",
      "keyRef " + JSON.stringify(text) + " does not name a file inside the keys folder " +
      "(refused for: " + errors.issueKinds(verdict.issues) + ").");
  }
  return text;
}

function _readActor(value) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string" || value.trim().length === 0) {
    throw err("store/bad-argument", "acknowledgedBy must be a non-empty string when given.");
  }
  var text = value.trim();
  if (text.length > MAX_ACTOR_CHARS) {
    throw err("store/bad-argument",
      "acknowledgedBy is longer than the " + MAX_ACTOR_CHARS + " characters the field may carry.");
  }
  return text;
}

// The refusal both destructive selector verbs make when the volume they
// would erase from is not the one these rows came off. It is written
// once because the two verbs owe the same answer, and the caller's
// mistake is the same in both: a private copy of the database is a
// reading, and unlinking a key file on the real volume to satisfy a read
// destroys signing material for a domain nobody asked to change.
function _refuseOnACopy(fn) {
  throw err("store/snapshot-is-read-only",
    "domains." + fn + " destroys the sealed private keys its selector rows name, and this " +
    "handle reads a private copy of the database rather than the volume itself. The rows " +
    "would go from the copy, which is discarded, and the keys would go from the volume, " +
    "which is not. Stop the server and open the volume to make this change.");
}

function create(ctx) {
  // Where the sealed private keys live, settled at assembly rather than
  // at the removal. A layer with no way to reach the keys folder would
  // otherwise delete the selector rows and discover on the next line
  // that the files they named are unreachable, which is precisely the
  // half-finished removal this path exists to avoid.
  if (typeof ctx !== "object" || ctx === null ||
      typeof ctx.dataDir !== "string" || ctx.dataDir.length === 0) {
    throw new TypeError("blamepost.store.domains.create: ctx.dataDir is required. " +
      "Deleting a selector row destroys the sealed private key it named, the row is the " +
      "only thing on this server that can find that file, and nothing walks the keys " +
      "folder, so the two go together or the key is left on the volume permanently.");
  }
  configModule.assertAbsoluteDataDir(
    "blamepost.store.domains.create: ctx.dataDir", ctx.dataDir);
  var dataDir = ctx.dataDir;
  // Whether this handle reads a private copy of the database. Null for
  // the volume itself. `openSnapshot` promises that nothing on the
  // volume is written, and a key erasure would break that promise from
  // inside a handle it handed out, so the two verbs that erase refuse
  // rather than trusting every caller to have read the contract.
  var readingACopy = ctx.snapshot || null;

  /**
   * @primitive blamepost.store.domains.add
   * @signature blamepost.store.domains.add(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 1035 section 2.3.4, RFC 4343
   * @related   blamepost.store.domains.acknowledgeDns, blamepost.store.accounts.create
   *
   * Host a domain. The name is folded and checked before it is written,
   * so an IPv4 address, a single label, a wildcard or a special-use
   * suffix is refused rather than becoming a domain no mail can ever
   * reach. A new domain starts active with its DNS posture
   * unacknowledged, which is what keeps the MX listener from binding
   * before the operator has published the records.
   *
   * @opts
   *   domain: string,   // required, the domain to host
   *
   * @example
   *   await store.domains.add({ domain: "example.com" });
   */
  async function add(opts) {
    _requireOpts(opts, "add");
    var name = address.canonicalDomain(opts.domain, "domain");
    var now = Date.now();

    var row = b.db.transaction(function () {
      if (_rowFor(name)) {
        throw err("store/domain-taken", name + " is already hosted here.");
      }
      return tables.insertRow(tables.DOMAINS, {
        domain:            name,
        status:            "active",
        dnsAcknowledged:   0,
        dnsAcknowledgedAt: null,
        dnsAcknowledgedBy: null,
        createdAt:         now,
        updatedAt:         now,
      });
    });

    await auditActor.record({
      action:   "domain.added",
      outcome:  "success",
      actor:    auditActor.current(),
      resource: { kind: "domain", id: row._id },
      metadata: { domain: name },
    });

    return _presentDomain(row);
  }

  /**
   * @primitive blamepost.store.domains.get
   * @signature blamepost.store.domains.get(domain)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: hosted-domain records and their DNS posture)
   * @related   blamepost.store.domains.list
   *
   * One hosted domain by name, or null when this server does not answer
   * for it. The name is folded first, so the lookup succeeds whatever
   * case and trailing dot the caller was handed.
   *
   * @example
   *   store.domains.get("EXAMPLE.com.").dnsAcknowledged;
   *   // false
   */
  function get(domain) {
    var verdict = address.parseDomain(domain);
    if (!verdict.ok) return null;
    return _presentDomain(_rowFor(verdict.domain));
  }

  /**
   * @primitive blamepost.store.domains.list
   * @signature blamepost.store.domains.list(opts?)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: hosted-domain records and their DNS posture)
   * @related   blamepost.store.domains.get
   *
   * Every hosted domain in name order, optionally narrowed to one
   * status. This is the list the MX listener reads to know which
   * recipients are worth accepting and the admin views render.
   *
   * @opts
   *   status: string,   // active or disabled
   *
   * @example
   *   store.domains.list({ status: "active" }).length;
   */
  function list(opts) {
    opts = opts || {};
    var query = b.db.from(tables.DOMAINS);
    if (opts.status !== undefined && opts.status !== null) {
      if (tables.DOMAIN_STATUS.indexOf(opts.status) === -1) {
        throw err("store/bad-argument",
          "domains.list: status must be one of " + tables.DOMAIN_STATUS.join(", ") + ".");
      }
      query = query.where({ status: opts.status });
    }
    return query.orderBy("domain", "asc").all().map(_presentDomain);
  }

  /**
   * @primitive blamepost.store.domains.setStatus
   * @signature blamepost.store.domains.setStatus(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: hosted-domain records and their DNS posture)
   * @related   blamepost.store.domains.remove, blamepost.store.domains.add
   *
   * Turn a hosted domain off or back on without touching anything it
   * holds. A disabled domain takes no new mail and accepts no new
   * mailboxes, and its accounts stay exactly as they were, which is the
   * answer when a domain is being moved elsewhere or is under
   * investigation.
   *
   * @opts
   *   domain: string,   // required
   *   status: string,   // required, active or disabled
   *   reason: string,   // required, recorded in the audit trail
   *
   * @example
   *   await store.domains.setStatus({
   *     domain: "example.com", status: "disabled", reason: "moving to another host",
   *   });
   */
  async function setStatus(opts) {
    _requireOpts(opts, "setStatus");
    var name = address.canonicalDomain(opts.domain, "domain");
    if (tables.DOMAIN_STATUS.indexOf(opts.status) === -1) {
      throw err("store/bad-argument",
        "domains.setStatus: status must be one of " + tables.DOMAIN_STATUS.join(", ") + ".");
    }
    var reason = _requireReason(opts.reason, "setStatus");
    var row = _requireRowFor(name);

    tables.updateRow(tables.DOMAINS, row._id, {
      status:    opts.status,
      updatedAt: Date.now(),
    });
    await auditActor.record({
      action:   "domain.status_changed",
      outcome:  "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: row._id },
      metadata: { domain: name, from: row.status, to: opts.status },
    });
    return _presentDomain(_rowFor(name));
  }

  /**
   * @primitive blamepost.store.domains.acknowledgeDns
   * @signature blamepost.store.domains.acknowledgeDns(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 7208, RFC 9989, RFC 6376, RFC 8461, RFC 8460
   * @related   blamepost.store.domains.add, blamepost.store.domains.get
   *
   * Record that the operator has published the DNS a hosted domain
   * needs, or withdraw that record. The MX listener refuses to bind for
   * a domain that has not been acknowledged, because a listener
   * collecting mail for a domain with no SPF, DMARC or DKIM is
   * collecting mail nobody downstream can authenticate.
   *
   * Acknowledging is a statement, not a measurement. Nothing here
   * resolves anything.
   *
   * @opts
   *   domain:         string,    // required
   *   acknowledged:   boolean,   // default true; false withdraws it
   *   acknowledgedBy: string,    // who confirmed it, sealed on the row
   *
   * @example
   *   await store.domains.acknowledgeDns({
   *     domain: "example.com", acknowledgedBy: "operator@example.com",
   *   });
   */
  async function acknowledgeDns(opts) {
    _requireOpts(opts, "acknowledgeDns");
    var name = address.canonicalDomain(opts.domain, "domain");
    var acknowledged = opts.acknowledged !== false;
    var actor = _readActor(opts.acknowledgedBy);
    var row = _requireRowFor(name);
    var now = Date.now();

    tables.updateRow(tables.DOMAINS, row._id, {
      dnsAcknowledged:   acknowledged ? 1 : 0,
      dnsAcknowledgedAt: acknowledged ? now : null,
      dnsAcknowledgedBy: acknowledged ? actor : null,
      updatedAt:         now,
    });
    await auditActor.record({
      action:   acknowledged ? "domain.dns_acknowledged" : "domain.dns_acknowledgement_withdrawn",
      outcome:  "success",
      // Two people and two facts. `acknowledgedBy` is the operator's
      // claim about who published the zone, and it lives on the domain
      // row because that is what the MX gate is standing on. The actor
      // is who ran the verb. Folding either into the other leaves the
      // trail unable to answer the question the other one holds.
      actor:    auditActor.current(),
      resource: { kind: "domain", id: row._id },
      metadata: { domain: name, acknowledgedBy: actor },
    });
    return _presentDomain(_rowFor(name));
  }

  /**
   * @primitive blamepost.store.domains.remove
   * @signature blamepost.store.domains.remove(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      internal (design: hosted-domain records and their DNS posture)
   * @related   blamepost.store.domains.setStatus, blamepost.store.accounts.delete
   *
   * Stop hosting a domain. It refuses while any account or alias still
   * belongs to the domain, and says how many of each are in the way,
   * because removing the domain out from under them would leave rows
   * routing to a name this server no longer answers for. Delete those
   * first, or disable the domain instead. The DKIM selector records go
   * with it, and so do the sealed private keys those records named.
   *
   * The keys leave their place before the rows do, and the count of what
   * went comes back. A selector row is the only handle this server has
   * on the file its keyRef points at: nothing walks the keys folder, and
   * the code that erases a key finds its subject through a row. So a key
   * that could not be moved refuses the whole removal with the rows
   * intact, rather than leaving signing material for the domain on the
   * volume and in every backup taken afterwards, with nothing left able
   * to name it. Whoever holds one of those keys signs mail as this
   * domain, and that stays true after somebody else re-hosts the name.
   *
   * Both refusals are decided inside the erasure, beside the deletion
   * they authorize, so a refusal costs nothing: the keys go back where
   * they were and the domain is exactly as it was. That matters most for
   * the two things that can arrive while a removal is running. An
   * account created on the domain keeps it, and it keeps its signing
   * keys with it. A selector published on it is not dropped, because
   * dropping the rows for a set the erasure did not answer for would
   * leave the newest key on the volume with nothing able to name it.
   * Either way the removal says why and the operator runs it again.
   *
   * `keysLeftAside` is the one answer that needs somebody to go and
   * look, and it is empty on every ordinary run. It names a key that
   * left its place and could not be destroyed once the rows had gone.
   * No row points at the name it is sitting under, so remove it by hand.
   *
   * Aliases in other domains that point INTO this one are counted too,
   * and they are the ones worth stopping for: mail an alias aims at a
   * name in a hosted domain that holds no mailbox is refused at RCPT,
   * while the same alias in a domain this server no longer answers for
   * is a forward, so the message would start being accepted and sent
   * off the machine. It usually goes straight back to this server,
   * whose MX record the removal did not change. Repoint them first.
   *
   * @opts
   *   domain: string,   // required
   *   reason: string,   // required, recorded in the audit trail
   *
   * @example
   *   await store.domains.remove({ domain: "example.com", reason: "moved to another host" });
   */
  async function remove(opts) {
    _requireOpts(opts, "remove");
    if (readingACopy) _refuseOnACopy("remove");
    var name = address.canonicalDomain(opts.domain, "domain");
    var reason = _requireReason(opts.reason, "remove");
    var row = _requireRowFor(name);

    // Asked here while a refusal still costs nothing. A domain that
    // plainly still holds accounts is refused without a key file being
    // touched at all, which is the answer an operator meets. It is not
    // the authority: the same question is asked again below, beside the
    // deletion it authorizes.
    _refuseWhileInUse(name);

    // The key file names are read out rather than the rows counted,
    // because the count and the names have to come off one read: two
    // reads could not report on the same set, and the set is what the
    // decision below compares against.
    var erasedFrom = _keyRefsFor(name);

    // The sealed private keys leave their place FIRST and the rows go
    // second, and both happen inside this one call.
    //
    // A row's keyRef is the only handle this server has on the file it
    // names: nothing walks the keys folder, and the code that erases a
    // key finds its subject through a row. Take the rows first and a
    // file that would not go is left with nothing able to name it, on
    // this volume and in every backup bundle taken afterwards, which is
    // a key that signs mail as this domain for as long as the volume
    // lasts and after somebody else re-hosts the name.
    //
    // What that ordering costs is the decision. Erasing the keys is the
    // only suspension this verb has, so a decision reached before it
    // describes the volume as it stood, and a refusal raised on the far
    // side would leave the rows published and the keys destroyed. That
    // domain signs nothing, no re-run puts it back, and minting a
    // replacement is refused for the rows that are still there.
    //
    // Handing the decision to the eraser is what closes it. The eraser
    // renames every key aside and runs this function with nothing able
    // to interleave, so the two questions below are answered about the
    // volume the erasure is standing on rather than the one it started
    // on. A truthy answer destroys the files; a falsy one puts them
    // back, and the refusal has cost nothing.
    var refusal = null;
    var swept = await dkimKeys.eraseKeyFiles(dataDir, erasedFrom, function () {
      return b.db.transaction(function () {
        refusal = _whyDomainStays(name, erasedFrom);
        if (refusal !== null) return false;
        b.db.from(tables.SELECTORS).where({ domain: name }).deleteMany();
        tables.deleteRow(tables.DOMAINS, row._id);
        return true;
      });
    });

    if (swept.stranded.length > 0) {
      throw err("store/domain-keys-stranded",
        name + " still holds " + swept.stranded.length + " sealed DKIM private key(s) that " +
        "could not be moved out of the keys folder: " +
        swept.stranded.map(function (entry) {
          return entry.keyRef + " (" + entry.reason + ")";
        }).join("; ") + ". " +
        _strandedAdvice(swept.stranded.map(function (entry) { return entry.reason; })) +
        " Removing the rows first would leave the keys on this volume with nothing able to " +
        "find them, and whoever holds one signs mail as " + name + ".");
    }
    if (!swept.committed) {
      throw err(refusal.code, refusal.message +
        (swept.leftAside.length === 0 ? "" :
          " One thing did not survive the attempt: the sealed private key(s) " +
          _leftAsideNames(swept) + " were moved out of the way and could not be put back, " +
          "so they are sitting beside the names their rows point at and " + name +
          " cannot sign with them. Rename each one back in the keys folder by hand, " +
          "dropping the trailing suffix."));
    }

    await auditActor.record({
      action:   "domain.removed",
      // A key left in neither place is the one outcome here that somebody
      // has to act on, so the row says so rather than reading as a clean
      // removal with a field nobody opened.
      outcome:  swept.leftAside.length > 0 ? "failure" : "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: row._id },
      // What was destroyed, in the halves it was destroyed in. A key
      // already gone is counted apart from one this call erased, because
      // a retirement erases the private half and leaves the row
      // published through its overlap, and a trail that folded the two
      // together could not answer when a given key stopped existing.
      metadata: {
        domain:           name,
        selectorsRemoved: erasedFrom.length,
        keysErased:       swept.erased.length,
        keysAlreadyGone:  swept.absent.length,
        keysLeftAside:    swept.leftAside.map(function (entry) { return entry.setAside; }),
      },
    });

    return {
      domain:           name,
      outcome:          "removed",
      selectorsRemoved: erasedFrom.length,
      keysErased:       swept.erased.length,
      keysAlreadyGone:  swept.absent.length,
      keysLeftAside:    swept.leftAside.map(function (entry) { return entry.setAside; }),
    };
  }

  /**
   * @primitive blamepost.store.domains.addSelector
   * @signature blamepost.store.domains.addSelector(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 6376 section 3.6.2
   * @related   blamepost.store.domains.listSelectors, blamepost.store.domains.retireSelector
   *
   * Publish a DKIM selector for a hosted domain. Only the public half is
   * recorded: the selector name, the algorithm, the base64 public key
   * that goes in the record's p= tag, and the name of the sealed file
   * under the keys folder that holds the private half. That file name is
   * checked to be a plain name, so a selector row cannot point the
   * signer at something outside the keys folder.
   *
   * A domain signs with every active selector it has, which is how the
   * shipped posture puts an Ed25519 signature and an RSA-SHA256 signature
   * on the same message. Those are the two algorithms the DKIM-Signature
   * `a=` tag admits, so the pair is fixed by the wire format.
   *
   * @opts
   *   domain:    string,   // required, must already be hosted
   *   selector:  string,   // required, one DNS label
   *   algorithm: string,   // required, ed25519 or rsa-sha256
   *   publicKey: string,   // required, base64
   *   keyRef:    string,   // required, file name under the keys folder
   *
   * @example
   *   await store.domains.addSelector({
   *     domain: "example.com", selector: "bp1", algorithm: "ed25519",
   *     publicKey: publicKeyBase64, keyRef: "example.com.bp1.ed25519.sealed",
   *   });
   */
  async function addSelector(opts) {
    _requireOpts(opts, "addSelector");
    var name      = address.canonicalDomain(opts.domain, "domain");
    var selector  = _readSelectorName(opts.selector);
    var algorithm = _readAlgorithm(opts.algorithm);
    var publicKey = _readPublicKey(opts.publicKey);
    var keyRef    = _readKeyRef(opts.keyRef);
    var domainRow = _requireRowFor(name);
    var now = Date.now();

    var row = b.db.transaction(function () {
      var clash = b.db.from(tables.SELECTORS)
        .where({ domain: name, selector: selector, algorithm: algorithm }).first();
      if (clash) {
        throw err("store/selector-taken",
          name + " already publishes a " + algorithm + " key under selector " + selector + ".");
      }
      return tables.insertRow(tables.SELECTORS, {
        domain:    name,
        selector:  selector,
        algorithm: algorithm,
        publicKey: publicKey,
        keyRef:    keyRef,
        status:    "active",
        createdAt: now,
        updatedAt: now,
        retiresAt: null,
      });
    });

    await auditActor.record({
      action:   "domain.selector_added",
      outcome:  "success",
      actor:    auditActor.current(),
      resource: { kind: "domain", id: domainRow._id },
      metadata: { domain: name, selector: selector, algorithm: algorithm },
    });

    return _presentSelector(row);
  }

  /**
   * @primitive blamepost.store.domains.listSelectors
   * @signature blamepost.store.domains.listSelectors(opts?)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 6376 section 3.6.2
   * @related   blamepost.store.domains.addSelector
   *
   * The selector records for a domain, or for every domain when none is
   * named, narrowed by status. The signer asks for the active ones; the
   * DNS export asks for everything that is still published, retiring
   * selectors included, because their records have to stay up while
   * mail signed under them is still being delivered.
   *
   * @opts
   *   domain: string,   // one hosted domain
   *   status: string,   // active, retiring or retired
   *
   * @example
   *   store.domains.listSelectors({ domain: "example.com", status: "active" });
   */
  function listSelectors(opts) {
    opts = opts || {};
    var query = b.db.from(tables.SELECTORS);
    if (opts.domain !== undefined && opts.domain !== null) {
      query = query.where({ domain: address.canonicalDomain(opts.domain, "domain") });
    }
    if (opts.status !== undefined && opts.status !== null) {
      if (tables.SELECTOR_STATUS.indexOf(opts.status) === -1) {
        throw err("store/bad-argument",
          "domains.listSelectors: status must be one of " + tables.SELECTOR_STATUS.join(", ") + ".");
      }
      query = query.where({ status: opts.status });
    }
    return query.orderBy("domain", "asc").orderBy("selector", "asc").all().map(_presentSelector);
  }

  /**
   * @primitive blamepost.store.domains.retireSelector
   * @signature blamepost.store.domains.retireSelector(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 6376 section 3.6.2
   * @related   blamepost.store.domains.removeSelector, blamepost.store.domains.addSelector
   *
   * Stop signing with a selector while leaving its record published.
   * The row moves to retiring and gets the moment its DNS record may be
   * withdrawn, seven days out. Mail that left before the rotation is
   * still being retried and its signature still has to verify, so
   * pulling the record the same day turns in-flight mail into DMARC
   * failures.
   *
   * @opts
   *   domain:    string,   // required
   *   selector:  string,   // required
   *   algorithm: string,   // required
   *
   * @example
   *   await store.domains.retireSelector({
   *     domain: "example.com", selector: "bp1", algorithm: "ed25519",
   *   });
   */
  async function retireSelector(opts) {
    _requireOpts(opts, "retireSelector");
    var row = _requireSelector(opts, "retireSelector");
    var now = Date.now();
    var retiresAt = now + tables.SELECTOR_OVERLAP_MS;

    tables.updateRow(tables.SELECTORS, row._id, {
      status:    "retiring",
      retiresAt: retiresAt,
      updatedAt: now,
    });
    await auditActor.record({
      action:   "domain.selector_retiring",
      outcome:  "success",
      actor:    auditActor.current(),
      resource: { kind: "domain", id: _requireRowFor(row.domain)._id },
      metadata: {
        domain: row.domain, selector: row.selector,
        algorithm: row.algorithm, retiresAt: retiresAt,
      },
    });
    return _presentSelector(b.db.from(tables.SELECTORS).where({ _id: row._id }).first());
  }

  /**
   * @primitive blamepost.store.domains.removeSelector
   * @signature blamepost.store.domains.removeSelector(opts)
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 6376 section 3.6.2
   * @related   blamepost.store.domains.retireSelector
   *
   * Drop a selector record, and the sealed private key it named. It
   * refuses while an active selector is the only one left for its
   * domain, since a domain with no key signs nothing and every message
   * it sends fails DMARC alignment. It also refuses while a retiring
   * selector is still inside its overlap window, unless the caller says
   * to go ahead anyway, which is what an exposed private key calls for.
   *
   * The last one of those is a statement about every selector the domain
   * signs with, not about the row being withdrawn, so it is decided
   * against the set as it stands at the moment the row is deleted. Two
   * withdrawals running at once each take one half of the only pair a
   * domain has, and each sees the other half still active until the
   * moment it is not; whichever one reaches the deletion second is
   * refused, and its key goes back where it was.
   *
   * The key leaves its place before the row does, and `keyErased` says
   * whether one was still there to destroy. Usually there is not:
   * retiring a pair destroys the private halves and leaves the rows
   * published through the overlap, so this arrives after the file has
   * gone. The case that matters is the other one, and it is the case an
   * exposed key lands in: a selector reaches this verb without a
   * retirement having run, and the row is the only thing that can find
   * the file.
   *
   * `keysLeftAside` is the one answer that needs somebody to go and
   * look, and it is empty on every ordinary run. It names a key that
   * left its place and could not be destroyed once the row had gone.
   * No row points at the name it is sitting under, so remove it by hand.
   *
   * @opts
   *   domain:    string,    // required
   *   selector:  string,    // required
   *   algorithm: string,    // required
   *   reason:    string,    // required, recorded in the audit trail
   *   immediate: boolean,   // withdraw inside the overlap window
   *
   * @example
   *   await store.domains.removeSelector({
   *     domain: "example.com", selector: "bp1", algorithm: "ed25519",
   *     reason: "rotation complete",
   *   });
   */
  async function removeSelector(opts) {
    _requireOpts(opts, "removeSelector");
    if (readingACopy) _refuseOnACopy("removeSelector");
    var row = _requireSelector(opts, "removeSelector");
    var reason = _requireReason(opts.reason, "removeSelector");
    var immediate = opts.immediate === true;

    // Asked here while a refusal still costs nothing, for the reason
    // `remove` gives. A selector inside its overlap window is refused
    // without its key being touched at all. The authority is the same
    // question asked inside the erasure below, beside the deletion it
    // authorizes.
    var early = _whySelectorStays(row, immediate, Date.now());
    if (early !== null) throw err(early.code, early.message);

    // The sealed private key leaves its place before the row does, for
    // the reason `remove` gives above: the keyRef on this row is the
    // only thing that can find that file. A key already gone is the
    // ordinary case here rather than a fault, because retiring a pair
    // destroys the private halves and leaves the rows published through
    // their overlap, so this call usually arrives after the file has
    // gone. What it must not do is assume that: a selector can reach
    // this verb without a retirement having run, and `immediate` is the
    // answer an operator is told to reach for when they believe a key is
    // exposed.
    //
    // The decision travels with the erasure so that both refusals are
    // decided against the domain as it stands. The last-active one is
    // the reason that matters: it is a statement about the SET of
    // selectors the domain still signs with, and re-reading THIS row
    // after the erasure answers a different question, because the row is
    // unchanged in each of two concurrent withdrawals and both then
    // proceed to take one half of the only pair the domain has.
    var refusal = null;
    var swept = await dkimKeys.eraseKeyFiles(dataDir, [row.keyRef], function () {
      return b.db.transaction(function () {
        var current = b.db.from(tables.SELECTORS).where({ _id: row._id }).first();
        if (!current) {
          refusal = {
            code: "store/selector-moved",
            message:
              "selector " + row.selector + " on " + row.domain + " was withdrawn by " +
              "something else while its sealed private key was being set aside, so no row " +
              "was deleted here and none was recorded. Run `blamepost dkim list --domain " +
              row.domain + "` to see what the domain publishes now.",
          };
          return false;
        }
        refusal = _whySelectorStays(current, immediate, Date.now());
        if (refusal !== null) return false;
        tables.deleteRow(tables.SELECTORS, row._id);
        return true;
      });
    });

    if (swept.stranded.length > 0) {
      throw err("store/selector-key-stranded",
        "the sealed private key for " + row.selector + " on " + row.domain + " could not " +
        "be moved out of the keys folder: " + swept.stranded[0].keyRef + " (" +
        swept.stranded[0].reason + "). The selector row is kept, because it is the only " +
        "thing that names that file, and whoever holds the key signs mail as " +
        row.domain + ". " +
        _strandedAdvice(swept.stranded.map(function (entry) { return entry.reason; })));
    }
    if (!swept.committed) {
      throw err(refusal.code, refusal.message +
        (swept.leftAside.length === 0 ? "" :
          " One thing did not survive the attempt: the sealed private key " +
          _leftAsideNames(swept) + " was moved out of the way and could not be put back, " +
          "so it is sitting beside the name its row points at and " + row.domain +
          " cannot sign with it. Rename it back in the keys folder by hand, dropping the " +
          "trailing suffix."));
    }

    await auditActor.record({
      action:   "domain.selector_removed",
      outcome:  swept.leftAside.length > 0 ? "failure" : "success",
      actor:    auditActor.current(),
      reason:   reason,
      resource: { kind: "domain", id: _requireRowFor(row.domain)._id },
      metadata: {
        domain: row.domain, selector: row.selector,
        algorithm: row.algorithm, immediate: immediate,
        // Whether the private half went with the row here, or had
        // already gone when the pair was retired. An incident placing a
        // signature asks when the key stopped existing, and one number
        // covering both cases answers a different question.
        keyErased:     swept.erased.length === 1,
        keysLeftAside: swept.leftAside.map(function (entry) { return entry.setAside; }),
      },
    });
    return {
      domain:        row.domain,
      selector:      row.selector,
      algorithm:     row.algorithm,
      outcome:       "removed",
      keyErased:     swept.erased.length === 1,
      keysLeftAside: swept.leftAside.map(function (entry) { return entry.setAside; }),
    };
  }

  function _requireSelector(opts, fn) {
    var name      = address.canonicalDomain(opts.domain, "domain");
    var selector  = _readSelectorName(opts.selector);
    var algorithm = _readAlgorithm(opts.algorithm);
    var row = b.db.from(tables.SELECTORS)
      .where({ domain: name, selector: selector, algorithm: algorithm }).first();
    if (!row) {
      throw err("store/no-such-selector",
        "domains." + fn + ": " + name + " publishes no " + algorithm +
        " key under selector " + selector + ".");
    }
    return row;
  }

  return {
    add:            add,
    get:            get,
    list:           list,
    setStatus:      setStatus,
    acknowledgeDns: acknowledgeDns,
    remove:         remove,
    addSelector:    addSelector,
    listSelectors:  listSelectors,
    retireSelector: retireSelector,
    removeSelector: removeSelector,
  };
}

module.exports = { create: create };
