// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * One description of a zone, in the two shapes this server's consumers
 * ask for.
 *
 * The posture checker holds a `b.network.dns.resolver` handle and calls
 * `queryTxt` / `queryMx` / `queryTlsa`, which answer `{ rrs: [...] }`.
 * The mail-authentication primitives take an injectable `dnsLookup`,
 * which answers `string[][]`, the character strings RFC 1035 §3.3.14
 * splits a TXT record into. Building both from the same table is what
 * keeps a test from proving that two of its own fixtures agree.
 *
 * Absence has three distinct signals and a test that blurs them proves
 * nothing about the code that has to tell them apart. A name that does
 * not exist makes the resolver throw `resolver/nxdomain`; a name that
 * exists with no record of that type answers with an empty `rrs` list;
 * and an operator-supplied `dnsLookup` signals absence with an
 * `ENODATA` error. A lookup that could not complete at all is none of
 * those, and is offered here as `FAILING` so the difference can be
 * asserted rather than assumed.
 *
 * A question accepted and never answered is none of the four, and is
 * offered as `HANGING`. It is the only entry here that asks whether the
 * caller holds a bound of its own rather than what it does with an
 * answer, because it is the only one that never arrives.
 *
 * Both markers are read by one function, `_markerAnswer`, rather than
 * by each builder for itself. Every builder answers in the shape its
 * consumer takes, which is why there is more than one of them; which
 * entries are markers at all is not something they may differ about.
 *
 * Verifying a DKIM signature against a zone built this way is the only
 * assertion worth making about a selector record: a record that has
 * drifted from the key signing under it looks perfect from the sending
 * side and shows up only as other people trusting the mail less.
 */

var b = require("../../lib/vendor/blamejs");

// The marker a zone entry carries when the lookup itself is broken,
// which is distinct from a name that answers nothing.
var FAILING = { failing: true };

// The marker a zone entry carries when the lookup is accepted and never
// answered at all. It is a fourth answer and not a variant of the third:
// a failure arrives, so whatever was waiting on it carries on, while
// this one never arrives, so whatever was waiting on it waits. A
// resolver that behaves this way is ordinary rather than exotic. A
// nameserver that takes the query and drops the response, a firewall
// that blackholes the reply, and a handle an operator wrote around an
// internal service that stopped answering all present exactly like this.
//
// It exists so a session driven against a listener can show whether the
// connection path holds a bound of its own. Nothing else in this file
// can produce that question: every other entry settles, so a path with
// no bound and a path with one look identical against all of them.
var HANGING = { hanging: true };

function _key(name) {
  return String(name).toLowerCase().replace(/\.$/, "");
}

function _entries(zone) {
  var table = Object.create(null);
  Object.keys(zone || {}).forEach(function (name) { table[_key(name)] = zone[name]; });
  return table;
}

function _nxdomain(name, qtype) {
  // The shape lib/vendor/blamejs/lib/network-dns-resolver.js raises for
  // RFC 1035 §4.1.1 RCODE 3, a name that does not exist. Consumers that
  // treat this as a failed lookup rather than as an absent record report
  // a resolver problem for a record the operator simply has not
  // published, which is the commonest answer in DNS.
  var err = new Error("query: upstream RCODE=3 for " + name + "/" + qtype);
  err.code = "resolver/nxdomain";
  return err;
}

function _unreachable(name, qtype) {
  var err = new Error("query: upstream lookup failed for " + name + "/" + qtype + ": timed out");
  err.code = "resolver/upstream-failed";
  return err;
}

// What a marker means, decided once for every builder below.
//
// The three builders answer over the same zone tables in three shapes,
// because their consumers take three shapes, and that is the reason
// there is more than one of them. Which entries are markers at all is
// not something they may differ about, so they ask this rather than
// testing the markers themselves.
//
// The property that matters is what happens to the NEXT marker.
// `HANGING` was added to one builder and left to fall through the other
// two, where one read it as an empty record set and the other as a name
// publishing nothing. Either reading turns a stall fixture into a prompt
// reply, so a test written to prove a caller bounds its own DNS reads
// passes without the bound ever being asked for, which is the worst
// thing a fixture can do: nothing about it looks wrong from the test
// that used it. Read in one place, a marker is honored by every builder
// the day it is added.
//
// The answer is a thrown error or a promise nobody settles, both of
// which are the whole of what the marker means. `undefined` says the
// entry is ordinary zone data the caller has to shape for itself.
function _markerAnswer(entry, qname, qtype) {
  // A lookup that could not complete, which is a different answer from
  // a name that publishes nothing under a different code. A consumer
  // that folds either into the other only shows it when a fixture can
  // produce both.
  if (entry === FAILING) throw _unreachable(qname, qtype);
  // Accepted and never answered. A promise nobody settles is the whole
  // of it, and it is deliberately not a rejection, because a rejection
  // is the one thing a caller cannot fail to notice.
  if (entry === HANGING) return new Promise(function () { /* never settles, by design */ });
  return undefined;
}

/**
 * A resolver handle over a zone table.
 *
 * `zone` maps a name to `{ txt: string[], mx: string[], tlsa: number }`.
 * A name the table does not carry does not exist. An entry present with
 * an empty list for the type asked about exists and publishes nothing
 * of that type. The markers mean here what they mean everywhere in this
 * file: `FAILING` cannot be looked up at all, and `HANGING` is accepted
 * and never answered.
 *
 * Every answer carries `validated`, which is what the shipped resolver
 * reports the response's DNSSEC authentication under (RFC 4035 §3.2.3).
 * An entry sets `authenticated: false` for a name in an unsigned zone.
 * The field is not decoration: RFC 7672 §1.3 forbids a sender from using
 * a TLSA record that arrived unauthenticated, so a fixture that left the
 * field off would have a caller reading silence where the real handle
 * always speaks.
 *
 * `opts.reportsDnssec: false` leaves the field off every answer instead,
 * which is the operator-supplied handle rather than the shipped one:
 * `posture.create` takes any handle with the readers below, and one
 * wrapped around an internal service reports nothing about DNSSEC. That
 * is a third answer and not a variant of the second, so it is asked for
 * rather than arrived at.
 *
 * `calls` records every question asked, so a test can assert that the
 * resolver the operator pinned is the one a lookup went to.
 */
function resolverOver(zone, opts) {
  var table = _entries(zone);
  var calls = [];
  var reportsDnssec = !(opts && opts.reportsDnssec === false);

  function _answer(name, qtype, pick) {
    calls.push(qtype + " " + _key(name));
    var entry = table[_key(name)];
    if (entry === undefined || entry === null) throw _nxdomain(_key(name), qtype);
    var marker = _markerAnswer(entry, _key(name), qtype);
    if (marker !== undefined) return marker;
    var answer = pick(entry);
    if (reportsDnssec) answer.validated = entry.authenticated !== false;
    return answer;
  }

  return {
    calls: calls,
    async queryTxt(name) {
      return _answer(name, "TXT", function (entry) {
        var rows = entry.txt || [];
        return { rrs: rows.map(function (r) { return { type: 16, decoded: [r] }; }) };
      });
    },
    async queryMx(name) {
      return _answer(name, "MX", function (entry) {
        var hosts = entry.mx || [];
        return {
          rrs: hosts.map(function (h, i) {
            return { type: 15, decoded: { exchange: h, preference: (i + 1) * 10 } };
          }),
        };
      });
    },
    async queryTlsa(name) {
      return _answer(name, "TLSA", function (entry) {
        var n = entry.tlsa || 0;
        var rrs = [];
        for (var i = 0; i < n; i += 1) rrs.push({ type: 52, decoded: "3 1 1 " + i });
        return { rrs: rrs };
      });
    },
  };
}

/**
 * The `dnsLookup` an authentication primitive takes, over the same zone
 * table. TXT only, which is every policy record these primitives read.
 *
 * Absence here is `ENODATA` rather than `resolver/nxdomain`, and the
 * difference from `resolverOver` above is deliberate: these primitives
 * were written against `dnsPromises`, so `ENODATA` is the signal they
 * read as "this name publishes nothing". The markers are not part of
 * that difference. A marker is decided before any of it, because a
 * stall answered under the absence code is the exact reading that lets
 * whoever can stall a query delete the policy it would have found.
 */
function lookupOver(zone) {
  var table = _entries(zone);
  var calls = [];
  var fn = async function dnsLookup(qname, type) {
    calls.push(String(type || "TXT").toUpperCase() + " " + _key(qname));
    var entry = table[_key(qname)];
    var marker = _markerAnswer(entry, _key(qname), "TXT");
    if (marker !== undefined) return marker;
    if (entry === undefined || entry === null || !(entry.txt || []).length) {
      var err = new Error("no TXT records for " + _key(qname));
      err.code = "ENODATA";
      throw err;
    }
    return entry.txt.map(function (r) { return [r]; });
  };
  fn.calls = calls;
  return fn;
}

// ---------------------------------------------------------------------------
// The resolver a whole server is pinned to
// ---------------------------------------------------------------------------

// The typed readers `b.network.dns.resolver.create()` offers. Derived
// from one list rather than written out, so this cannot drift into
// offering a reader the shipped resolver does not have, or withholding
// one it does.
//
// `queryPtr` is on that list, and a fixture without it is not a
// harmless omission: the HELO gate's forward-confirmed reverse check
// refuses a resolver that cannot answer a reverse question rather than
// reading the missing reader as "no reverse name", so a handle built
// here without it would fail the gate for reasons that belong to the
// fixture.
var TYPED_READERS = Object.freeze([
  "A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT", "SRV", "TLSA", "DS", "DNSKEY", "SVCB", "HTTPS",
]);

/**
 * A resolver over a zone keyed `<name>|<QTYPE>`, for the whole server
 * rather than for one primitive.
 *
 * `blamepost.create({ resolver })` hands one handle to the HELO gate,
 * SPF, DKIM verification, DMARC and MTA-STS discovery, and every one of
 * them reaches it through `query(name, qtype)` rather than through the
 * typed readers. That is the difference between this and `resolverOver`
 * above: the same zone, asked in the shape the listener composition
 * passes down, so a gate that works here works against the shipped
 * resolver.
 *
 * Values are resource records in the shape `query` resolves to, so a
 * gate reading `rrs[i].decoded` sees what it would see in production, or
 * `{ rrs, authenticated: false }` for a name in a zone nothing signed. A
 * name and type the table does not carry does not exist, which the
 * handle signals the way the shipped resolver signals it, with
 * `resolver/nxdomain`. An entry whose value is `FAILING` is a lookup
 * that could not complete, which is a different answer under a
 * different code, and the resolver keeps the two apart precisely so a
 * consumer cannot quietly fold one into the other. An entry whose value
 * is `HANGING` is accepted and never answered, which is the one shape
 * that asks whether the caller holds a bound of its own rather than
 * what it does with an answer.
 *
 * That code is load bearing rather than cosmetic. The shipped resolver
 * never raises `ENOTFOUND`, and every framework record reader already
 * treats `ENOTFOUND` as absence. A fixture raising it therefore performs
 * the conversion the server is supposed to perform, so a run built on
 * one proves nothing about whether the server tells a name that does not
 * exist apart from a lookup that could not complete. That is the
 * wrong-config entry in the coverage taxonomy, and it hid a class of
 * defect where a domain publishing no policy was scored as a transient
 * DNS failure and its mail deferred at the wire.
 *
 * `asked()` and `wasAsked(name, qtype)` record every question, so a
 * test can assert that the resolver the operator pinned is the one a
 * lookup went to rather than assuming it.
 */
function pinnedResolverOver(zone) {
  var table = Object.create(null);
  Object.keys(zone || {}).forEach(function (key) {
    var bar = String(key).lastIndexOf("|");
    if (bar === -1) {
      throw new TypeError("helpers/dns-zone.pinnedResolverOver: every key must be " +
        "'<name>|<QTYPE>', which " + JSON.stringify(key) + " is not");
    }
    var name  = _key(String(key).slice(0, bar));
    var qtype = String(key).slice(bar + 1).toUpperCase();
    table[name + "|" + qtype] = zone[key];
  });

  var asked = [];
  function query(name, type) {
    var qname = _key(name);
    var qtype = String(type).toUpperCase();
    asked.push(qname + "|" + qtype);
    var entry = table[qname + "|" + qtype];
    var marker = _markerAnswer(entry, qname, qtype);
    if (marker !== undefined) return marker;
    if (!entry) throw _nxdomain(qname, qtype);
    // A value may be the records alone, or `{ rrs, authenticated }` for
    // a name in a zone nothing signed. The second shape exists because a
    // fixture that can only produce an authenticated answer lets a case
    // about DNSSEC pass without the question being asked: RFC 7672 §1.3
    // forbids a sender from using a TLSA record that arrived
    // unauthenticated, so the answer's authentication is the verdict
    // rather than a detail of it.
    var rrs = Array.isArray(entry) ? entry : entry.rrs;
    return Promise.resolve({
      rrs:        rrs.slice(),
      authority:  [],
      additional: [],
      ttl:        60000,
      fromCache:  false,
      stale:      false,
      validated:  Array.isArray(entry) ? true : entry.authenticated !== false,
    });
  }

  var handle = {
    query:      query,
    asked:      function () { return asked.slice(); },
    wasAsked:   function (qname, qtype) {
      return asked.indexOf(_key(qname) + "|" + String(qtype).toUpperCase()) !== -1;
    },
    clearCache: function () { /* drop-silent by design: nothing is cached here */ },
    cacheSize:  function () { return 0; },
    profile:    "strict",
  };
  // `TXT` becomes `queryTxt` and `AAAA` becomes `queryAaaa`, the naming
  // the shipped resolver uses for the same set.
  TYPED_READERS.forEach(function (qtype) {
    handle["query" + qtype.charAt(0) + qtype.slice(1).toLowerCase()] =
      function (name) { return query(name, qtype); };
  });
  return handle;
}

// A zone table holding exactly the DKIM records this server tells the
// operator to publish, straight from `dkim.dnsRecords(domain)`.
function zoneFromRecords(records) {
  var zone = {};
  records.forEach(function (r) { zone[r.dnsName] = { txt: [r.dnsTxtValue] }; });
  return zone;
}

// Every `s=` selector on a signed message, in header order.
function selectorsOn(signed) {
  var out = [];
  var re = /^DKIM-Signature:([\s\S]*?)(?=\r\n[^\s]|\r\n\r\n)/gm;
  var m;
  while ((m = re.exec(signed)) !== null) {
    var s = /[;\s]s=([^;\s]+)/.exec(m[1]);
    if (s) out.push(s[1]);
  }
  return out;
}

// Verify a signed message against a published record set.
//
// Pass the octets. A message that came back from the signer as a Buffer
// goes in as that Buffer: handing over a latin1 rendering of it instead
// has the verifier read the rendering as text and re-encode it, so it
// checks a different message from the one that was signed and every
// signature comes back as a body hash mismatch. The failure reads as a
// signer defect and is not one.
async function verifyAgainst(signed, records) {
  return await b.mail.dkim.verify(signed, { dnsLookup: lookupOver(zoneFromRecords(records)) });
}

// "bpa=pass, bpa-rsa=fail(signature verification failed)", which is
// enough to read a failure off a check without opening the log.
function summarize(results) {
  return results.map(function (r) {
    var why = r.errors && r.errors.length ? "(" + String(r.errors[0]).slice(0, 60) + ")" : "";
    return r.s + "=" + r.result + why;
  }).join(", ");
}

function allPass(results) {
  return results.length > 0 && results.every(function (r) { return r.result === "pass"; });
}

// A message worth signing: every header the shipped signer binds is
// present, so the signature covers the identity and the threading
// position rather than a bare subject.
function messageFrom(domain, tag) {
  return [
    "From: alice@" + domain,
    "To: bob@example.net",
    "Subject: A message worth signing",
    "Date: Sat, 23 Aug 2026 12:00:00 +0000",
    "Message-ID: <" + tag + "@" + domain + ">",
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "",
    "Body under signature.",
    "",
  ].join("\r\n");
}

module.exports = {
  FAILING:             FAILING,
  HANGING:             HANGING,
  resolverOver:        resolverOver,
  pinnedResolverOver:  pinnedResolverOver,
  lookupOver:      lookupOver,
  zoneFromRecords: zoneFromRecords,
  selectorsOn:     selectorsOn,
  verifyAgainst:   verifyAgainst,
  summarize:       summarize,
  allPass:         allPass,
  messageFrom:     messageFrom,
};
