// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
/**
 * @module   blamepost.mail.delivery
 * @nav      Sending
 * @title    Outbound delivery
 * @order    10
 * @featured true
 *
 * @intro
 *   The single outbound path. Everything this server sends leaves
 *   through here, and the rule holds for whatever is added next as
 *   much as for what is here now: relay after an authenticated
 *   submission, mail the webmail composes, a message an alias forwards
 *   off this server, and the delivery status notifications this module
 *   generates itself.
 *
 *   The wire work belongs to the framework. `b.mail.send.deliver.create`
 *   chains MX lookup (RFC 5321 §5.1), MTA-STS policy fetch plus MX match
 *   (RFC 8461), DANE TLSA (RFC 7672), REQUIRETLS (RFC 8689), retry
 *   classification, and DSN composition (RFC 3464). Three things that
 *   composer leaves to the operator are owned here: the on-disk retry
 *   spool, the bounce path that turns a permanent failure into a report
 *   the original sender actually receives, and the MTA-STS record
 *   lookup, which the composer makes on its own behalf rather than over
 *   the resolver it was handed.
 *
 *   Which resolver answers that last one decides whether mail to a
 *   domain is protected. RFC 8461 §3.1 makes one TXT record the gate on
 *   the whole policy, so a suppressed answer and an honest "no record"
 *   look the same, and a sender reading them the same way delivers in
 *   the clear to a domain that asked for TLS. The lookup happens here
 *   first, over the resolver the operator pinned, and a domain it could
 *   not settle is withheld from rather than delivered to. Absence and
 *   failure are kept apart with care in both directions: reading absence
 *   as failure would stop delivery to every domain that never published
 *   a policy, which is most of them.
 *
 *   Why every send site routes through one handle rather than calling a
 *   transport directly: the policy chain is where confidentiality and
 *   deliverability live. A notification sent straight through an SMTP
 *   transport leaves with no MTA-STS enforcement, no DANE, no
 *   REQUIRETLS, and fails quietly. The spool is what lets a transient
 *   failure survive a restart instead of vanishing with the process.
 *
 *   The spool is a directory of small files under
 *   `<dataDir>/queue`, one JSON descriptor and one message body per
 *   waiting recipient. A sweep timer retries whatever is due. Each
 *   descriptor carries its own attempt counter, so the framework's
 *   retry budget converts an endlessly transient recipient into a
 *   permanent failure with a bounce, rather than a file that lives
 *   forever. An entry leaves the spool once an attempt has actually
 *   finished, so a message is never off disk and un-sent at the same
 *   time.
 *
 *   Each descriptor also carries its own record of what has been tried
 *   on it: when each attempt ran, which receiver answered where the
 *   framework names one, what the far side said in its own words, the
 *   enhanced status that says which step refused, and the transport
 *   security in force at the time. `queue.show` reads one entry with
 *   that record and with a projection of how it ends if nothing
 *   changes, which is the difference between "this is stuck" and "this
 *   has never been tried".
 *
 *   Where a peer's words and a sender's address are made safe to print
 *   is a decision this module makes once, on the way out. The
 *   descriptor keeps what arrived, so a refusal can be read exactly as
 *   it was written, and everything `queue.list`, `queue.show` and
 *   `queue.runDue` hand back has been through `b.guardText` first. That
 *   way an entry that has sat on disk across restarts is as safe to
 *   print as one written a moment ago, and a reader added later cannot
 *   arrive without the screening. An escape sequence in a refusal repaints a
 *   terminal; a bidi override in a local part reverses the address an
 *   operator is reading before they decide what to do about it.
 *
 *   This server also owes reports of its own. RFC 8460 makes TLS-RPT a
 *   two-party arrangement: a receiver publishes `_smtp._tls.<domain>`
 *   naming where aggregate reports about transport security should go,
 *   and every sender that reads that record owes them a periodic
 *   account of how delivery actually went. blamepost asks its operators
 *   to publish that record for their own domains, so it honors other
 *   people's. Each attempt leaves an observation against the receiver's
 *   domain, a run composes what accumulated into an RFC 8460 report,
 *   and where it goes is decided by asking the receiver's zone at the
 *   moment of the run rather than from anything cached at send time.
 *
 *   Two things about that path are worth stating outright. Only an
 *   outcome that is genuinely about transport security is recorded, so
 *   an unknown recipient or an unresolvable name never becomes a signed
 *   accusation about somebody else's certificates. And a receiver whose
 *   record could not be looked up is not a receiver that published
 *   nothing. The observations stay and the next run asks again, because
 *   discarding evidence somebody asked for on the strength of one
 *   unreachable resolver is the same mistake in the opposite direction
 *   as deferring mail to every domain that never published a policy.
 *
 *   The reports this server generates about its own failed deliveries
 *   travel with the RFC 5321 §4.5.5 empty reverse path, which §6.1
 *   requires so that a permanently broken sender address cannot start a
 *   loop of reports about reports. They go out over this same outbound
 *   path, and generation is rate bounded per original sender and in
 *   total: a report is addressed to the sender of the message it is
 *   about, and on a run of mail to addresses that do not exist here that
 *   sender is whoever forged it. A report the bound refuses is recorded
 *   for the operator rather than sent. A TLS-RPT report is not that
 *   shape: RFC 8460 §5.3 sends it from an ordinary address, so the mail
 *   form is handed to the outbound path like any other message.
 *
 * @card
 *   Sends every outbound message through one path that looks up the
 *   recipient's MX hosts and applies MTA-STS and DANE. A transient failure
 *   waits in the on-disk queue for a retry, and a permanent failure sends a
 *   bounce to the original sender.
 */

var nodeBuffer = require("node:buffer");
var nodeFs = require("node:fs");
var nodeOs = require("node:os");
var nodePath = require("node:path");
var b = require("../vendor/blamejs");
var address = require("../store/address");
var auditActor = require("../store/actor");
// The data volume's layout is settled in one place, and the guard that
// refuses a base path nothing can be joined onto safely lives with it.
var configModule = require("../config");
var posture = require("./posture");
// The one screen between text somebody else wrote and somebody here
// reading it. A refusal is a stranger's mail server talking and an
// address is one somebody else chose, and both are read back in a
// terminal, in an audit row and in the browser.
var displayText = require("../text");
// The bounded RFC 3462 §3 quote of a message's own headers. Every report
// this server composes asks the same reader, so the caps on what a
// report may carry and the choice of which empty line ends the block are
// one decision rather than one per report path.
var reportedHeaderBlock = require("./mailbox").reportedHeaderBlock;

// How much structure a message may declare and how large it may be,
// read from the module that owns the numbers. The message read here
// arrived at an address a stranger can write to, so it gets the bounds
// every other parse on this server gets rather than the parser's own
// defaults.
var MESSAGE_PARSE_CAPS = require("./mailbox").MESSAGE_PARSE_CAPS;

var TIME = b.constants.TIME;
var BYTES = b.constants.BYTES;

// The sweep cadence. Each descriptor holds its own next attempt time,
// so this only decides how promptly a due entry is noticed.
var DEFAULT_SWEEP_MS = TIME.seconds(60);

// Read cap for one spooled message body. The listeners cap a message at
// 50 MiB on the wire, and what is spooled is that message plus whatever
// this server added to it on the way past: a DKIM signature per
// algorithm, a Received line. So the cap carries headroom over the wire
// cap rather than matching it, because a spool that can write a body it
// cannot read back destroys the message on the first retry. Anything
// past this is corruption rather than mail.
var MAX_SPOOLED_BODY_BYTES = BYTES.mib(64);
var MAX_SPOOL_DESCRIPTOR_BYTES = BYTES.kib(64);

// How much the spool may hold before it starts refusing.
//
// A spool that keeps a message rather than destroying it is the right
// answer to a delivery fault, and it is the right answer only while
// there is somewhere to keep it. Nothing else on the volume is
// bounded against this one: the database, the sealed message bodies
// and the audit trail share it, so a spool that grows without a
// bottom eventually takes the mailboxes with it. That is a larger
// outage than the one being avoided, and it arrives without warning
// because a full filesystem fails every write at once.
//
// Two ceilings rather than one, because they are not the same
// question and either one alone leaves the other open. Depth is what
// the sweep pays: every pass reads every descriptor, so a very large
// number of very small entries costs processor time on a schedule
// whatever they weigh. Bytes are what the volume pays: a handful of
// entries at the largest size the spool can read back is gigabytes
// while the depth is still in single figures. Whichever is reached
// first is the spool being full.
//
// The shipped depth is high enough that an ordinary server never meets
// it. The spool holds one entry per waiting recipient, and every entry
// now leaves on somebody's answer or on the end of the retry budget, so
// the queue drains on its own and the ordinary depth is a handful. What
// the ceiling is sized against is the worst case the operator does not
// control: a large receiver deferring everything for the length of the
// retry budget while a busy server keeps handing it mail. Ten thousand
// waiting recipients is well past that on any server one person runs,
// and short enough to bound the volume.
//
// The number was reached the other way round once, as months of
// accumulation for a server whose outbound path was stalled altogether
// and whose queue therefore only grew. That premise is gone. The number
// survives it because the case above is the real one and lands in the
// same place, and because moving a bound with no measurement behind the
// move is how a bound stops meaning anything.
//
// The shipped byte ceiling is what that depth costs at an ordinary
// message size, rounded up generously: ten thousand entries of a
// couple of hundred kilobytes. It binds before the depth does only
// when the messages are unusually large, which is exactly the case
// the depth ceiling cannot see.
var DEFAULT_MAX_SPOOL_MESSAGES = 10000;
var DEFAULT_MAX_SPOOL_BYTES = BYTES.gib(2);

// The smallest message the listeners can be configured to accept, which
// is the configuration schema's own floor on that setting. It bounds the
// report this module composes about a message it could not deliver, so a
// server configured to take small mail still writes a report that fits
// inside its own ceiling.
var MIN_CONFIGURABLE_MESSAGE_BYTES = BYTES.kib(64);

// The largest message the listeners accept when the operator names no
// ceiling, read from the module that holds the table rather than
// restated here. It stands in for the real one when nobody tells this
// module what the listeners take.
var SHIPPED_MAX_MESSAGE_BYTES = configModule.LIMIT_DEFAULTS.maxMessageBytes;

// The share of the ceiling a message arriving from a stranger may
// take, leaving the rest for accounts that have authenticated.
//
// One ceiling, because there is one spool and one volume under it.
// Splitting it in two would not split the disk: two halves that each
// refuse at their own number still fill the volume at the sum of them,
// and neither number would be the one that matters. The listeners
// hold a limiter each for a different reason, which is that a
// connection budget spent holding a mailbox open is not the budget for
// sending, and those are two resources. This is one.
//
// What the per-listener arrangement is right about carries over all
// the same, in the form this resource can take it. Mail that reaches
// the spool from the MX listener is an alias forwarding somebody
// else's message off this server, and its volume is chosen by whoever
// writes to the alias. Left to share the ceiling evenly it would
// spend the room the operator's own account holders need to send at
// all, so it stops short and the remainder is theirs.
//
// Which side keeps the reserved share was chosen rather than assumed.
// Refusing a stranger's message hands it back to a peer that still
// holds it and retries on its own schedule, and generates a report
// from its side if it gives up; refusing an account holder is a
// message stuck in an outbox with a person waiting on it. The
// recoverable refusal goes to the party that can recover.
var STRANGER_SPOOL_SHARE = 0.8;

// The refusal a full spool makes, as a code rather than a sentence.
// The listeners read it to tell a spool that is full apart from a
// fault, so it is a frozen contract between the two and not a phrase
// either of them may reword.
var SPOOL_FULL_CODE = "delivery/spool-full";

// What an envelope may say about where it came from. Only one value
// changes anything, and it is the one whose volume this server does
// not choose. Anything else is this server's own mail or an account
// that has authenticated, and reaches the whole ceiling.
var ORIGIN_INBOUND = "inbound";

// A delivery report this server generated. It takes a share of its own
// (see REPORT_SPOOL_SHARE) because its volume is chosen by whoever
// addressed the message it is about rather than by anybody here.
var ORIGIN_REPORT = "report";
var ORIGINS = Object.freeze(["inbound", "submission", "local", "report"]);

// The extension on the file that claims one entry for one attempt.
// See `_claimEntry` for why the claim is a file rather than a field.
var CLAIM_SUFFIX = ".claim";

// The two extensions of an entry's pair. The names are a contract with
// everything that reads the spool: the listings enumerate descriptors,
// `_dropSpooled` removes both, and the reconciliation below holds one
// against the other. Written once here so a reader can find every place
// that keys on them.
var BODY_SUFFIX       = ".eml";
var DESCRIPTOR_SUFFIX = ".json";

// How long a message body may be on disk without a descriptor before it
// is reported as one nothing claims.
//
// Writing an entry is two writes, and between them the pair is
// legitimately half there. A reconciliation that reported that moment
// would name a message arriving normally, and an operator acting on it
// would delete mail that was on its way. So a body counts as stranded
// only once it has been there longer than any write could still be in
// flight.
//
// Five minutes rather than the day the message-body reconciliation
// allows, because the two windows are covering different gaps. That one
// spans an append reaching the database, which a stalled volume can
// hold open. This one spans two filesystem writes in one function with
// nothing between them, so five minutes is already several orders of
// magnitude of headroom, and a window measured in days would mean an
// operator hearing about spent queue capacity a day after the queue
// started refusing mail over it.
var SPOOL_SETTLE_MS = TIME.minutes(5);

// The claims this process is holding, by path.
//
// The framework's lock answers the question it exists to answer, which
// is whether another PROCESS holds a path, and it answers it with a
// fact the kernel decided. It deliberately adopts a lock file that
// already records this process's own PID, because the case it was
// built for is a parent handing a daemon its pidfile. That leaves one
// question it does not answer: whether something else in THIS process
// is already attempting the entry. Two handles over one data directory
// would both be told they had won.
//
// So the two halves are kept apart and both are answered from
// somewhere that can be authoritative about them. Across processes the
// kernel decides, because nothing inside this one can see another. In
// this process the heap decides, because nothing outside it can see
// in. A single set at module scope rather than per handle, since a
// second handle is exactly the case being covered.
var HELD_CLAIMS = new Set();

// What one entry remembers about the attempts already made on it. The
// bound is what keeps the descriptor inside the read cap above: a peer
// that answers a thousand times, or answers with a very long line, must
// not be able to grow a file this server has to be able to read back.
//
// The bound on a peer's text is counted in the bytes it costs to store
// rather than in characters, because the two differ by six to one on
// exactly the input a hostile peer sends. A control character is
// written as a six byte escape once the descriptor is JSON, so a
// character count of 512 bounds one field at 3 KiB and the twenty
// history rows at 120 KiB, which is twice the size the descriptor's own
// reader accepts. A peer able to write a file this server cannot read
// back has destroyed the message, so the bound is measured the way the
// cap is.
var MAX_HISTORY_ROWS = 20;
var MAX_RECORDED_REASON_BYTES = 512;

// What replaces the tail of a value the bound cut short. It is counted
// against the budget, so the result stays inside it.
var TRUNCATION_MARK = "...";

// The spool mints its ids with b.crypto.generateToken, which returns
// lowercase hex. An id arrives from an operator typing it and from a
// form field on the admin page, and it becomes two file paths, so
// anything outside that shape did not come from here.
var MIN_SPOOL_ID_CHARS = 16;
var MAX_SPOOL_ID_CHARS = 64;

// Why this module asks the MTA-STS question itself.
//
// RFC 8461 §3.1 puts the whole decision in one TXT record: a receiver
// that publishes `_mta-sts.<domain>` has a policy and a sender that
// sees no record enforces nothing. So whoever answers that question
// decides whether this server's mail to that domain is protected, and
// a suppressed answer and an honest "no record" look identical.
//
// The framework's delivery composer takes the operator's resolver and
// threads it to the MX lookup only. `mail-send-deliver.js:232` calls
// `mtaSts.fetch(domain)` with one argument, and
// `network-smtp-policy.js:146` accepts `opts.dnsLookup` and forwards it
// to the record lookup, so the question that gates outbound TLS is
// answered by whatever the host would answer with. Nothing on the
// composer's option surface reaches it, so this asks first, over the
// resolver the operator pinned, and refuses to hand a message over
// while that answer is missing.
//
// The error the record lookup raises when it could not complete. A
// policy that was found and could not be FETCHED is a different code
// and is left to the composer, which has its own verdict for it.
var MTA_STS_TXT_LOOKUP_FAILED = "smtp/mta-sts-txt-lookup-failed";

// RFC 3463 §3.8 X.7.0, the security status for a refusal none of the
// more specific codes describes. Transient, because a resolver that
// could not answer this minute may answer the next, and a message held
// is a message that can still be delivered.
//
// Deliberately not X.7.10: the IANA enhanced-status registry gives that
// one to "Encryption Needed" against basic code 523 (RFC 5248), and
// RFC 8461 registers no status code of its own.
var MTA_STS_UNSETTLED_STATUS = "4.7.0";

// RFC 3463 §4.4 X.4.7, the status for a message the sending system held
// as long as it was willing to hold it. It is what the report carries
// when this server runs out of attempts against a fault of its own: a
// resolver that never answered, a policy record that never settled, an
// envelope the composer would not take.
//
// It is not the status a receiver's refusal carries, and the difference
// is the whole point of having a separate one. A 5.x.x from a peer says
// that address will not take this message; this says nothing about the
// address at all, because no peer was ever reached. A sender reading it
// knows the message is worth sending again, which a permanent code
// would tell them it is not.
//
// The class is transient and the report's own Action is `failed`, which
// is the pairing RFC 3464 §2.3.3 and §2.3.4 describe and the one every
// established MTA emits for an expired queue entry: the failure is
// final for THIS attempt at delivery while the condition that caused it
// is not permanent.
var ABANDONED_STATUS = "4.4.7";

// The longest one wait between attempts may be. It is the same ceiling
// the configuration layer accepts, so an operator meets one rule rather
// than two, and it is here as well because this is the entry point a
// caller reaching for the primitive directly comes through.
var MAX_BACKOFF_MS = TIME.days(7);

// The waits between attempts, climbed one rung per attempt.
//
// The last entry is the steady state rather than the last wait. Both
// give-up sites index this list at `Math.min(attempt - 1, length - 1)`,
// so every attempt past the fourth waits four hours, and the schedule
// covers a budget of any size without another entry being written down.
//
// The first three rungs are shorter than the thirty minutes RFC 5321
// §4.5.4.1 names as a general retry interval. That paragraph allows a
// variable strategy in place of the flat one, and a receiver that
// greylists is the case it is worth taking: a greylist window is
// typically five minutes, so a first retry at one minute and a second at
// six clears it on the second attempt, while a flat thirty minute
// interval delays every first contact message by half an hour.
var DEFAULT_RETRY_BACKOFF_MS = Object.freeze([
  TIME.minutes(1),
  TIME.minutes(5),
  TIME.minutes(15),
  TIME.hours(1),
  TIME.hours(4),
]);

// How many attempts a message gets before this server gives up on it and
// tells its sender.
//
// It is larger than the schedule above, and it has to be. The two
// numbers answer different questions: the schedule says how long to wait
// between attempts, and this says how long to go on trying. N attempts
// are separated by N-1 waits, so an attempt count equal to the
// schedule's length leaves the schedule's last entry unreachable: the
// attempt that would first wait it is the attempt that gives up instead.
//
// The value is chosen from the total it produces. Thirty four waits over
// this schedule are one minute, five, fifteen, an hour, and then thirty
// waits of four hours, which is five days and eighty one minutes.
// RFC 5321 §4.5.4.1 asks for a give-up time of at least four to five
// days, and Postfix ships five days under `maximal_queue_lifetime`, so a
// receiver schedules its maintenance against the same scale a sender keeps.
// A budget that ran out sooner turns an afternoon of downtime on the far
// side into a permanent bounce, and an operator moving from an
// established MTA loses the mail it would have delivered.
var DEFAULT_MAX_ATTEMPTS = 35;

// The RFC 5321 §4.5.5 empty reverse path, which is what every report
// this server generates travels with, and the reason §6.1 requires it:
// a report sent from a real address makes this server the apparent
// originator of every bounce it emits, so a bounce that itself bounces
// comes back here and starts the loop the requirement exists to stop.
//
// The delivery composer takes it as the envelope sender and the SMTP
// transport writes it as `MAIL FROM:<>`. Giving a report any other
// return path is the one thing that must not happen, so the value is
// named once and every report path reads it from here.
var REPORT_REVERSE_PATH = "";

// What the wire spells the same address as. It is what a peer writes,
// and it is what a descriptor holding the literal spelling carries. It
// is not what the composer's envelope reader takes: that reader wants
// the empty string and hands the literal to the address guard, which
// reads `<>` as a malformed address. So both spellings are recognized as the
// null sender and the empty one is what goes out.
var NULL_SENDER_FORMS = ["", "<>"];

// How many reports this server generates in one window, per original
// sender and in total.
//
// A report is addressed to the sender of the message it is about, and on
// a run of mail to addresses that do not exist here that sender is
// whoever forged it. Emitting one per arriving message turns this server
// into a backscatter amplifier pointed at whoever the run names, in a
// quantity chosen by the party running it. The bound is the difference
// between reporting a genuine misdelivery and relaying an attack.
//
// Two bounds rather than one, because they answer different questions
// and either alone leaves the other open. The per sender bound stops one
// forged address being buried; the global bound stops a run that spreads
// itself across many forged addresses from costing the same in total.
//
// The per sender number is set where an ordinary correspondent never
// meets it: somebody who mistypes an address a few times in an hour
// hears about every one of them. The global number is roughly what a
// small server's whole legitimate bounce volume looks like in an hour,
// so reaching it means something other than ordinary mail is happening.
//
// A report the bound refuses is recorded rather than dropped: the audit
// row, the error line and `describe().reportsUnsent` all still name the
// address that was owed one, so an operator can see what was suppressed
// and why.
var REPORT_RATE_WINDOW_MS = TIME.hours(1);
var MAX_REPORTS_PER_SENDER_PER_WINDOW = 25;
var MAX_REPORTS_PER_WINDOW = 500;

// How many distinct original senders the rate bound tracks at once.
// The counters live in memory and are keyed by an address somebody else
// chose, so the map needs a bottom of its own or a run of forged senders
// grows it without one. Past the cap a sender that is not already
// tracked is refused a report rather than admitted untracked, because
// admitting it is the case the bound exists for.
var MAX_TRACKED_REPORT_SENDERS = 4096;

// What an operator is told about a report the bound refused.
var REPORT_RATE_LIMITED =
  "this server has already generated as many delivery reports as it will in this " +
  "window, so this one is recorded rather than sent. A report is addressed to the " +
  "sender of the message it is about, and on a run of mail to addresses that do not " +
  "exist here that sender is whoever forged it, so the bound is what keeps this " +
  "server from relaying somebody else's run back at them";

// How long this process has been running, in milliseconds.
//
// The report bound is spent over a window, and a window is elapsed time.
// `Date.now()` does not measure that: it moves when an operator corrects
// a wrong time, when NTP steps a drifted host, and when a container that
// started before it synchronized catches up. A window measured across
// two readings of it rolls over on a correction rather than on time
// passing, so a host whose clock is stepped forward hands out a fresh
// budget of reports on every step, and the ceiling an operator reads in
// the documentation is not the ceiling this server keeps. A step
// backwards is the other half: the window cannot elapse at all until the
// clock has climbed back to where it was, so the bound goes on
// suppressing reports for mail that has nothing to do with the run that
// engaged it.
//
// `b.time.monotonicMs` counts from a fixed point no clock correction can
// move, and advances only at the rate of real time. A reading is never
// stored and never leaves the process: it names no instant, and the
// moment a value has to say what time something happened it is a wall
// clock reading again. Every timestamp on a spooled descriptor, on an
// attempt record and on a report stays exactly that.
function _elapsedMs() {
  return b.time.monotonicMs();
}

// The share of the spool ceiling that reports may occupy.
//
// A report is this server's own mail, so left alone it would reach the
// whole ceiling and a run of undeliverable mail would spend the room
// account holders need to send at all. It stops short for the same
// reason mail arriving for forwarding does, and at a smaller share,
// because the volume is chosen by whoever addressed the original message
// rather than by anyone here.
var REPORT_SPOOL_SHARE = 0.1;

// ---- reports arriving about this server's own mail --------------------------

// How much of an arriving report the reader will look at. The framework
// parser refuses anything above one mebibyte outright, so this stops at
// the same number rather than handing over bytes that come back as a
// size refusal wearing the wrong reason.
var MAX_ARRIVING_REPORT_BYTES = BYTES.mib(1);

// How many per recipient groups one arriving report may name. RFC 3464
// sets no bound, and a report naming ten thousand addresses is a way to
// spend this server's time rather than a report about anything. Past
// this it is recorded as unreadable, so an operator sees that something
// arrived rather than seeing nothing.
var MAX_ARRIVING_REPORT_RECIPIENTS = 128;

// How many arriving reports are kept for reading back, and how many
// recipients of each. Enough to answer what has been coming back lately
// without becoming a second copy of the mailbox the reports are already
// sitting in.
var MAX_RECENT_ARRIVING_REPORTS = 20;
var MAX_SHOWN_ARRIVING_RECIPIENTS = 8;

// Whether a composed message can reach a peer at all in this build.
//
// This is measured rather than recorded. The composer's default
// transport is `b.mail.transports.smtp`, which is the name it reaches
// for, so asking the surface whether that name is callable answers the
// question the composer will ask at the first send. A recorded answer
// would go stale in silence; this one cannot, because it reads the same
// thing the composer reads.
//
// It is deliberately not a probe for a symptom. A check written against
// a name the composer does not reach for, such as an export called
// `smtpTransport` that nothing defines, reports an outage whether or not
// there is one and never fires the staleness error it was built to fire.
// A capability check asks for the capability.
//
// What it cannot see is whether the transport puts the raw message bytes
// on the wire unchanged. A transport that rebuilds the body from
// structured fields is callable and destroys the message, and no type
// check distinguishes the two. That guarantee is held by a behavioral
// test that sends a message to a loopback receiver and compares what
// arrived against what was sent.
var WIRE_DELIVERY_BLOCKED =
  "outbound mail cannot reach a peer in this build: the framework's delivery " +
  "composer has no SMTP transport behind it, so nothing this server sends opens a " +
  "socket. Messages are held in the spool rather than lost. Refresh the vendored " +
  "framework with `bash scripts/vendor-update.sh blamejs <version>`";

// Whether an enforcing DANE posture can authenticate a peer.
//
// RFC 7672 §2.1.1 and §2.2 forbid using a TLSA record that was not
// validated with DNSSEC, and the composer honors that by requiring the
// caller to say its resolver validates: `policy.dnssecValidated: true` is the
// statement, and `policy.dane: "enforce"` without it is refused by the
// composer itself.
//
// Nothing here can verify that statement. It is a fact about the
// resolver the operator pointed this server at, which may be a local
// validating resolver, a forwarder that strips the authenticated-data
// bit, or a public endpoint reached over DoH. Asserting it falsely is
// worse than not running DANE at all: it authenticates the peer against
// records anybody on the path could have rewritten, under a banner that
// says they were verified. So the statement is the operator's to make,
// and this server refuses `enforce` until they make it rather than
// making it on their behalf.
var DANE_ENFORCE_NEEDS_ASSERTION =
  "policy.dane \"enforce\" needs policy.dnssecValidated: true beside it. RFC 7672 " +
  "§2.1.1 and §2.2 forbid using a TLSA record that was not validated with DNSSEC, and " +
  "nothing on this server can tell whether the resolver it was given validates: that is a " +
  "fact about the resolver you pointed it at. Set dnssecValidated only if that " +
  "resolver really does validate, because asserting it falsely authenticates peers " +
  "against records anybody on the path could have rewritten. Otherwise set " +
  "policy.dane to \"opportunistic\", which reaches the same peers and claims nothing";

// ---------------------------------------------------------------------------
// TLS-RPT (RFC 8460), the sending half
// ---------------------------------------------------------------------------

// How often a run composes and sends what has accumulated. RFC 8460
// §4.1 puts an aggregate report at a day, and a receiver reading two
// reports a day from one sender learns nothing more than from one.
var DEFAULT_TLS_RPT_INTERVAL_MS = TIME.hours(24);

// How much of the volume the accumulated observations may occupy. A
// server relaying for many accounts touches many receiving domains, and
// one small file per domain has to stay small in both directions. The
// per-domain file is a handful of counters plus a bounded list of
// distinct failures, so the whole set stays in the low tens of
// megabytes at the cap. Past the cap no new domain is tracked, which
// costs a report rather than the volume; a run drops the domains that
// publish no endpoint, which is nearly all of them, so the count comes
// back down on its own.
var MAX_TLS_RPT_DOMAINS = 1024;
var MAX_TLS_RPT_FAILURE_ROWS = 16;
var MAX_TLS_RPT_MX_HOSTS = 16;
var MAX_TLS_RPT_FILE_BYTES = BYTES.kib(64);

// The enhanced status the delivery composer answers an MTA-STS refusal
// with, which RFC 8461 §10.3 gives it. The composer writes it verbatim,
// so it is a frozen contract rather than a phrase, which is what an
// outcome classification can safely anchor on.
//
// It names two conditions rather than one. The composer raises it when a
// policy was read and none of the domain's mail exchangers matched it,
// and again when the policy could not be fetched at all under an
// enforcing posture. RFC 8460 §4.3 registers a separate result type for
// each, and the difference is the receiver's to act on: a domain told
// its policy is invalid, when what happened is that this sender could
// not read it, is a domain invited to change a policy that is correct.
// The status alone cannot separate them, so the reason the composer
// wrote beside it is what does, below.
var MTA_STS_REFUSED_STATUS = "5.7.10";

// The RFC 8460 §4.3 result types this server can honestly observe.
//
// Three of them are settled before any socket is opened: an MTA-STS
// record this server could not look up, a policy document it could not
// fetch, and a policy whose mail exchanger list does not cover the
// domain's own. The rest describe what happened during a TLS
// negotiation, and are read from the failure the transport raises rather
// than from anything this server decided on its own.
//
// Nothing outside this list is ever reported. A delivery can fail for
// reasons that have nothing to do with transport security, and telling a
// receiver their TLS is broken on the strength of a full mailbox or an
// unresolvable name is an accusation this server signs its own name to.
var TLS_RPT_RESULT = Object.freeze({
  STS_FETCH_ERROR:   "sts-policy-fetch-error",
  STS_INVALID:       "sts-policy-invalid",
  DANE_REQUIRED:     "dane-required",
  // The value below is the RFC 8460 §4.3 result type a receiver parses,
  // spelled the way the registry spells it, rather than a note about
  // unfinished work in this file.
  // allow:todo-fixme-hack-xxx an RFC 8460 §4.3 result type, not a work marker
  STARTTLS_MISSING:  "starttls-not-supported",
  CERT_HOST:         "certificate-host-mismatch",
  CERT_EXPIRED:      "certificate-expired",
  CERT_UNTRUSTED:    "certificate-not-trusted",
  VALIDATION:        "validation-failure",
});

// RFC 8460 §4.4 policy types. `sts` is used only where this server
// actually read the receiver's MTA-STS policy or its record, and `tlsa`
// only where the attempt was refused over the TLSA records the receiver
// publishes. Anything else is reported as what it is, which is a
// delivery this server made no policy claim about.
var TLS_RPT_POLICY_STS = "sts";
var TLS_RPT_POLICY_TLSA = "tlsa";
var TLS_RPT_POLICY_NONE = "no-policy-found";

// How a failed attempt is read as a TLS-RPT result.
//
// The two enhanced statuses are frozen contracts. One decides on its
// own; the other covers both MTA-STS refusals the composer makes, so it
// narrows to a pair and the reason beside it picks between them.
// Everything below them is a token the framework's SMTP transport
// writes into the failure it raises, and those are matched as separate
// literals rather than as one sentence, so a rephrasing between them
// cannot silently stop matching. Anything that matches nothing here is
// not a transport-security event: an unknown recipient, a peer's own
// 5xx, a mail exchanger that could not be resolved. Counting one of
// those as a TLS failure would tell a receiver their TLS is broken on
// the strength of a full mailbox.
var TLS_RPT_DANE_LOOKUP_RE   = /\bDANE TLSA lookup\b/i;
var TLS_RPT_DANE_ENFORCE_RE  = /\bunder enforce policy\b/i;
// The token the transport writes at the head of every DANE
// peer-authentication failure: a peer that presented no chain, a chain
// that could not be walked, and a chain matching none of the records the
// peer publishes. It is the one failure DANE exists to produce, and it
// was reported to nobody. The three above are one condition as far as a
// receiver is concerned, which is that the peer was not authenticated
// against its own records, so one token covers them.
var TLS_RPT_DANE_AUTH_RE     = /\bdane:\s/i;
var TLS_RPT_STARTTLS_RE      = /\bstarttls-rejected\b/i;
var TLS_RPT_TLS_UPGRADE_RE   = /\btls-upgrade\b/i;
var TLS_RPT_CERT_HOST_RE     = /\baltname|does not match certificate/i;
var TLS_RPT_CERT_EXPIRED_RE  = /\bcertificate has expired\b|\bCERT_HAS_EXPIRED\b/i;
var TLS_RPT_CERT_UNTRUSTED_RE =
  /self[ -]signed certificate|unable to verify the first certificate|unable to get (?:local )?issuer certificate/i;
// Which of the two MTA-STS refusals the composer made. Both arrive under
// one enhanced status and the composer keeps only its own message, so
// this token is all there is to tell them apart. It is the opening
// phrase of the refusal that could not fetch the policy; the one it has
// to be held apart from reads "no MX for <domain> matches the published
// MTA-STS policy", which never says fetch. Matching loosely here would
// report a genuine mail exchanger mismatch as this server's own failure
// to read the document, which is the accusation running backwards.
var TLS_RPT_STS_FETCH_RE     = /\bMTA-STS fetch for\b/i;

/**
 * @primitive blamepost.mail.delivery.tlsRptResultFor
 * @signature blamepost.mail.delivery.tlsRptResultFor(row)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 8460 §4.3 (result types), RFC 8461 §10.3 (enhanced status)
 * @related   blamepost.mail.delivery.tlsRpt
 *
 * Read one failed recipient outcome as the RFC 8460 §4.3 result type a
 * TLS report may carry, or `null` where the failure says nothing about
 * transport security. `row` is a recipient row from the delivery
 * composer: `reasonCode` is the enhanced status and `reason` is the
 * message it was refused with.
 *
 * This decides what a receiver is told about their own transport
 * security, under this server's name, so it is a reading in its own
 * right rather than a step inside the send. One condition it separates
 * is a policy the delivery composer read and found to cover none of the
 * domain's mail exchangers, which needs the receiver's policy document,
 * and RFC 8461 §3.3 puts that behind an HTTPS fetch of
 * `mta-sts.<domain>` the framework will not direct at a loopback
 * address. Calling the reading is how that condition is put beside the
 * one it has to be told apart from.
 *
 * @example
 *   var type = delivery.tlsRptResultFor({ reasonCode: "5.7.10", reason: why });
 */
function tlsRptResultFor(row) {
  if (!row) return null;
  var code = String(row.reasonCode === undefined || row.reasonCode === null ? "" : row.reasonCode);
  var reason = String(row.reason === undefined || row.reason === null ? "" : row.reason);
  if (code === MTA_STS_UNSETTLED_STATUS) return TLS_RPT_RESULT.STS_FETCH_ERROR;
  if (code === MTA_STS_REFUSED_STATUS) {
    return TLS_RPT_STS_FETCH_RE.test(reason)
      ? TLS_RPT_RESULT.STS_FETCH_ERROR
      : TLS_RPT_RESULT.STS_INVALID;
  }
  if (TLS_RPT_DANE_LOOKUP_RE.test(reason) && TLS_RPT_DANE_ENFORCE_RE.test(reason)) {
    return TLS_RPT_RESULT.DANE_REQUIRED;
  }
  // A peer that was asked about and did not authenticate against its own
  // TLSA records. It is read after the lookup failure above, which is the
  // records being unobtainable rather than unmatched, and before the
  // negotiation tokens below, because the handshake completed and what
  // failed was the peer behind it.
  //
  // RFC 8460 §4.3 has no result type for a certificate that does not
  // match a TLSA record. `tlsa-invalid` is about the record set itself,
  // none of whose records was found to be valid, and these records were
  // valid and were used. `dane-required` is about records that were
  // needed and not obtained, which is the case above. What is left is the
  // registry's own general failure, which is what this is: the peer was
  // refused on a validation the receiver publishes the inputs to.
  if (TLS_RPT_DANE_AUTH_RE.test(reason)) return TLS_RPT_RESULT.VALIDATION;
  if (TLS_RPT_STARTTLS_RE.test(reason)) return TLS_RPT_RESULT.STARTTLS_MISSING;
  if (!TLS_RPT_TLS_UPGRADE_RE.test(reason)) return null;
  if (TLS_RPT_CERT_HOST_RE.test(reason)) return TLS_RPT_RESULT.CERT_HOST;
  if (TLS_RPT_CERT_EXPIRED_RE.test(reason)) return TLS_RPT_RESULT.CERT_EXPIRED;
  if (TLS_RPT_CERT_UNTRUSTED_RE.test(reason)) return TLS_RPT_RESULT.CERT_UNTRUSTED;
  return TLS_RPT_RESULT.VALIDATION;
}

// Which of the receiver's policies a failed attempt was refused under,
// in the RFC 8460 §4.4 vocabulary.
//
// `null` says the attempt names no policy of its own, so it belongs
// under whatever this server read for the domain. A DANE refusal does
// name one: the records are the receiver's published policy, and
// reporting it under `no-policy-found` sends the domain running DANE a
// document saying no policy was applied to the delivery its own TLSA
// records refused.
//
// Both DANE conditions count. `dane-required` is the records being
// required and not obtained, and the general failure reached through
// the peer-authentication token is the records being obtained and not
// matched. A receiver reading either one is reading about their TLSA
// records.
function _tlsRptPolicyTypeFor(row, resultType) {
  if (resultType === TLS_RPT_RESULT.STS_FETCH_ERROR ||
      resultType === TLS_RPT_RESULT.STS_INVALID) return TLS_RPT_POLICY_STS;
  if (resultType === TLS_RPT_RESULT.DANE_REQUIRED) return TLS_RPT_POLICY_TLSA;
  var reason = String(row && row.reason !== undefined && row.reason !== null ? row.reason : "");
  if (TLS_RPT_DANE_AUTH_RE.test(reason)) return TLS_RPT_POLICY_TLSA;
  return null;
}

// The policy type an accumulated failure row is reported under.
//
// Rows written before the field existed carry none, and a file under
// the data volume is a file an operator can edit, so a value that is
// not one of the three registered types is read as absent rather than
// passed through to a receiver's parser. Either way the row falls back
// to what this server read for the domain, which is where every row
// went before.
function _tlsRptPolicyTypeOf(row, domainType) {
  var stored = row && row.policyType;
  if (stored === TLS_RPT_POLICY_STS ||
      stored === TLS_RPT_POLICY_TLSA ||
      stored === TLS_RPT_POLICY_NONE) return stored;
  return domainType;
}

// The receiver's domain, refused before it becomes a path.
//
// It arrives from a recipient address somebody else chose, and it
// becomes a file name under the data volume, so it is checked with the
// framework's own domain reader rather than trusted. That reader also
// folds case, which is the part that matters on a case-insensitive
// filesystem: two spellings of one domain must be one file, or half the
// observations end up in a report the receiver never sees.
function _tlsRptDomainOf(recipient) {
  var parsed = address.parse(recipient);
  return parsed.ok && parsed.domain ? parsed.domain : null;
}

// RFC 8461 §3.2 line shape, rebuilt from the policy this server parsed.
// It is a faithful rendering of what the receiver published rather than
// the bytes they served, because the framework's fetch hands back the
// parsed policy and not the document. A receiver reading their own
// policy back in a report needs to recognize it, which this does.
function _tlsRptPolicyString(policy) {
  if (!policy || typeof policy !== "object") return [];
  var lines = [];
  if (policy.version) lines.push("version: " + policy.version);
  if (policy.mode) lines.push("mode: " + policy.mode);
  var hosts = Array.isArray(policy.mx) ? policy.mx : [];
  for (var i = 0; i < hosts.length && i < MAX_TLS_RPT_MX_HOSTS; i += 1) {
    lines.push("mx: " + hosts[i]);
  }
  if (policy.max_age) lines.push("max_age: " + policy.max_age);
  return lines;
}

// Whether an id could have been minted by this spool.
//
// The check is a shape check rather than a lookup, and it runs before
// the id becomes a path. `queue remove` takes the id from an operator's
// command line and the admin page takes it from a form field, so it is
// untrusted text on both routes; joined onto the spool directory
// unchecked it addresses any file on the volume whose name ends in the
// extension the spool appends. `b.safeBuffer.isLowerHex` is the
// framework's reader for the alphabet `b.crypto.generateToken`
// produces, so the two stay in step.
function _spoolIdIsWellFormed(id) {
  if (typeof id !== "string") return false;
  if (id.length < MIN_SPOOL_ID_CHARS || id.length > MAX_SPOOL_ID_CHARS) return false;
  return b.safeBuffer.isLowerHex(id);
}

// Which process table this process's own PID belongs to.
//
// A claim on a spool entry records the process holding it, and reaping
// a claim means deciding its holder is gone. That decision is only
// meaningful when the PID can be probed against the table it was
// issued from. A container and its host share a kernel and not a
// process namespace, so PID 8 inside a container and PID 8 on the host
// are unrelated, and an operator running `blamepost queue flush` on the
// host against a bind-mounted volume is exactly that arrangement. The
// namespace link is the fact that tells them apart; where it cannot be
// read the hostname stands in, which is weaker but still a fact about
// the running system rather than an assumption.
//
// The volume lock asks the same question for the same reason, and the
// two answers have to agree about what a process table is, but they act
// on it differently: the volume lock refuses to open the volume at all,
// and this one leaves a single entry to whoever holds it and moves on.
function _processNamespace() {
  try { return String(nodeFs.readlinkSync("/proc/self/ns/pid")); }
  catch (_e) { return "host:" + nodeOs.hostname(); }
}

function _text(value) {
  if (typeof value === "string") return value;
  return String(value === undefined || value === null ? "" : value);
}

// What one value costs to write into the descriptor. JSON is the
// storage format, so the escape a control character turns into is the
// real size of it and a character count is not. Nor is a character count
// the size of the ones JSON does not escape: the descriptor is written
// as UTF-8, where most of the world's scripts cost three bytes a
// character and everything past them costs four.
function _storedCost(codepoint) {
  return Buffer.byteLength(JSON.stringify(codepoint), "utf8") - 2;
}

// What one value costs to hand back, which is what it costs to encode.
function _shownCost(codepoint) {
  return Buffer.byteLength(codepoint, "utf8");
}

// A value cut to a budget, spent one code point at a time.
//
// Code points rather than the units a string is indexed by, because a
// cut counted in those units can land between the two halves of one
// character and leave an unpaired half behind, which is a string no
// encoder can write out: the record an operator opened to diagnose one
// failure becomes the next one.
//
// `costOf` says what one code point spends, because the two budgets here
// are not the same question. What a value costs to keep is what it costs
// once JSON has escaped it; what it costs to hand back is what it costs
// to encode.
function _boundByCost(text, budget, costOf) {
  var points = Array.from(text);
  var out = "";
  var spent = 0;
  for (var i = 0; i < points.length; i += 1) {
    var cost = costOf(points[i]);
    if (spent + cost > budget) break;
    out += points[i];
    spent += cost;
  }
  return out;
}

// A value on its way ONTO disk, kept as it arrived and bounded by what
// it costs to keep.
//
// Nothing is screened here, and that is the point. A refusal is a
// record of something that already happened, and an operator diagnosing
// one needs the bytes the far side actually sent rather than a repaired
// rendering of them. Repairing on the way in also does nothing for the
// entries already on disk, which is the half that matters most: an
// entry written before any screening existed is still read, still
// printed, and still able to forge a row. So the descriptor keeps what
// arrived and every read path is what is safe.
//
// The bound is real and is measured in stored bytes (see
// MAX_RECORDED_REASON_BYTES).
function _storedText(value) {
  var raw = _text(value);
  if (Buffer.byteLength(JSON.stringify(raw), "utf8") - 2 <= MAX_RECORDED_REASON_BYTES) return raw;
  return _boundByCost(raw, MAX_RECORDED_REASON_BYTES - TRUNCATION_MARK.length, _storedCost) +
    TRUNCATION_MARK;
}

// A value on its way to an operator, made safe to print and short enough
// to keep.
//
// The screen is `blamepost.text.forDisplay` and is not restated here. It
// removes the bidirectional overrides, the zero-width characters, the C0
// controls and the C1 controls, and folds tab, line feed and carriage
// return to a space, so a reply carrying an escape sequence no longer
// repaints the terminal and an address carrying an override no longer
// reverses the sentence an operator is reading before they decide what
// to do about it.
//
// What stays here is the bound, which is about the descriptor rather
// than about the text. A screened value is written back into an entry's
// own record of what has been tried, and that record has to stay inside
// the size the descriptor's reader accepts, so it is counted in the
// bytes it is about to be written out as and cut on a code point
// boundary (see MAX_RECORDED_REASON_BYTES). A stranger's mail server
// writes in its own language, and a bound counted in the units a string
// is indexed by lets a reply in one of them past by three times over and
// can leave half a character at the end.
function _screenForDisplay(value) {
  var safe = displayText.forDisplay(value);
  if (Buffer.byteLength(safe, "utf8") <= MAX_RECORDED_REASON_BYTES) return safe;
  return _boundByCost(safe, MAX_RECORDED_REASON_BYTES - TRUNCATION_MARK.length, _shownCost) +
    TRUNCATION_MARK;
}

/**
 * @primitive blamepost.mail.delivery.daneEnforcementStatus
 * @signature blamepost.mail.delivery.daneEnforcementStatus(sendSurface, policy?)
 * @since     0.1.0
 * @status    experimental
 * @spec      RFC 7672 §2.1.1, §2.2 (TLSA records require DNSSEC validation)
 * @related   blamepost.mail.delivery.create
 *
 * Whether an enforcing DANE posture can authenticate a peer, given a
 * framework send surface and the outbound policy an operator wrote.
 * Takes the surface rather than reading the vendored module directly,
 * so the answer can be checked against a hypothetical build without
 * anybody having to alter the real one.
 *
 * RFC 7672 §2.1.1 and §2.2 forbid using a TLSA record that was not
 * DNSSEC validated, so enforcement needs somebody to state that the
 * resolver validates. That statement is about the resolver the operator pointed
 * this server at, and nothing here can check it, so it is theirs to
 * make with `policy.dnssecValidated: true`. Enforcing without it is
 * refused at boot: it would authenticate peers against records anybody
 * on the path could have rewritten, under a banner claiming otherwise.
 *
 * Returns `{ available, reason, issues }`. `create` refuses to build a
 * handle at `policy.dane: "enforce"` while `available` is false.
 *
 * @example
 *   var dane = delivery.daneEnforcementStatus(b.mail.send, config.outboundPolicy);
 *   if (!dane.available) log.warn(dane.reason);
 */
function daneEnforcementStatus(sendSurface, policy) {
  var factory = sendSurface && sendSurface.deliver && sendSurface.deliver.create;
  if (typeof factory !== "function") {
    return {
      available: false,
      reason:    "the vendored framework exposes no delivery composer, so no outbound " +
                 "posture can be applied at all",
      issues:    [],
    };
  }

  // The operator's statement about their own resolver. Absent means
  // unstated, which is not the same as false and is treated the same
  // way: enforcement is refused until somebody says it out loud.
  if (!policy || policy.dnssecValidated !== true) {
    return { available: false, reason: DANE_ENFORCE_NEEDS_ASSERTION, issues: [] };
  }
  return { available: true, reason: "", issues: [] };
}

/**
 * @primitive blamepost.mail.delivery.wireDeliveryStatus
 * @signature blamepost.mail.delivery.wireDeliveryStatus(mailSurface)
 * @since     0.1.0
 * @status    experimental
 * @spec      internal (design: the outbound path either reaches a peer or says why not)
 * @related   blamepost.mail.delivery.create
 *
 * Whether outbound mail can reach a peer, given a framework mail
 * surface. Takes the surface rather than reading the vendored module
 * directly, so the answer can be checked against a hypothetical build
 * without anybody having to alter the real one.
 *
 * The answer is measured, not recorded: it asks whether the surface
 * exposes the callable transport the delivery composer reaches for at
 * the first send. A build that cannot send says so at boot rather than
 * at 03:00 with a queue that stopped draining, and a build that can
 * needs nothing switched on.
 *
 * Returns `{ available, reason, issues }`. `reason` says what an
 * operator can do about it; `issues` is empty while the path works.
 *
 * What it does not cover is body fidelity. A transport that is callable
 * and rebuilds the message from structured fields destroys the body and
 * reports success, and no check of the surface can tell that from a
 * working one. A behavioral test sends to a loopback receiver and
 * compares the bytes.
 *
 * @example
 *   var status = delivery.wireDeliveryStatus(b.mail);
 *   if (!status.available) log.error(status.reason);
 */
function wireDeliveryStatus(mailSurface) {
  var surface = mailSurface || {};
  // The name the composer itself reaches for. Asking the surface for the
  // capability, rather than for a symptom of its absence, is what keeps
  // this answer from going stale: there is nothing recorded to disagree
  // with the framework.
  var transports = surface.transports;
  var hasTransport = transports !== null && typeof transports === "object" &&
    typeof transports.smtp === "function";

  if (hasTransport) return { available: true, reason: "", issues: [] };

  return { available: false, reason: WIRE_DELIVERY_BLOCKED, issues: [] };
}

// The spool ceiling, refused at create rather than read at the message
// that crosses it.
//
// Both values decide whether a message is taken or refused, so a value
// that is not a usable number is a ceiling that either refuses
// everything or bounds nothing, and both of those are found at 03:00
// rather than at boot unless they are refused here. A depth that is not
// a whole count is the same fault wearing a decimal point: an entry is
// a file, and there is no such thing as four and a half of them.
//
// The floor on the byte ceiling is the one check that is about more
// than the shape of the value. A spool whose ceiling is smaller than
// one message cannot hold one message, so every message crosses it and
// the server takes nothing at all. That reads as a total outage with a
// configuration file that looks entirely reasonable, which is the kind
// of setting that has to be refused rather than honored.
//
// What one message costs is the caller's to say, because it is the
// listeners that decide what they accept and this module never sees
// that setting. When the caller says nothing the floor falls back to
// the shipped ceiling, which is what the listeners run on a
// configuration that names none: the composition facade resolves the
// operator's number the same way and hands it in, so the two agree.
//
// The shipped ceiling rather than the schema's floor, which is eight
// hundred times smaller. A floor set there would pass a spool sized for
// a sixty-fourth of a mebibyte on a server accepting fifty, and a spool
// too small to hold one message is the whole of what this check is for.
function _assertSpoolOpts(spool, maxMessageBytes) {
  if (spool === undefined || spool === null) return;
  if (typeof spool !== "object" || Array.isArray(spool)) {
    throw new TypeError("blamepost.mail.delivery.create: opts.spool must be an object of " +
      "{ maxMessages, maxBytes }");
  }
  if (spool.maxMessages !== undefined) {
    var n = spool.maxMessages;
    if (typeof n !== "number" || !isFinite(n) || n < 1 || Math.floor(n) !== n) {
      throw new TypeError("blamepost.mail.delivery.create: opts.spool.maxMessages must be a " +
        "whole number of waiting recipients of at least 1. It is the depth past which the " +
        "listeners refuse a message temporarily rather than letting the spool grow without " +
        "a bottom.");
    }
  }
  if (spool.maxBytes === undefined) return;
  var bytes = spool.maxBytes;
  if (typeof bytes !== "number" || !isFinite(bytes) || bytes < 1 ||
      Math.floor(bytes) !== bytes) {
    throw new TypeError("blamepost.mail.delivery.create: opts.spool.maxBytes must be a whole " +
      "number of bytes of at least 1. It is the volume past which the listeners refuse a " +
      "message temporarily rather than letting the spool take the whole disk.");
  }
  var floor = typeof maxMessageBytes === "number" && isFinite(maxMessageBytes) &&
    maxMessageBytes > 0 ? maxMessageBytes : SHIPPED_MAX_MESSAGE_BYTES;
  if (bytes < floor) {
    throw new TypeError("blamepost.mail.delivery.create: opts.spool.maxBytes must be at least " +
      floor + " bytes, which is one message at the size this server accepts. A ceiling below " +
      "one message refuses every message the listeners take, so the server accepts nothing at " +
      "all. Lower config.limits.maxMessageBytes as well if the intention is to accept smaller " +
      "mail.");
  }
}

// The retry settings, refused at create rather than read at the first
// send.
//
// Both values end up in arithmetic that decides when a message is tried
// again and when it is given up on. A wait that is not a positive
// number of milliseconds produces a moment that is either in the past
// forever or not a number at all, and either one turns the sweep into a
// loop that spends the whole budget in a second and then discards the
// message. A backoff list spelled as something other than a list is
// worse than a bad value: the composer ignores it and runs the shipped
// defaults, so an operator who narrowed the budget is never told their
// setting had no effect.
//
// The composer refuses a bad `maxAttempts` on its own; it is checked
// here as well so the refusal names the option an operator set rather
// than the framework's spelling of it.
function _assertRetryOpts(retry) {
  if (retry === undefined || retry === null) return;
  if (typeof retry !== "object" || Array.isArray(retry)) {
    throw new TypeError("blamepost.mail.delivery.create: opts.retry must be an object of " +
      "{ maxAttempts, backoffMs }");
  }
  if (retry.maxAttempts !== undefined) {
    var n = retry.maxAttempts;
    if (typeof n !== "number" || !isFinite(n) || n < 1 || Math.floor(n) !== n) {
      throw new TypeError("blamepost.mail.delivery.create: opts.retry.maxAttempts must be a " +
        "whole number of attempts of at least 1, so a message that is never accepted is " +
        "eventually given up on and its sender told");
    }
  }
  if (retry.backoffMs === undefined) return;
  if (!Array.isArray(retry.backoffMs) || retry.backoffMs.length === 0) {
    throw new TypeError("blamepost.mail.delivery.create: opts.retry.backoffMs must be a " +
      "non-empty array of waits in milliseconds. Leave it out to keep the shipped waits; " +
      "an unusable value here would otherwise be ignored and the shipped waits used anyway.");
  }
  for (var i = 0; i < retry.backoffMs.length; i += 1) {
    var wait = retry.backoffMs[i];
    if (typeof wait !== "number" || !isFinite(wait) || wait <= 0) {
      throw new TypeError("blamepost.mail.delivery.create: opts.retry.backoffMs[" + i + "] " +
        "must be a finite number of milliseconds greater than zero. A wait of zero or less " +
        "retries without waiting, which spends the whole retry budget on one unreachable peer.");
    }
    if (wait > MAX_BACKOFF_MS) {
      throw new TypeError("blamepost.mail.delivery.create: opts.retry.backoffMs[" + i + "] " +
        "must be no longer than a week. A wait longer than that is not a retry schedule: " +
        "the message stays in the spool untried, its sender is never told it failed, and " +
        "nothing ever clears it.");
    }
  }
}

/**
 * @primitive blamepost.mail.delivery.create
 * @signature blamepost.mail.delivery.create(opts)
 * @since     0.1.0
 * @status    stable
 * @spec      RFC 5321, RFC 8461 (MTA-STS), RFC 7672 (DANE), RFC 8689 (REQUIRETLS), RFC 3464 (DSN)
 *
 * Build the outbound handle every send site in this server calls.
 * Wraps `b.mail.send.deliver.create` so the policy chain runs once,
 * adds the on-disk retry spool the composer leaves to the operator,
 * turns a permanent failure into a delivery status notification
 * addressed to the original sender, and asks the MTA-STS record
 * question over `opts.resolver` before a message is handed over.
 *
 * `opts.resolver` is load-bearing under an enforcing MTA-STS posture,
 * because its answer decides whether a message is held here rather than
 * offered to the domain. A handle that cannot answer TXT questions is
 * refused here rather than at the first send.
 *
 * It does not decide whether the delivery is protected. The composer
 * asks the same record question a second time over the resolver the
 * framework shares, and that asking is the one the MX filtering and the
 * refusal run from. A domain publishing no record is refused
 * permanently when the shared resolver cannot answer for it, whatever
 * `opts.resolver` answered. The lookup that decides is the framework's
 * own, and it accepts no resolver from here.
 *
 * Returns `{ send, bounce, queue, tlsRpt, start, stop, describe }`.
 * `send` takes an envelope and returns the composer's per recipient
 * outcome, screened for display, after spooling every recipient the
 * peer answered with a transient code. `queue` exposes the spool:
 * `list`, `count`,
 * `held`, `show`, `runDue`, `remove`, `capacity`, `admits`, `reserve`
 * and `claim`.
 * `tlsRpt` exposes the RFC 8460 reports this server owes the domains it
 * delivers to: `observed` and `run`. `start` arms the sweep and
 * reporting timers and `stop` disarms them, so a process that only
 * sends without draining, such as a one shot CLI run, never leaves a
 * timer holding the loop open.
 *
 * The spool is bounded, and `send` refuses rather than growing it past
 * the bound. The refusal carries the code in `SPOOL_FULL_CODE`, and
 * both listeners turn it into a temporary answer on the wire, so the
 * message stays with whoever sent it. An envelope is admitted whole or
 * refused whole: one that spooled some recipients and refused the rest
 * would be retried and delivered twice to everybody already waiting.
 *
 * Admission takes the room rather than measuring it. `queue.reserve`
 * answers whether there is room and keeps what it admitted until the
 * caller releases it, so the ceiling weighs the volume plus every
 * message partway through writing to it and two connections cannot both
 * be given the last slot. `queue.admits` answers the same question and
 * holds nothing, for a caller that only wants to report the number.
 *
 * Bad configuration throws at create time rather than at the first
 * send: an operator finds a typo at boot, not on a bounce at 03:00.
 *
 * @opts
 *   hostname:        string,   // required; HELO name and DSN Reporting-MTA
 *   dataDir:         string,   // required; the spool lives at <dataDir>/queue
 *   postmaster:      string,   // From: on delivery reports and envelope sender on TLS-RPT reports; default MAILER-DAEMON@<hostname>
 *   port:            number,   // peer port; default 25
 *   resolver:        object,   // b.network.dns.resolver handle; MX and MTA-STS both go to it
 *   policy:          object,   // { mtaSts: "enforce"|"testing"|"off", dane: "opportunistic"|"enforce"|"off" }
 *   retry:           object,   // { maxAttempts, backoffMs }; default 35 attempts over 1m/5m/15m/1h/4h, giving up after 5 days
 *   timeouts:        object,   // { mxLookupMs, perHostMs }; a wait left out is the composer's own
 *   spool:           object,   // { maxMessages, maxBytes }; ceiling past which a message is refused
 *   maxMessageBytes: number,   // largest message the listeners accept; checked against spool.maxBytes
 *   requireTls:      boolean,  // RFC 8689: put REQUIRETLS on MAIL FROM, and permanently fail a recipient no MX host advertises it for; default false
 *   sweepIntervalMs: number,   // spool sweep cadence; default 60s
 *   tlsRptIntervalMs: number,  // RFC 8460 report cadence; default 24h
 *   tlsRptSubmit:    object,   // { httpClient, timeoutMs } for HTTPS report submission
 *   audit:           boolean,  // framework audit emission; default true
 *
 * @example
 *   var delivery = blamepost.mail.delivery.create({
 *     hostname: "mx.example.com",
 *     dataDir:  "/var/lib/blamepost",
 *     policy:   { mtaSts: "enforce", dane: "opportunistic" },
 *   });
 *   delivery.start();
 *   var outcome = await delivery.send({
 *     from:   "alice@example.com",
 *     to:     ["bob@example.net"],
 *     rfc822: messageBytes,
 *   });
 */
function create(opts) {
  if (!opts || typeof opts !== "object" || Array.isArray(opts)) {
    throw new TypeError("blamepost.mail.delivery.create: opts object is required");
  }
  if (typeof opts.hostname !== "string" || opts.hostname.length === 0) {
    throw new TypeError("blamepost.mail.delivery.create: opts.hostname is required " +
      "(the public name this server announces in HELO and reports as the Reporting-MTA)");
  }
  if (typeof opts.dataDir !== "string" || opts.dataDir.length === 0) {
    throw new TypeError("blamepost.mail.delivery.create: opts.dataDir is required " +
      "(the outbound spool lives at <dataDir>/queue)");
  }
  configModule.assertAbsoluteDataDir(
    "blamepost.mail.delivery.create: opts.dataDir", opts.dataDir);
  var sweepIntervalMs = opts.sweepIntervalMs === undefined
    ? DEFAULT_SWEEP_MS : opts.sweepIntervalMs;
  if (typeof sweepIntervalMs !== "number" || !isFinite(sweepIntervalMs) || sweepIntervalMs < TIME.seconds(1)) {
    throw new TypeError("blamepost.mail.delivery.create: opts.sweepIntervalMs must be a " +
      "finite number of milliseconds no smaller than 1000");
  }
  if (opts.postmaster !== undefined &&
      (typeof opts.postmaster !== "string" || opts.postmaster.indexOf("@") === -1)) {
    throw new TypeError("blamepost.mail.delivery.create: opts.postmaster must be an " +
      "address the operator controls, for example MAILER-DAEMON@" + opts.hostname);
  }
  _assertRetryOpts(opts.retry);
  _assertSpoolOpts(opts.spool, opts.maxMessageBytes);
  if (opts.requireTls !== undefined && typeof opts.requireTls !== "boolean") {
    throw new TypeError("blamepost.mail.delivery.create: opts.requireTls must be a boolean. " +
      "It decides whether every outbound envelope asks a peer for REQUIRETLS (RFC 8689), and " +
      "a value that is neither true nor false leaves that undecided at the point where the " +
      "answer changes whether mail is delivered or bounced.");
  }

  var hostname = opts.hostname;
  var postmaster = opts.postmaster || ("MAILER-DAEMON@" + hostname);
  // The handle-wide REQUIRETLS posture. An envelope may carry its own,
  // which wins; this is what applies when it does not.
  var requireTls = opts.requireTls === true;
  var spoolDir = nodePath.join(opts.dataDir, "queue");
  b.atomicFile.ensureDir(spoolDir, 0o700);
  var log = b.log.boot("mail.delivery");

  var spoolOpts = opts.spool || {};
  var maxSpoolMessages = spoolOpts.maxMessages === undefined
    ? DEFAULT_MAX_SPOOL_MESSAGES : spoolOpts.maxMessages;
  var maxSpoolBytes = spoolOpts.maxBytes === undefined
    ? DEFAULT_MAX_SPOOL_BYTES : spoolOpts.maxBytes;

  // Where a message arriving from a stranger stops. Rounded down, and
  // then held below the ceiling by at least one entry however small the
  // ceiling is, because a reservation that rounds up to the whole thing
  // is not a reservation.
  var strangerMessages = Math.min(maxSpoolMessages - 1,
    Math.floor(maxSpoolMessages * STRANGER_SPOOL_SHARE));
  var strangerBytes = Math.floor(maxSpoolBytes * STRANGER_SPOOL_SHARE);

  // Where a report this server generated stops. Held to at least one
  // entry however small the ceiling is, because a share that rounds to
  // nothing would mean no sender is ever told their mail failed, which
  // is the failure a mail server exists to prevent.
  var reportMessages = Math.max(1,
    Math.min(strangerMessages, Math.floor(maxSpoolMessages * REPORT_SPOOL_SHARE)));
  var reportBytes = Math.max(MIN_CONFIGURABLE_MESSAGE_BYTES,
    Math.min(strangerBytes, Math.floor(maxSpoolBytes * REPORT_SPOOL_SHARE)));

  // The process table this process's claims are issued from, read once.
  var ourNamespace = _processNamespace();

  // Envelopes this handle refused because the spool was full, since the
  // process started. Surfaced by describe(), so an operator reading a
  // server that is refusing mail can tell the spool apart from
  // everything else that answers a client with a temporary code.
  var spoolRefusals = 0;

  // Room the spool has promised to messages that have not written it yet.
  //
  // Between a message being admitted and its entries reaching disk are a
  // copy filed into every mailbox this server holds for the envelope, an
  // MX lookup, a policy chain and a conversation with a receiver that
  // answers at its own pace. The spool is one directory shared with every
  // other connection and with the retry sweep, so an admission that
  // weighed only what is on disk would hand the same last slot to two
  // senders at once. These two numbers are what makes the admission a
  // reservation instead: they go up when a message is admitted and back
  // down when it has finished, and every ceiling is measured against the
  // volume plus them.
  //
  // They over-count for the length of one message, because the entries a
  // message writes are on disk and still held until it releases. Refusing
  // a message temporarily where it need not have been is the direction to
  // be wrong in: the sender keeps their copy.
  var heldSpoolEntries = 0;
  var heldSpoolBytes   = 0;

  // Recipients currently being retried by a sweep. A second sweep that
  // overlaps the first must not send the same spooled message twice.
  // It is the cheap first gate and it covers only this process; the
  // claim `_claimEntry` takes is what covers the second one.
  var inFlight = new Set();
  var sweepTimer = null;

  // Asked once, at create, so an operator whose build cannot send reads
  // it at boot rather than discovering it from a queue that stopped
  // draining.
  var wireDelivery = wireDeliveryStatus(b.mail);
  if (!wireDelivery.available) log.error(wireDelivery.reason);

  // Reports this server owed somebody and did not send, which today is
  // the ones the generation bound refused. Surfaced by describe(), so
  // `blamepost doctor` can report a number rather than leaving the
  // operator to notice error lines going by.
  var reportsUnsent = 0;

  // The retry budget, resolved once and handed to everything that spends
  // it.
  //
  // Two paths reach the end of it and they have to reach it together.
  // The composer converts a peer's temporary refusal to a permanent one
  // when the attempt count runs out; the spool gives up on a fault of
  // its own the same way, over the same schedule. Handing the composer
  // the raw option instead would leave it applying its own defaults
  // while this file applied a second set, so the two budgets would be
  // one only for as long as nobody changed either.
  //
  // Every shape this reads has already been refused by `_assertRetryOpts`
  // above, in this module's own words, which is a strictly narrower check
  // than the composer's: it wants a whole number of attempts and a wait
  // per entry that a date can hold.
  var retryOpts = opts.retry || {};
  var backoffMs = Array.isArray(retryOpts.backoffMs) && retryOpts.backoffMs.length > 0
    ? retryOpts.backoffMs.slice()
    : DEFAULT_RETRY_BACKOFF_MS.slice();
  var maxAttempts = retryOpts.maxAttempts !== undefined
    ? retryOpts.maxAttempts
    : DEFAULT_MAX_ATTEMPTS;

  // The framework composer. Its dsn hook fires once per permanently
  // failed recipient and hands back a ready RFC 3464 report, which is
  // where the report path picks the outcome up.
  var deliverPolicy = opts.policy || { mtaSts: "enforce", dane: "opportunistic" };

  // An enforcing DANE posture with nothing standing behind it is refused
  // here rather than accepted and allowed to authenticate against
  // records nobody validated.
  //
  // This is the boot, so the operator reads it while they are changing
  // the setting. The refusal names the value to add and the value to use
  // instead, and it lifts the moment they state that their resolver
  // validates.
  // The composer's own default when the operator named no DANE posture,
  // resolved here rather than read straight off the option, for the
  // reason `stsMode` below is: the two settings are independent, so a
  // configuration naming one and leaving the other alone is the ordinary
  // shape, and `describe()` is what an operator reads to find out which
  // transport security produced the queue in front of them. Echoing the
  // option instead of the resolved value reports a posture this server
  // is not keeping.
  var daneMode = deliverPolicy.dane || "opportunistic";

  var daneEnforcement = daneEnforcementStatus(b.mail.send, deliverPolicy);
  if (daneMode === "enforce" && !daneEnforcement.available) {
    throw new TypeError("blamepost.mail.delivery.create: " + daneEnforcement.reason);
  }

  var deliver = b.mail.send.deliver.create({
    hostname:  hostname,
    port:      opts.port,
    resolver:  opts.resolver,
    policy:    deliverPolicy,
    retry:     { maxAttempts: maxAttempts, backoffMs: backoffMs.slice() },
    timeouts:  opts.timeouts,
    audit:     opts.audit,
    dsn: {
      from: postmaster,
      // Three arguments, and the third is the one that matters: the
      // composer builds the report and hands it over, so a wrapper that
      // forwards only the envelope and the outcome leaves the report
      // path with nothing to send.
      onPermanentFailure: function (envelope, result, dsnMessage) {
        return _reportFailure(envelope, result, dsnMessage);
      },
    },
  });

  // The two budgets are read back from the composer and compared against
  // the pair handed to it.
  //
  // The pair is passed explicitly precisely so one budget governs both
  // paths, and that only works while the composer resolves the pair to
  // what it was given. It has not always: it derived the attempt count
  // from its own constant rather than from the caller's schedule, so a
  // caller supplying a short ramp still ran the default number of
  // attempts and repeated its last wait. A mismatch there does not throw
  // anywhere. The spool would count one budget while the composer
  // converted a temporary refusal to a permanent one on another, so a
  // message would be given up on and its sender told, at a time neither
  // this file nor the operator guide names.
  //
  // What is compared is the composer's own answer rather than a number
  // restated here, so a future change to how it derives them is a boot
  // failure naming both values instead of a queue that silently gives up
  // early.
  if (typeof deliver.retryPolicy === "function") {
    var resolved = deliver.retryPolicy();
    if (resolved.maxAttempts !== maxAttempts ||
        resolved.backoffMs.length !== backoffMs.length) {
      throw new TypeError("blamepost.mail.delivery.create: the outbound composer resolved a " +
        "retry budget of " + resolved.maxAttempts + " attempt(s) over " +
        resolved.backoffMs.length + " wait(s), and this server spends " + maxAttempts +
        " attempt(s) over " + backoffMs.length + " wait(s) on its own spool. The two have to " +
        "be one budget: the composer decides when a temporary refusal becomes permanent and " +
        "the sender is told, and the spool decides when to stop retrying, so a message given " +
        "up on at two different times is one whose sender is told at neither.");
    }
  }

  // The two waits an outbound attempt spends, as this handle forwarded
  // them, kept so `describe()` can report them.
  //
  // Read after the composer has been built, because that is where a
  // value which is not a pair of waits is refused. What reaches here is
  // a pair or nothing at all.
  //
  // A wait the operator left alone is reported as null rather than as a
  // number. The number that would stand there is the composer's, it
  // moves with a vendor refresh, and this file has no reading of it to
  // compare a copy against, so a copy would report a wait this server is
  // not running from the first refresh that moved one. Null also keeps
  // the two states apart: a wait somebody wrote and a wait nobody wrote
  // are different answers, and an operator reading their own
  // configuration back is asking which of the two they are in.
  var timeoutOpts = opts.timeouts && typeof opts.timeouts === "object" &&
    !Array.isArray(opts.timeouts) ? opts.timeouts : {};
  var outboundTimeouts = {
    mxLookupMs: timeoutOpts.mxLookupMs === undefined ? null : timeoutOpts.mxLookupMs,
    perHostMs:  timeoutOpts.perHostMs === undefined ? null : timeoutOpts.perHostMs,
  };

  // The MTA-STS record lookup, over the resolver the operator pinned
  // (see MTA_STS_TXT_LOOKUP_FAILED). One reader, shared with the DNS
  // posture report, so both ask DNS the same way and read absence the
  // same way.
  //
  // This answer decides whether this server hands the recipient to the
  // composer. The composer asks the same record question again for
  // itself, over the `resolver` it is handed, which is the one pinned
  // here, so the two askings read one answer.
  // `test/layer-1-state/outbound-policy.test.js` holds the measurement
  // and fails when the two verdicts stop agreeing.
  //
  // With no resolver pinned there is nothing to guarantee and the gate
  // is off: the framework's own validating resolver answers, which is
  // what it would have done anyway, and asking twice would only make
  // this server refuse mail on the strength of a lookup the operator
  // never chose either. `blamepost.create` always pins one.
  //
  // The composer's own default when nothing is said is `enforce`, and
  // it is resolved here rather than read straight off the option, so
  // the two cannot disagree about a posture nobody wrote down.
  var stsMode = deliverPolicy.mtaSts || "enforce";
  if (stsMode === "enforce" && opts.resolver &&
      typeof opts.resolver.queryTxt !== "function") {
    throw new TypeError("blamepost.mail.delivery.create: opts.resolver cannot answer TXT " +
      "questions, so the MTA-STS record that decides whether this server holds a message " +
      "back rather than offering it to a domain could not be looked up over it. Pass a " +
      "b.network.dns.resolver handle, or set policy.mtaSts to \"testing\" or \"off\" if " +
      "that is the posture you want");
  }
  var stsLookup = opts.resolver && typeof opts.resolver.queryTxt === "function"
    ? posture.txtLookup(opts.resolver)
    : null;

  // Whether the MTA-STS question about this domain is unanswered.
  //
  // `null` means nothing blocks the message: the domain publishes no
  // policy, or publishes one and the pinned resolver said so. A row
  // means the record lookup could not complete, which under an
  // enforcing posture is not the same as "no policy" and must not be
  // read as one. Absence arrives from the shared reader as the signal
  // the policy fetcher recognizes, so a name that does not exist reads
  // as no policy rather than as a broken resolver. That is the answer
  // nearly every domain gives.
  //
  // Only `enforce` blocks. RFC 8461 §5 says a policy published in
  // testing mode may be delivered against as though there were no
  // validation failure, and an operator who set `off` asked for none of
  // this.
  async function _mtaStsUnanswered(domain) {
    if (stsMode !== "enforce" || stsLookup === null) return null;
    if (typeof domain !== "string" || domain.length === 0) return null;
    try {
      // What comes back is kept rather than discarded. A receiver whose
      // policy this server read is a receiver whose report can name the
      // policy the attempt was made under, which is the difference
      // between a report they can act on and a count they cannot place.
      var policy = await b.network.smtp.mtaSts.fetch(domain, { dnsLookup: stsLookup });
      // Bounded the same way the accumulator is, and for the same
      // reason: a relay meets a new receiving domain on most messages,
      // so a memo that only ever grew would hold one policy per domain
      // this process ever sent to. Past the cap a report says the
      // policy type and not the policy text, which is a smaller report
      // rather than a wrong one.
      if (policy && (stsPolicySeen.has(domain) || stsPolicySeen.size < MAX_TLS_RPT_DOMAINS)) {
        stsPolicySeen.set(domain, policy);
      }
      return null;
    } catch (err) {
      // A policy that was found and could not be fetched or parsed is a
      // different question with its own verdict, and the composer owns
      // that one. This is only about the record that decides whether
      // there is a policy to fetch at all.
      if (String((err && err.code) || "") !== MTA_STS_TXT_LOOKUP_FAILED) return null;
      var why = "the MTA-STS record for " + domain + " could not be looked up, and this " +
        "server will not deliver under an enforcing posture without knowing whether the " +
        "domain publishes a policy: " + ((err && err.message) || String(err));
      b.audit.safeEmit({
        action:   "blamepost.mail.delivery.mta_sts_unanswered",
        outcome:  "failure",
        metadata: { domain: _screenForDisplay(domain), reason: _screenForDisplay(why) },
      });
      return { reason: why, reasonCode: MTA_STS_UNSETTLED_STATUS };
    }
  }

  function _domainOf(recipient) {
    var parsed = address.parse(recipient);
    return parsed.ok ? parsed.domain : "";
  }

  // ---- TLS-RPT: what each attempt leaves behind -------------------------

  // One small file per receiving domain under `<dataDir>/tlsrpt`. On
  // disk rather than in memory because a mail server restarts, and a
  // daily report that only ever covers the minutes since the last
  // restart is a report nobody can act on.
  var tlsRptDir = nodePath.join(opts.dataDir, "tlsrpt");
  b.atomicFile.ensureDir(tlsRptDir, 0o700);

  // MTA-STS policies this process has read, so a report can name the
  // policy an attempt was made under. Per process rather than persisted:
  // a policy is the receiver's to change and the framework's fetch
  // caches it on its own terms, so a stale copy carried across a restart
  // would describe a posture that may no longer exist.
  var stsPolicySeen = new Map();

  // Read-modify-write on one domain's file, serialized per domain.
  // Recipients on different domains never touch the same file, and two
  // attempts to the same domain from two connections would otherwise
  // interleave and lose one of the two counts.
  var tlsRptWrites = new Map();
  var tlsRptSubmitted = 0;
  var tlsRptQueued = 0;
  var tlsRptUnsent = 0;
  var tlsRptLastRunAt = null;
  var tlsRptTimer = null;

  var tlsRptIntervalMs = opts.tlsRptIntervalMs === undefined
    ? DEFAULT_TLS_RPT_INTERVAL_MS : opts.tlsRptIntervalMs;
  if (typeof tlsRptIntervalMs !== "number" || !isFinite(tlsRptIntervalMs) ||
      tlsRptIntervalMs < TIME.seconds(1)) {
    throw new TypeError("blamepost.mail.delivery.create: opts.tlsRptIntervalMs must be a " +
      "finite number of milliseconds no smaller than 1000. RFC 8460 §4.1 puts an aggregate " +
      "report at a day, which is the shipped period; the floor here only refuses a value " +
      "that would spin the reporting timer.");
  }

  // How a report reaches an HTTPS destination, when the operator wants
  // it to go somewhere other than straight out of this process. The
  // framework's submission takes both keys; naming them here is what
  // lets the timer-driven run use them, since nobody passes options to
  // a timer. A per-run value still wins, because a run driven by hand
  // is somebody asking for this one to go differently.
  var tlsRptSubmitOpts = opts.tlsRptSubmit || {};
  if (typeof tlsRptSubmitOpts !== "object" || Array.isArray(tlsRptSubmitOpts)) {
    throw new TypeError("blamepost.mail.delivery.create: opts.tlsRptSubmit must be an object " +
      "of { httpClient, timeoutMs }");
  }

  // The reader every TLS-RPT endpoint lookup goes through. It is the
  // same one the MTA-STS question uses when the operator pinned a
  // resolver, because a spoofed `_smtp._tls` record redirects this
  // server's own failure reports to whoever forged it. Built on demand
  // so a handle that never runs a report never constructs a resolver.
  var tlsRptLookup = null;
  function _tlsRptLookup() {
    if (tlsRptLookup) return tlsRptLookup;
    tlsRptLookup = stsLookup ||
      posture.txtLookup(b.network.dns.resolver.create({ profile: "strict" }));
    return tlsRptLookup;
  }

  // The one place a path under this directory is built.
  //
  // The leading marker is not decoration. A receiving domain is chosen
  // by whoever an account writes to, and a domain like `con.example` or
  // `nul.example` passes every domain rule there is while naming a
  // Windows character device once it becomes a file name.
  // `b.guardFilename` at strict says `reserved-name` about
  // `con.example.json` and says nothing about `d.con.example.json`, so
  // a constant first segment retires the whole class rather than the
  // handful of names anyone thought to list.
  //
  // Measured rather than assumed, and the measurement cut the other
  // way: on this host, Node writes and reads a real file called
  // `con.example.json` without touching the console at all. The marker
  // stays because the framework's own filename reader disagrees with
  // that one observation, and because an operator's shell, an older
  // runtime or a backup walking the directory each parse the name their
  // own way.
  var TLS_RPT_FILE_MARKER = "d.";

  function _tlsRptPath(domain) {
    return nodePath.join(tlsRptDir, TLS_RPT_FILE_MARKER + domain + ".json");
  }

  function _tlsRptDomainInFile(name) {
    if (name.slice(0, TLS_RPT_FILE_MARKER.length) !== TLS_RPT_FILE_MARKER) return null;
    if (name.slice(-5) !== ".json") return null;
    return name.slice(TLS_RPT_FILE_MARKER.length, -5);
  }

  function _tlsRptFiles() {
    return b.atomicFile.listDir(tlsRptDir, {
      filter: function (name) { return _tlsRptDomainInFile(name) !== null; },
    });
  }

  // One domain's accumulated observations, or null when the file is
  // absent or cannot be read. An unreadable file is a crash between the
  // write and the rename; it is dropped rather than reported, because
  // what it held was counters and nothing in it was mail.
  async function _readTlsRptRecord(domain) {
    var record;
    try {
      record = await b.atomicFile.readJson(_tlsRptPath(domain), {
        maxBytes: MAX_TLS_RPT_FILE_BYTES,
      });
    } catch (_e) { return null; }
    if (!record || typeof record !== "object") return null;
    // When the accumulation window opened, as an instant rather than as
    // a duration. It has to be a wall clock reading and stays one: RFC
    // 8460 section 4.3 puts it in front of a receiver as a real date and
    // section 5.3 puts it in the filename they file the report under, so
    // an elapsed count would mean nothing at the other end.
    //
    // What a wall clock reading needs instead is a check on the way back
    // in. A host that was running ahead when the window opened, and has
    // since been corrected, holds a start LATER than the present, and a
    // report built from it names a period that ends before it began.
    // That reaches the receiver twice, in the document and in the
    // filename, and it is the kind of malformed input a reader either
    // rejects or files under the wrong day.
    //
    // Re-anchored to now rather than refused. The counts underneath it
    // are real transport-security observations the receiver is owed, and
    // withholding them would let a clock correction suppress reporting,
    // which is the same failure in different clothes. What this server
    // can no longer stand behind is the instant, so it stops claiming
    // it and names one it can. The corrected value is what the next
    // observation writes back, so the record heals rather than carrying
    // the bad instant until the period closes.
    var readAt = Date.now();
    var recorded = typeof record.since === "number" && isFinite(record.since)
      ? record.since : readAt;
    return {
      domain:       typeof record.domain === "string" ? record.domain : domain,
      since:        recorded > readAt ? readAt : recorded,
      policyType:   record.policyType === TLS_RPT_POLICY_STS
        ? TLS_RPT_POLICY_STS : TLS_RPT_POLICY_NONE,
      policyString: Array.isArray(record.policyString) ? record.policyString : [],
      mxHosts:      Array.isArray(record.mxHosts) ? record.mxHosts : [],
      successful:   typeof record.successful === "number" ? record.successful : 0,
      failures:     Array.isArray(record.failures) ? record.failures : [],
    };
  }

  function _writeTlsRptRecord(record) {
    return b.atomicFile.writeJson(_tlsRptPath(record.domain), record,
      { fileMode: 0o600, indent: 2 });
  }

  async function _dropTlsRptRecord(domain) {
    await nodeFs.promises.rm(_tlsRptPath(domain), { force: true });
  }

  function _tlsRptSerial(domain, work) {
    var prior = tlsRptWrites.get(domain) || Promise.resolve();
    var next = prior.then(work, work);
    // The chain has to survive one failure, or a single unwritable file
    // would stop every later observation about that domain.
    var settled = next.then(function () { /* settled */ },
      function () { /* drop-silent by design: the failure was already recorded */ });
    tlsRptWrites.set(domain, settled);
    // And the key goes once nothing is queued behind it. A relay touches
    // a new receiving domain on most messages, so a map that only ever
    // grew would hold one entry per domain this process ever sent to.
    settled.then(function () {
      if (tlsRptWrites.get(domain) === settled) tlsRptWrites.delete(domain);
    });
    return next;
  }

  // What one attempt says about the receiver's transport security.
  //
  // Drop-silent by design: a report is not mail, and a full disk or an
  // unreadable counter file must never cost the delivery that produced
  // it.
  //
  // Three things are refused outright rather than recorded. An attempt
  // whose outcome is marked held is one where nothing was negotiated, so
  // reporting it would accuse the receiver of a fault that was this
  // server's. An outcome that is not a transport-security event is not
  // one a TLS report may carry: a refusal that is genuinely the
  // receiver's and genuinely nothing to do with TLS, such as a domain
  // publishing no mail exchanger, would otherwise tell them to go and
  // look at their certificates. And a receiving domain past the tracking
  // cap is skipped rather than allowed to grow the volume.
  //
  // The classification is what does the work once an attempt reaches a
  // socket. It is what keeps this server from signing an accusation
  // about somebody else's transport security on the strength of a full
  // mailbox or an unresolvable name.
  async function _observeTlsRpt(recipient, outcome) {
    try {
      if (outcome && outcome.held === true) return;
      var domain = _tlsRptDomainOf(recipient);
      if (domain === null) return;
      var delivered = outcome && outcome.delivered === true;
      var resultType = delivered ? null : tlsRptResultFor(outcome);
      if (!delivered && resultType === null) return;
      // Read here, where the composer's whole message is still in hand.
      // What survives onto the row is screened and bounded, so the same
      // reading taken at report time would be taken from less than this
      // one sees.
      var rowPolicyType = delivered ? null : _tlsRptPolicyTypeFor(outcome, resultType);

      await _tlsRptSerial(domain, async function () {
        var record = await _readTlsRptRecord(domain);
        if (record === null) {
          if (!b.atomicFile.exists(_tlsRptPath(domain)) &&
              _tlsRptFiles().length >= MAX_TLS_RPT_DOMAINS) {
            b.audit.safeEmit({
              action:   "blamepost.mail.delivery.tls_rpt_domains_capped",
              outcome:  "failure",
              metadata: { domain: _screenForDisplay(domain), cap: MAX_TLS_RPT_DOMAINS },
            });
            return;
          }
          record = {
            domain:       domain,
            since:        Date.now(),
            policyType:   TLS_RPT_POLICY_NONE,
            policyString: [],
            mxHosts:      [],
            successful:   0,
            failures:     [],
          };
        }

        var policy = stsPolicySeen.get(domain) || null;
        if (policy) {
          record.policyType = TLS_RPT_POLICY_STS;
          record.policyString = _tlsRptPolicyString(policy);
        } else if (resultType === TLS_RPT_RESULT.STS_FETCH_ERROR ||
                   resultType === TLS_RPT_RESULT.STS_INVALID) {
          // The policy itself is what failed, so there is no document to
          // quote back. The type still says MTA-STS, because that is
          // what the attempt was refused over.
          record.policyType = TLS_RPT_POLICY_STS;
        }

        var mxHost = outcome && typeof outcome.mxHost === "string" && outcome.mxHost.length
          ? outcome.mxHost : null;
        if (mxHost !== null && record.mxHosts.indexOf(mxHost) === -1 &&
            record.mxHosts.length < MAX_TLS_RPT_MX_HOSTS) {
          record.mxHosts.push(mxHost);
        }

        if (delivered) {
          record.successful += 1;
        } else {
          // The policy is part of what makes two failures the same
          // failure. One result type reaches a receiver from two
          // policies: a certificate a peer could not be authenticated
          // against is a general failure whether the records that
          // refused it were the receiver's TLSA set or the chain under
          // their MTA-STS policy. Counting those as one row would file
          // both under whichever arrived first.
          var key = resultType + "|" + (rowPolicyType || "") + "|" + (mxHost || "");
          var existing = null;
          for (var i = 0; i < record.failures.length; i += 1) {
            if (record.failures[i] && record.failures[i].key === key) {
              existing = record.failures[i];
              break;
            }
          }
          if (existing) {
            existing.count += 1;
          } else if (record.failures.length < MAX_TLS_RPT_FAILURE_ROWS) {
            record.failures.push({
              key:        key,
              resultType: resultType,
              policyType: rowPolicyType,
              mxHost:     mxHost,
              count:      1,
              reason:     _storedText((outcome && outcome.reason) || ""),
            });
          }
        }
        await _writeTlsRptRecord(record);
      });
    } catch (err) {
      // Drop-silent by design. The audit row is best effort as well, so
      // an observability failure cannot reach the delivery that caused
      // it through either route.
      try {
        b.audit.safeEmit({
          action:   "blamepost.mail.delivery.tls_rpt_observe_failed",
          outcome:  "failure",
          metadata: { error: _screenForDisplay((err && err.message) || String(err)) },
        });
      } catch (_e) {
        // allow:swallow-unverified the audit sink is the reporting path
        // itself and swallows inside safeEmit, so reaching this needs the
        // sink replaced rather than a fault driven through it. A report
        // this server could not record must not stop the mail it is about.
      }
    }
  }

  // Every recipient outcome of one attempt, observed exactly once.
  //
  // The composer's three lists are read rather than the settled
  // deferral list, because settling moves rows between them: a
  // recipient nobody answered for is taken off the permanent list and
  // pushed onto the deferral list, and reading both lists would count
  // it twice while reading only one would miss the case that moved.
  async function _observeOutcome(outcome) {
    if (!outcome) return;
    var lists = [
      { rows: outcome.delivered, delivered: true },
      { rows: outcome.deferred,  delivered: false },
      { rows: outcome.failed,    delivered: false },
    ];
    for (var l = 0; l < lists.length; l += 1) {
      var rows = Array.isArray(lists[l].rows) ? lists[l].rows : [];
      for (var r = 0; r < rows.length; r += 1) {
        await _observeTlsRpt(rows[r].recipient, {
          delivered:  lists[l].delivered,
          held:       rows[r].held === true,
          mxHost:     rows[r].mxHost,
          reason:     rows[r].reason,
          reasonCode: rows[r].reasonCode,
        });
      }
    }
  }

  // `reversePath` rather than `address`, because the module of that
  // name is required at the top of this file and a parameter sharing it
  // makes the module unreachable from inside here.
  function _isNullSender(reversePath) {
    if (typeof reversePath !== "string") return true;
    return NULL_SENDER_FORMS.indexOf(reversePath.trim()) !== -1;
  }

  // How many reports have been generated in the current window, in total
  // and per original sender, and when the window started.
  //
  // In memory rather than on disk, and that is the right place for it: a
  // restart resets the count, and a restart is also the point at which
  // an operator has intervened. A bound that survived one would keep
  // suppressing reports after the run that provoked it had been dealt
  // with, and nothing would say why.
  // Null until the first report is considered, rather than zero. The
  // reading it holds is elapsed process time, whose origin is a fixed
  // point this code does not get to choose, so a numeric sentinel would
  // be a value the first comparison could accidentally sit inside. An
  // absent window is stated as absent.
  var reportWindowStartedAt = null;
  var reportsThisWindow = 0;
  var reportsBySender = new Map();

  // Whether this server may generate one more report for this sender.
  //
  // The window is fixed rather than sliding: a sliding window needs a
  // timestamp per report and the memory that implies, keyed by an
  // address somebody else chose, which is the growth the bound exists to
  // stop. A fixed window can let through up to two windows' worth across
  // a boundary, and at these numbers that is a rounding error against
  // what it prevents.
  //
  // It is measured on elapsed time and not on the date, so the bound is
  // spent over an hour of this server running rather than over an hour
  // of whatever the host's clock happens to say. See `_elapsedMs`.
  function _mayGenerateReport(originalSender) {
    var now = _elapsedMs();
    if (reportWindowStartedAt === null ||
        now - reportWindowStartedAt >= REPORT_RATE_WINDOW_MS) {
      reportWindowStartedAt = now;
      reportsThisWindow = 0;
      reportsBySender = new Map();
    }
    if (reportsThisWindow >= MAX_REPORTS_PER_WINDOW) return false;

    var key = _text(originalSender).toLowerCase();
    var spent = reportsBySender.get(key);
    if (spent === undefined) {
      // A sender nobody has seen this window needs a slot in the map,
      // and the map has a bottom. Refusing past it is the conservative
      // direction: admitting an untracked sender is exactly the case
      // this bound exists to cover.
      if (reportsBySender.size >= MAX_TRACKED_REPORT_SENDERS) return false;
      spent = 0;
    }
    if (spent >= MAX_REPORTS_PER_SENDER_PER_WINDOW) return false;

    reportsBySender.set(key, spent + 1);
    reportsThisWindow += 1;
    return true;
  }

  // A report was owed and was not sent, which today means the generation
  // bound refused it. Loud by construction: an audit row at failure
  // outcome for whatever ships the audit trail, an error line for the
  // operator watching the process, and a counter describe() reads. The
  // return value carries the composer's own outcome shape, so a caller
  // handles this the same way it handles a refusal that came back from a
  // peer.
  //
  // `informing` is who should have been told. `about` is what they
  // should have been told about. Both are addresses that arrived from
  // somebody else. `limit` is why nobody was told, and two of the callers
  // build it out of what a peer or the outbound path said. All four
  // readers of those values put them in front of a person: the audit
  // row, the operator's log line, the counter's own error text, and the
  // outcome the caller reads back and prints. So the screen runs once
  // here and every one of them is answered from the screened value.
  function _recordUnsentReport(detail) {
    var why = _screenForDisplay(detail.limit || REPORT_RATE_LIMITED);
    reportsUnsent += 1;
    b.audit.safeEmit({
      action:   "blamepost.mail.delivery.report_unsent",
      outcome:  "failure",
      metadata: {
        origin:     detail.origin,
        informing:  _screenForDisplay(detail.informing || ""),
        about:      _screenForDisplay(detail.about || ""),
        statusCode: _screenForDisplay(detail.statusCode || ""),
        bytes:      detail.bytes || 0,
        limit:      why,
      },
    });
    log.error(_screenForDisplay(detail.summary) + ": " + why);
    return {
      delivered: [],
      deferred:  [],
      failed:    [_screenedReportRow({
        recipient:  detail.informing,
        reason:     why,
        reasonCode: detail.statusCode || "5.3.5",
        mxHost:     null,
        dsnSent:    false,
      })],
      reportUnsent: true,
    };
  }

  // The recipients from one attempt that are still to be delivered.
  //
  // The composer's deferral list is that set, and it is handed back as
  // it arrived. Nothing is relabeled and no counter is frozen: every
  // recipient here has a verdict from the attempt behind it, so each one
  // spends its place in the retry budget and reaches the end of that
  // budget as a permanent failure with a report to its sender.
  //
  // The refusal text travels exactly as it arrived, because on a
  // recipient that is still waiting it is the only diagnostic there is.
  //
  // Which list a recipient arrives on is the composer's own explicit
  // verdict, and it is the only thing any caller here reads to decide
  // whether a message may end. Reading the refusal text instead, and
  // keeping the message only where a particular sentence is recognized,
  // is the wrong way round: it keeps the failures somebody already
  // enumerated and charges every other one to a peer's retry budget, and
  // the failures nobody has enumerated are the whole population of the
  // future ones. No phrasing is matched anywhere to reach that decision.
  //
  // A recipient nobody answered for is one whose domain would not
  // resolve, which is an ordinary transient that the budget is for. A
  // permanent refusal carrying a transient status is this server having
  // spent the budget rather than a receiver having refused; the sender
  // hears about it in a report, so stopping and saying so is the honest
  // end of a message nobody would take.
  //
  // `mxHost` and `reasonCode` are the frozen contracts anything reading
  // an outcome should anchor on: `mxHost` is set only where a host
  // actually spoke, and `reasonCode` is the enhanced status, 5.1.2 for a
  // domain publishing no mail exchanger or the RFC 7505 null MX, 5.1.3
  // for an address that cannot be routed, 5.7.10 where a published
  // MTA-STS policy lists no matching exchanger, 4.7.0 where this server
  // withheld the message over an MTA-STS record it could not settle, and
  // 4.4.4 where nothing answered at all.
  function _settleVerdicts(outcome) {
    return Array.isArray(outcome && outcome.deferred) ? outcome.deferred : [];
  }

  // Whether an envelope this server handed to the outbound path reached
  // nobody and is not waiting for another attempt.
  //
  // A report carries one recipient, so the composer answers with one row
  // in one of its three lists. Delivered means a receiver took it.
  // Deferred means it is on disk with the retry budget in front of it,
  // and an entry that spends that budget ends with a row of its own. A
  // failed row beside two empty lists is the third answer, and from
  // outside it looks exactly like the first: nothing is queued, nothing
  // is going to try again, and the address the report was written to will
  // never receive it.
  function _reachedNobody(outcome) {
    if (!outcome || typeof outcome !== "object") return false;
    var failed    = Array.isArray(outcome.failed)    ? outcome.failed    : [];
    var delivered = Array.isArray(outcome.delivered) ? outcome.delivered : [];
    var deferred  = Array.isArray(outcome.deferred)  ? outcome.deferred  : [];
    return failed.length > 0 && delivered.length === 0 && deferred.length === 0;
  }

  // Hand one composed report to the outbound path, or record it when the
  // path will not carry it.
  //
  // A report that cannot be spooled must not throw out of here. Both
  // callers are past the point where throwing is free: the composer's
  // hook runs mid-delivery and a throw there loses the outcome of every
  // sibling recipient, and `bounce` runs after the MX listener has
  // already told a peer the message was accepted, so a throw reaches
  // that peer as a temporary failure and buys an endless retry of a
  // message this server will always refuse to report on. Recording it is
  // the same answer the generation bound gives, for the same reason.
  //
  // A report the outbound path refuses OUTRIGHT is recorded the same way,
  // and that is the third door into one silence. The sender's own domain
  // publishes no mail exchanger, or publishes the RFC 7505 null MX, and
  // the report is permanently failed the moment it is handed over: it is
  // not queued, no retry is coming, and the message it was about is
  // already off the volume. Read as a report that went, it moves no
  // counter, files no row, and leaves a cancellation verdict saying its
  // sender was told. The three readers that answer "was the sender told"
  // have to give the same answer here as they do for a report the bound
  // suppressed and a report the composer could not build.
  async function _sendReport(detail) {
    var outcome;
    try {
      outcome = await send({
        from:   REPORT_REVERSE_PATH,
        to:     [detail.informing],
        rfc822: detail.report,
        origin: ORIGIN_REPORT,
      });
    } catch (err) {
      return _recordUnsentReport({
        origin:     detail.origin,
        informing:  detail.informing,
        about:      detail.about,
        statusCode: detail.statusCode,
        bytes:      Buffer.byteLength(detail.report, "utf8"),
        limit:      "the outbound queue would not take it: " + ((err && err.message) || String(err)),
        summary:    detail.summary,
      });
    }
    if (!_reachedNobody(outcome)) return outcome;
    // The refusal is a peer's or a zone's words on their way to an
    // operator's log and audit trail, so it is screened here rather than
    // where the row is written: the other two callers pass a sentence
    // this module wrote.
    return _recordUnsentReport({
      origin:     detail.origin,
      informing:  detail.informing,
      about:      detail.about,
      statusCode: detail.statusCode,
      bytes:      Buffer.byteLength(detail.report, "utf8"),
      limit:      "the outbound path refused it outright, so nothing will retry it: " +
                  _screenForDisplay((outcome.failed[0] && outcome.failed[0].reason) || ""),
      summary:    detail.summary,
    });
  }

  // The composer's permanent-failure hook. RFC 5321 §6.1: a report
  // itself travels with the null return path so a permanently broken
  // sender address cannot start a loop of reports about reports. When
  // the failed envelope was already a report there is nobody left to
  // tell, and that is a correct silence rather than a lost message.
  // Anything else is a report this server owes the original sender.
  //
  // The composer skips this hook entirely for an envelope that already
  // carries the empty reverse path, so the loop is closed before this is
  // reached; the check stays because `bounce` and a direct caller reach
  // the same decision by another route.
  //
  // `dsnMessage` is the composed report, built by the composer from the
  // original sender, the failed recipient and the enhanced status, with
  // the header guards already run over all three. It goes out through
  // this module's own send path so a report gets the same MX lookup,
  // policy chain, spool and retry budget as any other message, and with
  // the empty reverse path so a report that itself fails cannot start a
  // second one.
  async function _reportFailure(envelope, result, dsnMessage) {
    if (_isNullSender(envelope && envelope.from)) {
      b.audit.safeEmit({
        action:   "blamepost.mail.delivery.report_suppressed",
        outcome:  "success",
        metadata: { reason: "null-return-path" },
      });
      return { delivered: [], deferred: [], failed: [] };
    }
    var failedRecipient = (result && result.recipient) || "";
    if (typeof dsnMessage !== "string" || dsnMessage.length === 0) {
      // Nothing to send. The composer records its own reason when it
      // could not build one, and `_noteUnreportedFailures` reads the
      // `dsnSent` flag it sets, so this stays silent rather than
      // counting the same miss twice.
      return { delivered: [], deferred: [], failed: [] };
    }
    if (!_mayGenerateReport(envelope.from)) {
      return _recordUnsentReport({
        origin:     "peer-refusal",
        informing:  envelope.from,
        about:      failedRecipient,
        statusCode: (result && result.reasonCode) || "5.0.0",
        bytes:      Buffer.byteLength(dsnMessage, "utf8"),
        summary:    "no delivery report sent to " + envelope.from +
                    " about " + failedRecipient,
      });
    }
    return await _sendReport({
      origin:     "peer-refusal",
      informing:  envelope.from,
      about:      failedRecipient,
      statusCode: (result && result.reasonCode) || "5.0.0",
      report:     dsnMessage,
      summary:    "no delivery report sent to " + envelope.from +
                  " about " + failedRecipient,
    });
  }

  // An id an operator handed in, refused before it becomes a path. It
  // arrives from a command line and from a form field, and both routes
  // end at a removal, so an id from anywhere but this spool has to stop
  // here rather than address a file somewhere else on the volume.
  function _assertSpoolId(id, verb) {
    if (_spoolIdIsWellFormed(id)) return id;
    throw new TypeError("delivery.queue." + verb + ": id must be one this server minted, " +
      "which is the identifier shown beside the message in `blamepost queue list`");
  }

  // A permanent refusal the composer could not build a report for.
  //
  // The report is composed before the hook that records it runs, from
  // the original sender address, the failed recipient and the enhanced
  // status, and the header guards refuse a value that could smuggle
  // report headers into it. When they refuse, the composer records its
  // own reason and comes back with the recipient failed and `dsnSent`
  // false, and the hook that would otherwise have counted the report
  // was never called. Everything downstream then behaves as though the
  // sender had been told: the sweep takes the message off disk and
  // nothing anywhere says a sender heard nothing.
  //
  // So both places that read a permanent refusal pass it through here
  // first. The counter, the audit row and the error line are the same
  // three the rest of this module uses, because an operator looking for
  // "who was not told" has to find every case in one place.
  function _noteUnreportedFailures(failedList, envelopeFrom) {
    var rows = Array.isArray(failedList) ? failedList : [];
    for (var i = 0; i < rows.length; i += 1) {
      var row = rows[i];
      if (!row || row.dsnSent === true) continue;
      if (_isNullSender(envelopeFrom)) continue;
      reportsUnsent += 1;
      b.audit.safeEmit({
        action:   "blamepost.mail.delivery.report_unbuildable",
        outcome:  "failure",
        metadata: {
          informing: _screenForDisplay(envelopeFrom),
          about:     _screenForDisplay(row.recipient || ""),
          reason:    _screenForDisplay(row.reason || ""),
        },
      });
      log.error("delivery report for " + _screenForDisplay(envelopeFrom) + " about " +
        _screenForDisplay(row.recipient || "") + " could not be composed, so nobody was " +
        "told the message failed: " + _screenForDisplay(row.reason || ""));
    }
  }

  function _descriptorPath(id) { return nodePath.join(spoolDir, id + DESCRIPTOR_SUFFIX); }
  function _bodyPath(id)       { return nodePath.join(spoolDir, id + BODY_SUFFIX); }
  function _claimPath(id)      { return nodePath.join(spoolDir, id + CLAIM_SUFFIX); }

  // One walk of the spool directory, answering both of the questions
  // that have to be answered off the same set of files.
  //
  // How full the spool is, read off the volume rather than remembered.
  // A counter carried in memory is a claim about the directory, and the
  // directory has other writers: an operator clearing an entry by hand,
  // a `blamepost queue flush` in a second process taking one away, a
  // restore putting a set back. Each of those leaves a remembered count
  // wrong in the direction that matters, which is believing there is
  // room. One listing answers exactly, and the listing is the same
  // syscall the sweep already makes on its own schedule.
  //
  // And which bodies no descriptor claims. That question belongs on
  // this walk rather than on a second one for the same reason: two
  // walks describe two moments, so a body written between them would be
  // weighed by one and reconciled by the other, and the room reported
  // and the reason for it would disagree while both looked right.
  //
  // Both files of a pair are weighed, because both are what the volume
  // gives up. The claim files are not: they are a fixed handful of
  // bytes each and they exist only while an attempt is running, so
  // counting them would make the ceiling move as the sweep works. The
  // temporary file an atomic write leaves mid-rename is weighed and is
  // not a body, because it is neither of the two names a pair is
  // written under.
  function _spoolCensus(now) {
    var at = typeof now === "number" ? now : Date.now();
    var files = b.atomicFile.listDir(spoolDir, {
      includeStat: true,
      filter:      function (name) { return name.slice(-CLAIM_SUFFIX.length) !== CLAIM_SUFFIX; },
    });
    var described = Object.create(null);
    var bodies = [];
    var messages = 0;
    var bytes = 0;
    for (var i = 0; i < files.length; i += 1) {
      var name = files[i].name;
      var size = typeof files[i].sizeBytes === "number" ? files[i].sizeBytes : 0;
      bytes += size;
      if (name.slice(-DESCRIPTOR_SUFFIX.length) === DESCRIPTOR_SUFFIX) {
        messages += 1;
        described[name.slice(0, -DESCRIPTOR_SUFFIX.length)] = true;
        continue;
      }
      if (name.slice(-BODY_SUFFIX.length) !== BODY_SUFFIX) continue;
      bodies.push({
        id:         name.slice(0, -BODY_SUFFIX.length),
        sizeBytes:  size,
        writtenAt:  typeof files[i].mtimeMs === "number" ? files[i].mtimeMs : at,
      });
    }
    var orphans = [];
    var orphanBytes = 0;
    for (var k = 0; k < bodies.length; k += 1) {
      if (described[bodies[k].id]) continue;
      // Still inside the window where the descriptor write could be in
      // flight. Reporting it here would name a message that is arriving
      // normally.
      if (at - bodies[k].writtenAt < SPOOL_SETTLE_MS) continue;
      orphans.push({
        id:        bodies[k].id,
        sizeBytes: bodies[k].sizeBytes,
        writtenAt: bodies[k].writtenAt,
        ageMs:     at - bodies[k].writtenAt,
      });
      orphanBytes += bodies[k].sizeBytes;
    }
    orphans.sort(function (left, right) { return right.ageMs - left.ageMs; });
    return {
      messages:    messages,
      bytes:       bytes,
      orphans:     orphans,
      orphanBytes: orphanBytes,
    };
  }

  function queueCapacity() {
    var census = _spoolCensus();
    return {
      messages:    census.messages,
      bytes:       census.bytes,
      maxMessages: maxSpoolMessages,
      maxBytes:    maxSpoolBytes,
      refused:     spoolRefusals,
      // The part of `bytes` that no descriptor accounts for. It is
      // published beside the total rather than subtracted from it,
      // because the volume really is holding those octets and the
      // ceiling is about the volume. What the operator needs is the
      // reason the room is gone, which nothing else could tell them:
      // every listing enumerates descriptors, so a body without one is
      // in none of them.
      orphaned: {
        bodies:   census.orphans.length,
        bytes:    census.orphanBytes,
        settleMs: SPOOL_SETTLE_MS,
      },
    };
  }

  // The message bodies on disk that no descriptor names, oldest first.
  //
  // An entry is a body written first and a descriptor written second, so
  // a process that stops between them, or a descriptor write the volume
  // refuses, leaves the body with nothing pointing at it. `_spool` takes
  // its own body back when the second write throws; this is for the half
  // no `catch` can reach, which is the process that is no longer running
  // to execute one.
  //
  // The id is what an operator does something with: `blamepost queue
  // remove <id>` already clears whichever halves of a pair are present,
  // so naming the id is the whole of what was missing.
  function queueOrphans() {
    return _spoolCensus().orphans;
  }

  // Whether the spool can take an envelope whole, and the refusal when
  // it cannot.
  //
  // Whole is the operative word. An envelope that spooled some of its
  // recipients and was refused for the rest is one its sender retries,
  // and the retry delivers a second copy to everybody whose entry was
  // already waiting. So the question is asked once, for the worst case
  // the envelope could cost, before anything is written.
  //
  // The worst case is every recipient deferring, which over-reserves on
  // an ordinary day: most recipients are accepted and never reach the
  // spool at all. Over-reserving refuses a message temporarily where it
  // need not have; under-reserving writes past the ceiling. Of the two,
  // the one that keeps the sender's copy is the one to be wrong in.
  //
  // Three shares rather than one ceiling, because the volume of each is
  // chosen by a different party. Mail from an account that authenticated
  // reaches the whole ceiling, because that is the operator's own
  // traffic. Mail arriving for forwarding stops short of it, because its
  // volume belongs to whoever writes to the alias. A report stops
  // shortest, because its volume belongs to whoever addressed the
  // message it is about, which on a run of mail to addresses that do not
  // exist here is somebody hostile.
  //
  // The ceiling is measured against the volume PLUS the room already
  // promised to messages that have not written it yet, which is what
  // `heldSpoolEntries` above carries. A ceiling measured against the
  // directory alone would answer about an instant that has passed by the
  // time the caller acts on it: two senders crossing the last slot
  // together would both read room, both proceed, and the one refused at
  // its own write would already have filed the message into mailboxes
  // here. SMTP gives the whole message one reply, so that refusal is the
  // sender being told to send everything again and everybody who already
  // received it receiving it twice.
  //
  // `hold` says whether this caller is going to write. A caller with a
  // write ahead of it TAKES the room, through `_holdSpool` below, and
  // gives back whatever it did not spend. A caller that only wants to
  // know goes through `_admitToSpool`, holds nothing, and writes nothing
  // on the strength of the answer.
  function _spoolVerdict(request, hold) {
    var entries = request.entries;
    var bytes = request.bytes;
    var stranger = request.origin === ORIGIN_INBOUND;
    var report = request.origin === ORIGIN_REPORT;
    var ceilingMessages = maxSpoolMessages;
    var ceilingBytes = maxSpoolBytes;
    if (stranger) { ceilingMessages = strangerMessages; ceilingBytes = strangerBytes; }
    if (report)   { ceilingMessages = reportMessages;   ceilingBytes = reportBytes; }
    var capacity = queueCapacity();
    var occupiedMessages = capacity.messages + heldSpoolEntries;
    var occupiedBytes    = capacity.bytes + heldSpoolBytes;

    if (occupiedMessages + entries <= ceilingMessages &&
        occupiedBytes + bytes <= ceilingBytes) {
      if (hold) {
        heldSpoolEntries += entries;
        heldSpoolBytes   += bytes;
      }
      return null;
    }

    spoolRefusals += 1;
    var why = occupiedMessages + entries > ceilingMessages
      ? "the outbound queue is holding " + occupiedMessages + " message(s) and this " +
        "message needs " + entries + " more than " + ceilingMessages + " allows"
      : "the outbound queue is holding " + occupiedBytes + " byte(s) and this message " +
        "needs " + bytes + " more than " + ceilingBytes + " allows";
    var advice = "";
    if (stranger) {
      advice = ". Mail arriving for forwarding stops short of the ceiling so accounts on " +
        "this server can still send";
    } else if (report) {
      advice = ". Delivery reports stop short of the ceiling so a run of undeliverable " +
        "mail cannot spend the room accounts on this server need to send";
    }
    // The counts published here are the volume plus what is promised,
    // which is what the refusal was decided on. A row quoting only the
    // directory would tell an operator the queue had room at the moment
    // it refused, and send them looking for a fault that is not there.
    b.audit.safeEmit({
      action:   "blamepost.mail.delivery.spool_full",
      outcome:  "denied",
      metadata: {
        origin:      _screenForDisplay(request.origin || "local"),
        recipients:  entries,
        bytes:       bytes,
        messages:    occupiedMessages,
        maxMessages: ceilingMessages,
        spoolBytes:  occupiedBytes,
        maxBytes:    ceilingBytes,
      },
    });
    var refusal = new Error("this message was not taken because " + why + advice +
      ". Read the queue with `blamepost queue held` to see what is waiting and why, clear " +
      "what is never going to leave with `blamepost queue remove <id> --reason ...`, or " +
      "raise outboundSpool in the configuration if the volume has room for more.");
    refusal.code = SPOOL_FULL_CODE;
    refusal.spool = {
      messages:    occupiedMessages,
      bytes:       occupiedBytes,
      maxMessages: ceilingMessages,
      maxBytes:    ceilingBytes,
    };
    return refusal;
  }

  // Whether the spool could take an envelope, without taking anything.
  //
  // A reading, and only a reading: it describes the volume as it stands
  // at the moment it is asked, and by the moment anybody acts on it
  // another connection or the retry sweep has had the whole intervening
  // conversation to spend what it described. Everything in this server
  // that is going to WRITE takes `_holdSpool` instead.
  function _admitToSpool(request) {
    return _spoolVerdict(request, false);
  }

  // The same question with the room taken, for a caller that is about to
  // write.
  //
  // `taken` says whether there was room; `refusal` carries the reason
  // when there was not, in the same shape `_admitToSpool` answers with,
  // so a caller turns it into its own protocol code without reading the
  // sentence. `release` gives the room back and is safe to call more than
  // once, which is what lets a caller put it in a `finally` and not
  // reason about which path out it took.
  //
  // Both numbers are checked before either is added, because the room is
  // given back by subtracting the same two: a value that is not a whole
  // count would leave the ceiling permanently wrong for every message
  // after it, with nothing anywhere saying so.
  function _holdSpool(request) {
    if (!request || typeof request !== "object") {
      throw new TypeError("delivery.queue.reserve: a request object is required, naming the " +
        "entries and bytes this message will need.");
    }
    var entries = request.entries;
    var bytes = request.bytes;
    if (typeof entries !== "number" || !isFinite(entries) || entries < 0 ||
        Math.floor(entries) !== entries ||
        typeof bytes !== "number" || !isFinite(bytes) || bytes < 0 ||
        Math.floor(bytes) !== bytes) {
      throw new TypeError("delivery.queue.reserve: entries and bytes must both be whole " +
        "counts of nought or more. The room a reservation takes is given back by subtracting " +
        "the same two numbers, so anything else leaves the ceiling wrong for every message " +
        "after this one.");
    }
    var refusal = _spoolVerdict(request, true);
    if (refusal !== null) {
      return { taken: false, refusal: refusal, release: function () {} };
    }
    var hold = {
      taken:   true,
      refusal: null,
      release: function () {
        if (hold.taken !== true) return;
        hold.taken = false;
        heldSpoolEntries -= entries;
        heldSpoolBytes   -= bytes;
      },
    };
    return hold;
  }

  // A hold a caller took before it began writing, handed over on the
  // envelope so this message spends that room rather than asking for more
  // of it. Null when the caller brought none and this call takes its own.
  //
  // Refused loudly on anything else, and on a hold that has already been
  // given back: a hold that is no longer held describes room somebody
  // else now has, so honoring it would write past the ceiling with
  // nothing reporting that it had.
  function _envelopeHold(envelope) {
    if (envelope.hold === undefined || envelope.hold === null) return null;
    var hold = envelope.hold;
    if (typeof hold !== "object" || Array.isArray(hold) ||
        typeof hold.release !== "function" || hold.taken !== true) {
      throw new TypeError("delivery.send: envelope.hold must be a reservation that " +
        "queue.reserve admitted and that has not been released yet. A caller that has not " +
        "reserved leaves it out and this call takes its own room.");
    }
    return hold;
  }

  // Take one entry for one attempt, or answer that somebody else has it.
  //
  // Draining the spool is the one mutating operation that never opens
  // the database, and that is on purpose: `blamepost queue flush` has to
  // work on a server whose volume will not open, which is when an
  // operator most needs to see what is waiting. The cost is that the
  // single-opener lock never sees it, so two processes can walk the same
  // directory at once. Two attempts on one message send it twice where
  // it is deliverable, and one process can rewrite a descriptor another
  // has already moved past.
  //
  // The claim is per entry rather than per volume, so the exemption that
  // makes flush useful survives. It is a file the kernel created
  // exclusively rather than a field somebody wrote into the descriptor,
  // and the difference is the whole point: a reader that consults a
  // recorded claim believes it, and a recorded claim is wrong precisely
  // when the process that wrote it died holding it. An exclusive create
  // cannot be wrong about who won, and a holder that is genuinely gone
  // is found by asking the kernel about the PID rather than by trusting
  // what the file says about itself. `b.appShutdown.pidLock` is both of
  // those, and it is what the volume lock is built on, so the two agree
  // about what holding something means.
  //
  // A claim recorded against another process table is left alone rather
  // than probed. Probing it would look up an unrelated process in this
  // table and reap on the answer, which is the double attempt this
  // exists to prevent, arrived at by a more confident route. Skipping
  // costs one sweep: the entry stays, and whoever actually holds it
  // finishes with it.
  function _claimEntry(id) {
    var claimPath = _claimPath(id);
    // Somebody in this process already has it (see HELD_CLAIMS).
    if (HELD_CLAIMS.has(claimPath)) return null;
    var recorded = _recordedClaim(claimPath);
    if (recorded !== null && recorded.namespace !== null &&
        recorded.namespace !== ourNamespace) {
      return null;
    }
    var lock = b.appShutdown.pidLock(claimPath);
    try {
      lock.acquire();
    } catch (e) {
      if (e && e.code === "app-shutdown/pidlock-held") return null;
      // Anything else is the volume refusing a write, which is not this
      // entry's fault and not something a claim can answer. The entry is
      // left for the next sweep rather than attempted unclaimed.
      return null;
    }
    HELD_CLAIMS.add(claimPath);
    // Which table the PID above belongs to, recorded beside it so the
    // next process can tell whether probing it means anything. A claim
    // that cannot be written in full is not one this layer can honor,
    // so it is given back rather than left half written and believed.
    try {
      nodeFs.writeFileSync(claimPath, String(process.pid) + "\n" + ourNamespace + "\n");
    } catch (_e) {
      HELD_CLAIMS.delete(claimPath);
      // allow:swallow-unverified this is the cleanup on the path where the
      // claim could not be written, so reaching it needs two filesystem
      // faults in one call; the null returned below is the verdict either
      // way and a release that refuses must not replace it.
      try { lock.release(); } catch (_e2) { /* drop-silent: the return below is the verdict */ }
      return null;
    }
    var released = false;
    return {
      release: function () {
        if (released) return;
        released = true;
        HELD_CLAIMS.delete(claimPath);
        try { lock.release(); }
        catch (_e) { /* drop-silent by design: a claim already reaped is ordinary */ }
      },
    };
  }

  // What a claim file says, or null when there is nothing readable
  // there. A missing, truncated or unparseable claim reads as nothing
  // recorded, and the liveness probe inside the lock answers what
  // happens next.
  function _recordedClaim(claimPath) {
    var raw;
    try {
      raw = b.atomicFile.fdSafeReadSync(claimPath, {
        maxBytes:      b.constants.BYTES.kib(1),
        refuseSymlink: true,
        encoding:      "utf8",
      });
    } catch (_e) { return null; }
    var lines = String(raw).split("\n");
    var namespace = String(lines[1] || "").trim();
    return { namespace: namespace.length > 0 ? namespace : null };
  }

  // One line in an entry's own record of what has been tried on it.
  //
  // `mxHost` is the receiver that answered, and it is null rather than
  // a guess whenever the framework does not name one: the composer
  // reports the host it reached for a delivery and for a refusal, and
  // withholds it for a deferral. `reasonCode` is the enhanced status,
  // which is where the standards say which step refused, and the
  // registry RFC 5248 maintains is what gives each one its meaning.
  // `requireTls` is the RFC 8689 posture that was in force for this
  // attempt rather than the one in force now, because the two differ
  // across a configuration change and the operator is asking about the
  // attempt.
  //
  // Both texts are the far side's words and are kept as they arrived.
  // Screening happens where the row is read, not where it is written.
  function _historyRow(row) {
    return {
      at:         typeof row.at === "number" ? row.at : Date.now(),
      outcome:    row.outcome,
      attempt:    typeof row.attempt === "number" ? row.attempt : 0,
      mxHost:     typeof row.mxHost === "string" && row.mxHost.length ? row.mxHost : null,
      reason:     _storedText(row.reason),
      reasonCode: _storedText(row.reasonCode || ""),
      requireTls: row.requireTls === true,
      held:       row.held === true,
    };
  }

  // The record is bounded, and the newest attempts are the ones kept.
  // What an operator loses to the bound is the middle of a long stall,
  // and `queuedAt` on the entry still says when it began.
  function _appendHistory(prior, row) {
    var rows = Array.isArray(prior) ? prior.slice() : [];
    rows.push(_historyRow(row));
    if (rows.length > MAX_HISTORY_ROWS) rows = rows.slice(rows.length - MAX_HISTORY_ROWS);
    return rows;
  }

  // The descriptor alone. Rewriting it is how a retry moves its own
  // schedule forward without touching the body, which matters because
  // the body is the message: it is written once and read on every
  // attempt, and an attempt that only changes when to try again has no
  // business rewriting it.
  function _writeDescriptor(entry) {
    var history = Array.isArray(entry.history) ? entry.history : [];
    return b.atomicFile.writeJson(_descriptorPath(entry.id), {
      id:               entry.id,
      from:             entry.from,
      recipient:        entry.recipient,
      attempt:          entry.attempt,
      nextAttemptAt:    entry.nextAttemptAt,
      reason:           _storedText(entry.reason || ""),
      reasonCode:       _storedText(entry.reasonCode || ""),
      requireTls:       entry.requireTls === true,
      // Whether this entry is waiting on something other than a
      // receiver's verdict, and the sentence that says what would change
      // that.
      //
      // No delivery path here sets it. Every recipient that reaches the
      // spool has an answer from an attempt behind it, spends its place
      // in the retry budget, and ends as a permanent failure with a
      // report to its sender. The field is carried and reported because
      // a descriptor on the volume can hold the flag, and the readers
      // below have to report such an entry honestly until it drains; a
      // rewrite clears the flag, so the next attempt releases the entry
      // back into the ordinary budget.
      held:             entry.held === true,
      heldBecause:      entry.held === true ? _text(entry.heldBecause || "") : "",
      queuedAt:         entry.queuedAt || Date.now(),
      // How many times this message has been tried, which the attempt
      // counter cannot answer on its own: `attempt` is the entry's place
      // in the retry budget, and a descriptor can carry it frozen at
      // where it started while sweeps go on trying the message, so this
      // counter counts the attempts themselves.
      attemptsRecorded: typeof entry.attemptsRecorded === "number" ? entry.attemptsRecorded : history.length,
      history:          history,
    }, { fileMode: 0o600, indent: 2 });
  }

  // Persist one recipient that answered transiently. One file pair per
  // recipient rather than per envelope: recipients on different domains
  // fail and recover independently, and a shared descriptor would retry
  // the whole set every time any one of them came back.
  //
  // The body goes down once, here, and a later attempt rewrites the
  // descriptor alone. Both writes land through the atomic rename, so a
  // reader during a rewrite sees the old file or the new one.
  //
  // The body is written first and that order is deliberate. Written the
  // other way round, a descriptor that lands without its body is an
  // entry the sweep recognizes and clears, so the message is destroyed
  // by the very write that was supposed to preserve it. Body first makes
  // the half-written state a message nobody has to send yet.
  //
  // Which leaves the write that landed first owing a cleanup. Every
  // listing this module offers enumerates descriptors, so a body without
  // one is in no listing, has no id an operator can read and is reached
  // by no verb, while the ceiling, which is measured off the volume,
  // spends its bytes. Enough of them and mail is refused for a queue
  // that reads as empty. So a descriptor write that throws takes the
  // body back with it and the failure still reaches the caller: the
  // recipient is not spooled, which is the truthful outcome, and the
  // sender keeps their copy.
  //
  // A process that dies between the two writes executes no `catch`, and
  // that half is covered by `queueOrphans` and the reconciliation
  // `blamepost doctor` runs over this directory.
  async function _spool(entry, rfc822) {
    var id = entry.id || b.crypto.generateToken(12);
    await b.atomicFile.write(_bodyPath(id), rfc822, { fileMode: 0o600 });
    try {
      await _writeDescriptor({
        id:               id,
        from:             entry.from,
        recipient:        entry.recipient,
        attempt:          entry.attempt,
        nextAttemptAt:    entry.nextAttemptAt,
        reason:           entry.reason,
        reasonCode:       entry.reasonCode,
        requireTls:       entry.requireTls,
        held:             entry.held,
        heldBecause:      entry.heldBecause,
        queuedAt:         entry.queuedAt,
        attemptsRecorded: entry.attemptsRecorded,
        history:          entry.history,
      });
    } catch (e) {
      // Best effort, and it has to be: the volume that would not take
      // the descriptor may not take the removal either. A removal that
      // fails leaves exactly the state the reconciliation was built to
      // find, and the throw below is what tells the caller the recipient
      // was not spooled either way.
      try {
        await nodeFs.promises.rm(_bodyPath(id), { force: true });
      } catch (_rmErr) {
        log.error("outbound spool entry " + id + " could not be written and its message " +
          "body could not be taken back off " + spoolDir + ": " +
          _screenForDisplay((_rmErr && _rmErr.message) || String(_rmErr)) +
          ". It is spending queue capacity that no listing shows; " +
          "`blamepost doctor` reports it and `blamepost queue remove " + id +
          " --reason ...` clears it.");
      }
      throw e;
    }
    return id;
  }

  // One field of a descriptor, read back as the type `_writeDescriptor`
  // wrote it as. Anything else is a field this build did not write, and
  // it reads as absent rather than as whatever it happens to be: a value
  // of the wrong type is carried by every reader below into arithmetic,
  // into a comparison, or onto a terminal, and each of those answers
  // something different about it.
  //
  // `null` rather than an empty value of the right type, in every case.
  // Every consumer here already has an answer for a field the descriptor
  // does not carry, and they do not all pick the same one: the held
  // listing skips an entry with no queued moment, where reporting it as
  // queued at the start of 1970 would name it as the oldest thing in the
  // spool; and a recipient this server cannot read reaches the composer
  // as nothing at all, where an empty address would be answered as a
  // recipient whose syntax is wrong and take the message off the volume
  // on the first sweep. A descriptor nobody can read is a message to
  // keep and a record for an operator to repair, not a message to
  // destroy.
  function _readText(value)   { return typeof value === "string" ? value : null; }
  function _readNumber(value) { return typeof value === "number" && isFinite(value) ? value : null; }
  function _readCount(value)  { return Number.isInteger(value) && value >= 0 ? value : null; }
  function _readFlag(value)   { return value === true; }

  // One line of an entry's own record, read back.
  function _readHistoryRow(row) {
    return {
      at:         _readNumber(row.at),
      outcome:    _readText(row.outcome),
      attempt:    _readCount(row.attempt),
      mxHost:     typeof row.mxHost === "string" && row.mxHost.length ? row.mxHost : null,
      reason:     _readText(row.reason),
      reasonCode: _readText(row.reasonCode),
      requireTls: _readFlag(row.requireTls),
      held:       _readFlag(row.held),
    };
  }

  // The attempt record, read back and bounded the way it is bounded when
  // it is appended to. A record longer than the bound was not written
  // here, and a listing that printed all of it would be a file on the
  // volume deciding how many lines an operator reads.
  function _readHistory(value) {
    var rows = Array.isArray(value) ? value : [];
    var out = [];
    for (var i = 0; i < rows.length; i += 1) {
      if (rows[i] === null || typeof rows[i] !== "object" || Array.isArray(rows[i])) continue;
      out.push(_readHistoryRow(rows[i]));
    }
    if (out.length > MAX_HISTORY_ROWS) out = out.slice(out.length - MAX_HISTORY_ROWS);
    return out;
  }

  /**
   * One descriptor, read off the volume and held to the shape
   * `_writeDescriptor` writes.
   *
   * The spool is a directory on the data volume, so what comes back here
   * is whatever the volume holds: an entry this build wrote, an entry an
   * older one wrote, an entry a restore put back, a file somebody with
   * the volume wrote by hand. `_storedText` says as much where the
   * writing happens, and says that every read path is what is safe. This
   * is that read path, and three things are settled here rather than at
   * each of the six readers downstream.
   *
   * The ID IS THE FILE'S, always. It becomes `<id>.json`, `<id>.eml` and
   * `<id>.claim`, the sweep unlinks the first two when it gives up on an
   * entry, and it is the identifier an operator retypes into
   * `queue remove`. An id taken from the file's own content is a path
   * nobody chose and a row that names another message, and
   * `_assertSpoolId` cannot help: it guards the id a CALLER hands in,
   * which is a different value from this one.
   *
   * A descriptor is an OBJECT. Valid JSON that is not one reaches every
   * reader as a row with no fields, or as null, and a listing built over
   * either stops on the first one. It is refused the same way a file a
   * crash left half written is refused, which is the state the readers
   * already report as an entry needing a person.
   *
   * Every FIELD is the type it was written as, and nothing else comes
   * back. A descriptor carrying a field this build does not write is a
   * descriptor from somewhere else, and carrying it forward hands an
   * operator's terminal a key and a value that never went through the
   * display screen.
   */
  async function _readDescriptor(id) {
    var raw = await b.atomicFile.readJson(_descriptorPath(id), {
      maxBytes: MAX_SPOOL_DESCRIPTOR_BYTES,
    });
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      var err = new Error("outbound spool entry " + id + " holds a descriptor that is not an " +
        "object, so there is no entry to read out of it");
      err.code = "delivery/spool-descriptor-shape";
      throw err;
    }
    return {
      id:               id,
      from:             _readText(raw.from),
      recipient:        _readText(raw.recipient),
      attempt:          _readCount(raw.attempt),
      nextAttemptAt:    _readNumber(raw.nextAttemptAt),
      reason:           _readText(raw.reason),
      reasonCode:       _readText(raw.reasonCode),
      requireTls:       _readFlag(raw.requireTls),
      held:             _readFlag(raw.held),
      heldBecause:      _readText(raw.heldBecause),
      queuedAt:         _readNumber(raw.queuedAt),
      attemptsRecorded: _readCount(raw.attemptsRecorded),
      history:          _readHistory(raw.history),
    };
  }

  // What one file answered when it was asked to go: `removed` when it
  // was there and is not, `absent` when there was nothing under that
  // name, `refused` when the volume kept it.
  //
  // The flag that ignores a path which is not there is deliberately not
  // used. It is the only thing standing between the first two answers,
  // and they are different things to tell an operator: one is a
  // cancellation and the other is a message that had already gone,
  // which is past cancelling and has to be treated as sent. Letting the
  // absence arrive as the removal's own refusal makes it a reading of
  // the volume rather than a silence.
  async function _unlinkSpoolPart(target) {
    try {
      await nodeFs.promises.rm(target);
      return { state: "removed", error: null };
    } catch (err) {
      if (err && err.code === "ENOENT") return { state: "absent", error: null };
      return { state: "refused", error: (err && err.message) || String(err) };
    }
  }

  // The message bytes, read off the volume before the pair is taken
  // apart, so a removal that gets one part and not the other can put
  // back the part it took.
  //
  // The read is the same one the sweep makes on every attempt, under the
  // same bound, so nothing here can hold more of the volume than an
  // ordinary retry already does. A body that will not READ is a body
  // this call cannot promise to restore, so it refuses in front of the
  // first unlink rather than destroying something it has no copy of:
  // nothing is taken, the entry is whole, and the operator reruns
  // against the same message.
  //
  // `null` is an entry with no message beside it, which is ordinary. A
  // descriptor whose body has already gone is what an interrupted
  // removal leaves, and there is nothing to hold or to put back.
  async function _holdSpoolBody(id) {
    var target = _bodyPath(id);
    if (!b.atomicFile.exists(target)) return { held: null, error: null };
    try {
      var bytes = await b.atomicFile.read(target, { maxBytes: MAX_SPOOLED_BODY_BYTES });
      return { held: Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes, "utf8"), error: null };
    } catch (err) {
      if (err && err.code === "ENOENT") return { held: null, error: null };
      return { held: null, error: (err && err.message) || String(err) };
    }
  }

  // The message put back where it was, for a removal that took it and
  // then could not take the rest. Answers null when the volume took it
  // back, and what the volume said when it would not.
  async function _restoreSpoolBody(id, bytes) {
    try {
      await b.atomicFile.write(_bodyPath(id), bytes, { fileMode: 0o600 });
      return null;
    } catch (err) {
      return (err && err.message) || String(err);
    }
  }

  // Take one entry off the volume and say what actually happened to it.
  //
  // Taking a pair apart is two unlinks with a suspension between them,
  // so the half-taken state is one another attempt can pick up and
  // finish: the sweep reads an entry whose message has already gone,
  // gives up on it as one with nothing left to send, and takes the
  // descriptor, while this call is still holding a copy of the message
  // to put back if its own unlink refuses. What that produces is a body
  // beside no descriptor, in no listing, reached by no verb, spending
  // the ceiling, under a verdict saying nothing was destroyed and the
  // server will attempt the message again, which is false on every
  // count. So putting the message back is the step that requires holding
  // the entry, and the paragraph on `restoreOnRefusal` below says how
  // that is enforced.
  //
  // The message goes first, the descriptor second, and the order is the
  // whole point. A removal is two operations, and a sweep can run
  // between them. With the descriptor removed first, the half-removed
  // state is a message with nothing describing it: a sweep that had
  // already listed the entry reads the message, attempts it, and writes
  // the descriptor back, so a cancellation an operator just made is
  // undone and the message reappears in the queue. Removing the message
  // first makes the half-removed state a descriptor with nothing to
  // send, which the sweep recognizes and clears. Both orders leave the
  // spool consistent on the next pass; only one of them stays cancelled.
  //
  // That order is right about a CRASH, which is where nothing gets to
  // choose what happens next. It is not enough on its own against a
  // fault, because a fault leaves this call still running with a verdict
  // to hand back, and that verdict has to be true of what is left on
  // disk: a body the volume will not give up stops the removal where it
  // stands, while a descriptor the volume will not give up arrives one
  // step too late for that protection and would report `refused` over a
  // message already destroyed. So the message
  // is held in memory in front of the first unlink and written back if
  // the descriptor refuses. The pair is then whole again, the sweep
  // still has something to send, and the remediation the refusal names
  // is a real one.
  //
  // The answer distinguishes four outcomes because callers act on all
  // four, and the difference between the last two is the one an operator
  // is most easily misled about.
  //
  //   `removed`: something left. The cancellation happened.
  //   `not-spooled`: there was nothing under that name, so nothing was
  //     cancelled and whoever asked has to be told the message is past
  //     cancelling rather than stopped.
  //   `refused`: the volume kept a part and NOTHING was destroyed. The
  //     message is still on disk, the sweep will go on retrying it, and
  //     a rerun once the volume lets go reaches the same message.
  //   `incomplete`: part of the entry was destroyed and part of it
  //     stayed. This is not a cancellation to try again: what went is
  //     gone, the message can never be sent, and a rerun reaches only
  //     the remainder. Telling an operator to clear the fault and run
  //     the verb again is true of `refused` and false here, which is why
  //     the two carry different words rather than one.
  //
  // `left` names the parts that stayed and `destroyed` the parts that
  // went, because between them they are what is on the volume afterwards
  // and what an operator has to answer for.
  //
  // `restoreOnRefusal` is what tells a cancellation from a removal that
  // FOLLOWS an attempt, and the two need opposite answers to the same
  // fault. Putting the message back is right when nothing was cancelled,
  // because the message is still owed to its recipient and the sweep has
  // to be able to send it. It is exactly wrong once a peer has taken the
  // message: the entry is being cleared BECAUSE the message was
  // delivered, and a body put back is a message the next sweep sends a
  // second time. So the post-attempt callers pass false and leave the
  // body gone, which is what the sweep already reads as an entry with
  // nothing left to send. `notRestoredBecause` is the caller's own words
  // for that, because the two callers withhold the restore for opposite
  // reasons and the operator reads the sentence.
  //
  // Putting the message back requires HOLDING the entry, and the check
  // below is what enforces it. The restore is the one step here that
  // writes rather than reads, and it is the step a second writer turns
  // into the damage described above. A re-read before the write narrows
  // that window rather than closing it, because the sweep can finish
  // between the read and the write. Holding the entry closes it, and the
  // check is here rather than in each verb so a caller that restores
  // without a claim cannot arrive quietly.
  async function _dropSpooled(id, dropOpts) {
    var restoreOnRefusal = !(dropOpts && dropOpts.restoreOnRefusal === false);
    if (restoreOnRefusal && !HELD_CLAIMS.has(_claimPath(id))) {
      throw new TypeError("delivery: a message is put back only by a caller holding the " +
        "entry's claim. Take it with the same _claimEntry the sweep takes and hold it across " +
        "the whole removal, or clear the entry with restoreOnRefusal false and say why. An " +
        "unclaimed restore races the attempt running on the same entry, and the two of them " +
        "between them leave a message body that no descriptor names");
    }
    // Read only where it can be put back. A caller clearing an entry
    // after an attempt never restores the message, so holding a copy of
    // it would be a second full read of every message this server
    // delivers, on the path taken by every delivery, for a copy that is
    // discarded a line later.
    var holding = restoreOnRefusal ? await _holdSpoolBody(id) : { held: null, error: null };
    if (holding.error !== null) {
      return {
        id:        id,
        removed:   false,
        outcome:   "refused",
        left:      ["body"],
        destroyed: [],
        reason:    "the spooled message could not be read, so nothing was taken off the " +
          "data volume: " + holding.error,
      };
    }

    var destroyed = [];

    var body = await _unlinkSpoolPart(_bodyPath(id));
    if (body.state === "refused") {
      return {
        id: id, removed: false, outcome: "refused", left: ["body"], destroyed: [],
        reason: body.error,
      };
    }
    if (body.state === "removed") destroyed.push("body");

    var descriptor = await _unlinkSpoolPart(_descriptorPath(id));
    if (descriptor.state === "refused") {
      // The message goes back beside the descriptor that kept it, so
      // what the operator is told (nothing was cancelled, the server
      // will attempt this again) is true of the volume rather than only
      // of this call. A caller clearing an entry AFTER an attempt asks
      // for the opposite and gets it: the body stays gone, so the sweep
      // reads an entry with nothing to send rather than sending a
      // message its recipient already has.
      var putBack = null;
      if (restoreOnRefusal && destroyed.indexOf("body") !== -1) {
        putBack = await _restoreSpoolBody(id, holding.held);
        // Back where it was, so this call destroyed nothing after all.
        if (putBack === null) destroyed = [];
      }
      // Which of the two answers this is turns on what is GONE, not on
      // which file refused. An entry whose message had already left
      // before this ran destroys nothing here either, and telling its
      // operator the message was destroyed in part would name an act
      // this call did not perform.
      if (destroyed.length === 0) {
        return {
          id: id, removed: false, outcome: "refused", left: ["descriptor"], destroyed: [],
          reason: descriptor.error,
        };
      }
      // The message is destroyed and the entry is still listed, so this
      // is the one state where the sweep and the operator both have to
      // be told something other than "try again".
      return {
        id: id, removed: false, outcome: "incomplete", left: ["descriptor"],
        destroyed: destroyed.slice(),
        reason: descriptor.error + (restoreOnRefusal
          ? " (and the message could not be put back beside it: " + putBack + ")"
          : " (" + _text((dropOpts && dropOpts.notRestoredBecause) ||
            "the message is not put back") + ")"),
      };
    }
    if (descriptor.state === "removed") destroyed.push("descriptor");

    // The claim goes with the pair rather than being left behind. A
    // claim file whose entry no longer exists is never looked at again,
    // so nothing would ever clear it, and the attempt that is holding it
    // right now finds the file already gone at release, which its own
    // reader treats as ordinary.
    //
    // It is NOT part of the message, and the verdict is read that way in
    // both directions. A claim the volume keeps after the pair has gone
    // is not a cancellation that failed: the message left, and a file
    // nothing reads stayed, so it is named in `left` on an outcome that
    // still says the message went. And a claim removed with no pair
    // beside it is not a cancellation at all: a stale claim outlived its
    // entry, this call tidied it, and counting that as a removal filed a
    // row and wrote to a sender about a message that had already left.
    // So `removed` is read off the two files that ARE the message and
    // never off this one.
    var claim = await _unlinkSpoolPart(_claimPath(id));
    var left = claim.state === "refused" ? ["claim"] : [];

    return {
      id:        id,
      removed:   destroyed.length > 0,
      outcome:   destroyed.length > 0 ? "removed" : "not-spooled",
      left:      left,
      destroyed: destroyed,
      reason:    claim.state === "refused" ? claim.error : null,
    };
  }

  // The same removal for a caller with a recovery path rather than a
  // verdict to hand back.
  //
  // The sweep and the abandonment already treat a volume that refuses a
  // write as a fault to recover from: the pair stays where it is, the
  // schedule moves, and the next pass tries again. A verdict returned
  // into those paths would have to be re-raised at each of them to reach
  // the same handler, so the raise happens once here and the message
  // names what is still on the volume.
  async function _dropSpooledOrRaise(id) {
    // Every caller of this one is clearing an entry AFTER an attempt has
    // settled it: a peer took the message, a peer refused it
    // permanently and its sender has been written to, or the budget ran
    // out. In all three the message must not go on the wire again, so a
    // descriptor the volume keeps leaves the body gone rather than put
    // back. The sweep reads that as an entry with nothing to send and
    // gives up on it, which is the outcome; a body put back here would
    // be a second copy delivered to a recipient who already has one.
    var account = await _dropSpooled(id, {
      restoreOnRefusal:   false,
      notRestoredBecause: "the message is not put back, because this removal follows a " +
        "delivery attempt that settled it",
    });
    if (account.outcome === "refused" || account.outcome === "incomplete") {
      throw new Error("outbound spool entry " + id + " could not be taken off " + spoolDir +
        ": the volume kept its " + account.left.join(" and ") +
        (account.destroyed.length > 0
          ? ", after this server had already destroyed its " + account.destroyed.join(" and ")
          : "") +
        " (" + _screenForDisplay(account.reason) + ")");
    }
    return account;
  }

  /**
   * @primitive blamepost.mail.delivery.send
   * @signature delivery.send(envelope)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 5321 §3.3, RFC 8689 (REQUIRETLS)
   * @related   blamepost.mail.delivery.create
   *
   * Hand one envelope to the policy chain. Returns the framework
   * composer's per recipient outcome, so a caller sees exactly which
   * recipients the peers accepted and which they refused. Recipients
   * the peer answered with a transient code are written to the spool
   * before the promise resolves, so a restart between the answer and
   * the retry loses nothing.
   *
   * The rows come back screened for display, the way every row this
   * module hands out does: a `reason` is whatever settled the recipient
   * and a `mxHost` is a name out of somebody else's zone, and both are
   * printed in a console table and rendered on the administration page.
   * The spool keeps what arrived, so the record of what a peer actually
   * said is intact and the screen runs on every read.
   *
   * `rfc822` is the finished message and an envelope carrying none is
   * refused here. Taken instead it reaches a receiver as a message of no
   * bytes, and a recipient that defers leaves an empty file on the volume
   * that spends the whole retry budget.
   *
   * An envelope whose reverse path is empty is a report, either one this
   * server generated or one an alias is forwarding off this server. It
   * goes over this same path, and the reverse path survives the hop as
   * the empty one RFC 5321 §6.1 requires, so a report that itself fails
   * cannot start a second one. Both wire spellings of that address are
   * read as the same value, because a descriptor can carry the literal
   * `<>` and the composer takes the empty string.
   *
   * Under an enforcing MTA-STS posture each recipient domain is asked
   * about over the operator's pinned resolver before the message is
   * handed over, and a domain whose record could not be looked up is
   * deferred rather than delivered to. A domain that publishes no
   * policy is not affected, which is the distinction that keeps mail
   * moving to most of the internet.
   *
   * Room in the outbound queue is taken before the message is composed
   * and given back when it has been written, so a full queue refuses at
   * the one moment refusing is free rather than after a copy has reached
   * a mailbox. A caller that has already written something for this
   * message, or that is delivering one message in several envelopes,
   * takes the room itself with `queue.reserve` and hands the reservation
   * over as `hold`; one message then takes the room once, and whoever
   * took it releases it.
   *
   * `requireTls` is this message's own RFC 8689 posture and wins over the
   * one the handle was built with, so it is the reading that reaches the
   * transport. `attempt` is how many attempts have already been made on
   * the message and is what the retry budget is spent against. Both are
   * refused here unless they carry the type they are documented as: a
   * posture that is not a boolean would read as off and deliver without
   * the keyword, and a count that is not a whole number would either end
   * the message on its first try or leave it with no wait between
   * attempts. Leave either out and the handle's own answer stands.
   *
   * @example
   *   var outcome = await delivery.send({
   *     from:   "alice@example.com",
   *     to:     ["bob@example.net"],
   *     rfc822: messageBytes,
   *   });
   */
  async function send(envelope) {
    if (!envelope || typeof envelope !== "object") {
      throw new TypeError("delivery.send: envelope object is required");
    }
    if (envelope.origin !== undefined && ORIGINS.indexOf(envelope.origin) === -1) {
      throw new TypeError("delivery.send: envelope.origin must be one of " +
        ORIGINS.join(", ") + " when it is given at all. It decides which share of the " +
        "outbound queue this message may take, and a value nobody recognizes would " +
        "silently take the largest.");
    }
    // The two settings an envelope carries that decide whether this
    // message is delivered, deferred or bounced. Both are read below as
    // the exact type they are documented as, so a value of any other
    // shape becomes one particular answer rather than a refusal, and
    // both of those answers are the wrong one.
    if (envelope.requireTls !== undefined && typeof envelope.requireTls !== "boolean") {
      throw new TypeError("delivery.send: envelope.requireTls must be a boolean when it is " +
        "given at all. It is the RFC 8689 posture this message asks its receiver for, and " +
        "an envelope's own posture wins over the one the handle was built with. Any other " +
        "value reads as the posture being off, so a server an operator configured to ask " +
        "would deliver without the keyword and nothing would say so. Leave it out to keep " +
        "the handle's posture.");
    }
    if (envelope.attempt !== undefined &&
        (typeof envelope.attempt !== "number" || !isFinite(envelope.attempt) ||
         envelope.attempt < 0 || Math.floor(envelope.attempt) !== envelope.attempt)) {
      throw new TypeError("delivery.send: envelope.attempt must be a whole count of nought " +
        "or more when it is given at all. It is how many attempts have already been made on " +
        "this message. The retry budget is spent against it and the wait before the next " +
        "attempt is indexed by it. A value that is not a count either gives the message up " +
        "on its first try and tells its sender it failed, or produces a next attempt time " +
        "that is not a time and retries it on every sweep with no wait at all. Leave it out " +
        "for a message nobody has tried yet.");
    }
    var wire = Buffer.isBuffer(envelope.rfc822)
      ? envelope.rfc822
      : Buffer.from(String(envelope.rfc822 || ""), "utf8");
    // An envelope with no message is a caller fault, and it is refused
    // here because everywhere further on treats nought bytes as a
    // message. The composer offers a receiver a DATA with nothing in it,
    // which is neither headers nor body, and a recipient that defers
    // leaves a nought-byte file on the volume that spends the whole
    // retry budget before its sender is told a message that never
    // existed could not be delivered.
    if (wire.length === 0) {
      throw new TypeError("delivery.send: envelope.rfc822 is required and must carry the " +
        "message. An envelope with no message would be offered to a receiver as a message of " +
        "no bytes, and a recipient that defers would spend the whole retry budget on it.");
    }

    // Taken before anything is composed, spooled or handed over, because
    // it is the only point at which refusing costs nothing. Every path
    // below this line either writes to the spool or has already
    // committed the message somewhere.
    //
    // TAKEN, not measured. What stands between here and the spool write
    // at the bottom of this function is an MX lookup, a policy chain and
    // a whole conversation with a receiver that answers at its own pace,
    // and the spool is one directory shared with every other connection
    // and with the retry sweep. A reading of how full it is would be
    // spent by somebody else long before it was acted on, and the message
    // refused at the far end of that window is one whose caller may have
    // already filed copies into mailboxes here.
    //
    // A caller that reserved before it started writing hands its own hold
    // over instead, so a message delivered in several envelopes takes the
    // room once. Whoever took the room gives it back: this call releases
    // only what it took itself, on every path out.
    //
    // The count is every recipient on the envelope rather than the ones
    // that turn out to defer, because which ones those are is not known
    // until the composer has answered and by then the room is either
    // there or it is not.
    var wantedEntries = Array.isArray(envelope.to)
      ? envelope.to.length
      : (envelope.to ? 1 : 0);
    var ourHold = null;
    if (_envelopeHold(envelope) === null && wantedEntries > 0) {
      ourHold = _holdSpool({
        entries: wantedEntries,
        bytes:   wantedEntries * wire.length,
        origin:  envelope.origin,
      });
      if (ourHold.taken !== true) {
        log.error("a message for " + wantedEntries + " recipient(s) was refused: " +
          _screenForDisplay(ourHold.refusal.message));
        throw ourHold.refusal;
      }
    }
    try {
      return await _sendHeld(envelope, wire);
    } finally {
      if (ourHold !== null) ourHold.release();
    }
  }

  // The delivery itself, with the room for it already held.
  //
  // Split from `send` so the reservation and its release sit in one
  // short frame either side of everything that can throw. A message that
  // takes room and unwinds without giving it back leaves the ceiling
  // permanently lower with nothing on screen accounting for the
  // difference, which is the same failure as a spool entry nothing names.
  async function _sendHeld(envelope, wire) {
    // A message traveling with the RFC 5321 §4.5.5 empty reverse path
    // goes over the same path as everything else. That covers both
    // shapes it arrives in: a report this server generated, and a report
    // that arrived here and is being passed on by an alias.
    //
    // The wire spelling is normalized to the empty string the composer's
    // envelope reader takes. A descriptor can carry the literal `<>`,
    // and handing that over reaches the address guard, which reads it as
    // a malformed address and refuses the message. One spelling in, one
    // spelling out.
    var reversePath = _isNullSender(envelope.from) ? REPORT_REVERSE_PATH : envelope.from;
    // An envelope may carry its own REQUIRETLS posture, and it wins over
    // the handle's. This is the one place the two meet, which makes it
    // the place to say what the value does: the transport appends the
    // keyword to MAIL FROM for a peer whose post-STARTTLS EHLO advertises
    // it, and refuses a peer that does not, so the recipient fails over
    // to the next MX host and is permanently failed once every host for
    // the domain has been asked. RFC 8689 section 4.1 makes that the
    // required behavior: delivering without the parameter to a peer that
    // cannot honor it is indistinguishable, to the sender, from the
    // request having been made.
    var envelopeTls = envelope.requireTls === undefined ? requireTls : envelope.requireTls === true;
    var priorAttempt = envelope.attempt || 0;

    // The MTA-STS question, asked once per recipient domain rather than
    // once per recipient, and asked before the message is handed over.
    // A domain the pinned resolver could not answer about is held back
    // and the rest of the envelope goes on: one receiver's DNS trouble
    // must not stop mail to the others.
    //
    // A recipient list that is not a list is handed over untouched. The
    // composer refuses that shape in its own words, and wrapping it here
    // to make the loop convenient would accept an envelope this server
    // refuses.
    var recipients = Array.isArray(envelope.to) ? envelope.to.slice() : null;
    var deliverable = recipients;
    var withheld = [];
    if (recipients !== null) {
      deliverable = [];
      var verdicts = Object.create(null);
      for (var r = 0; r < recipients.length; r += 1) {
        var domain = _domainOf(recipients[r]);
        if (!(domain in verdicts)) verdicts[domain] = await _mtaStsUnanswered(domain);
        if (verdicts[domain] === null) { deliverable.push(recipients[r]); continue; }
        withheld.push({
          recipient:    recipients[r],
          reason:       verdicts[domain].reason,
          reasonCode:   verdicts[domain].reasonCode,
          attempt:      priorAttempt + 1,
          retryAfterMs: backoffMs[Math.min(priorAttempt, backoffMs.length - 1)],
        });
      }
    }

    var outcome = (recipients === null || deliverable.length > 0)
      ? await deliver({
        from:       reversePath,
        to:         recipients === null ? envelope.to : deliverable,
        rfc822:     wire,
        requireTls: envelopeTls,
        attempt:    priorAttempt,
      })
      : { delivered: [], deferred: [], failed: [] };
    var waiting = _settleVerdicts(outcome);
    // Added after the verdicts are settled, which is about what the
    // composer came back with. These never reached the composer: this
    // server withheld them itself over an MTA-STS record it could not
    // settle, which is its own verdict and carries its own status, so
    // they spend the budget the ordinary way.
    for (var w = 0; w < withheld.length; w += 1) {
      outcome.deferred.push(withheld[w]);
      // The relabel hands back the composer's own deferral list, so the
      // two are usually one array. Guarded rather than assumed, because
      // adding the row twice would spool the same message twice.
      if (waiting !== outcome.deferred) waiting.push(withheld[w]);
    }
    _noteUnreportedFailures(outcome.failed, reversePath);
    // Once the lists are settled and before anything is spooled, so an
    // attempt is observed whether or not the spool write that follows
    // it succeeds.
    await _observeOutcome(outcome);
    var now = Date.now();
    for (var i = 0; i < waiting.length; i += 1) {
      var row = {
        at:         now,
        outcome:    "deferred",
        attempt:    waiting[i].attempt,
        mxHost:     waiting[i].mxHost,
        reason:     waiting[i].reason,
        reasonCode: waiting[i].reasonCode,
        requireTls: envelopeTls,
        held:       waiting[i].held === true,
      };
      await _spool({
        from:             reversePath,
        recipient:        waiting[i].recipient,
        attempt:          waiting[i].attempt,
        nextAttemptAt:    now + waiting[i].retryAfterMs,
        reason:           waiting[i].reason,
        reasonCode:       waiting[i].reasonCode,
        requireTls:       envelopeTls,
        attemptsRecorded: 1,
        history:          _appendHistory([], row),
      }, wire);
    }
    return _screenedOutcome(outcome);
  }

  /**
   * @primitive blamepost.mail.delivery.bounce
   * @signature delivery.bounce(opts)
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 3464 (DSN), RFC 3462 (multipart/report), RFC 5321 §6.1
   * @related   blamepost.mail.delivery.send
   *
   * Report a refusal this server decided locally, rather than one a
   * peer handed back. The inbound path uses it when a recipient
   * address does not resolve to a mailbox here, which is the case the
   * MX listener cannot answer at RCPT time. The report body is built
   * by the framework composer, so a locally generated report has the
   * same shape as one generated after a peer refusal.
   *
   * A report is never generated for the null return path. RFC 5321
   * §6.1: the sender of a report is nobody, so there is nobody to tell
   * that the report failed, and the silence there is correct.
   *
   * The report goes out with the empty reverse path, over the same send
   * path as any other message, so it gets the MX lookup, the policy
   * chain, the spool and the retry budget. The composed bytes travel
   * back with the outcome as `report`, so an operator can read what the
   * sender was sent.
   *
   * Report generation is rate bounded, per original sender and in total.
   * A report is addressed to the sender of the message it is about, and
   * on a run of mail to addresses that do not exist here that sender is
   * whoever forged it, so an unbounded generator is a backscatter
   * amplifier pointed at them. A report the bound refuses is recorded
   * instead: the outcome carries `reportUnsent: true` and names the
   * address that was owed one, and the same fact reaches the audit trail
   * and the operator's log at error level. That address is screened for
   * display on the way back, the way every row this module hands out is,
   * so a caller printing it is not handed an escape sequence whoever
   * sent the message wrote.
   *
   * Building the body runs the framework's header guards over the
   * original sender address, the failed recipient and the enhanced
   * status, all of which reach here from the wire, so a sender trying to
   * smuggle report headers is refused at composition rather than being
   * put on a socket.
   *
   * `origin` is what a report this server could NOT send is filed under.
   * Several situations end here and they are not the same incident: a
   * recipient that does not resolve to a mailbox, an entry whose retry
   * budget ran out, and a message an operator cancelled. Each destroys
   * something different and each has a different next move, so an
   * operator filtering the trail for reports that were owed and never
   * sent needs them apart. Left unsaid it is a local refusal, which is
   * the inbound case and the one that was here first.
   *
   * @opts
   *   to:              string,   // required; the original sender who is owed the report
   *   recipient:       string,   // required; the address that failed
   *   reason:          string,   // required; operator readable explanation
   *   statusCode:      string,   // enhanced status; default 5.1.1
   *   originalHeaders: string,   // header block of the original message
   *   origin:          string,   // what an unsent report is filed under; default "local-refusal"
   *
   * @example
   *   await delivery.bounce({
   *     to:        "sender@example.net",
   *     recipient: "nobody@example.com",
   *     reason:    "No such mailbox on this server",
   *   });
   */
  async function bounce(bounceOpts) {
    if (!bounceOpts || typeof bounceOpts !== "object") {
      throw new TypeError("delivery.bounce: opts object is required");
    }
    if (typeof bounceOpts.recipient !== "string" || bounceOpts.recipient.length === 0) {
      throw new TypeError("delivery.bounce: opts.recipient is required (the address that failed)");
    }
    if (typeof bounceOpts.reason !== "string" || bounceOpts.reason.length === 0) {
      throw new TypeError("delivery.bounce: opts.reason is required (what the sender is told)");
    }
    // Which act is asking. Carried onto every row this function can
    // leave rather than onto the one that records an unsent report
    // alone, because all three answer one operator question: a sender
    // who was not told, and what happened to their message. A row that
    // names only this function names the one thing the reader already
    // knows.
    var origin = typeof bounceOpts.origin === "string" && bounceOpts.origin.length > 0
      ? bounceOpts.origin : "local-refusal";
    if (_isNullSender(bounceOpts.to)) {
      b.audit.safeEmit({
        action:   "blamepost.mail.delivery.report_suppressed",
        outcome:  "success",
        metadata: {
          origin:    origin,
          reason:    "null-return-path",
          recipient: _screenForDisplay(bounceOpts.recipient),
        },
      });
      return { delivered: [], deferred: [], failed: [], reportWithheld: "null-return-path" };
    }
    var statusCode = bounceOpts.statusCode || "5.1.1";
    var composed;
    try {
      composed = deliver.buildDsn({
        dsnFrom:         postmaster,
        originalFrom:    bounceOpts.to,
        recipient:       bounceOpts.recipient,
        reason:          bounceOpts.reason,
        statusCode:      statusCode,
        reportingMta:    hostname,
        originalHeaders: bounceOpts.originalHeaders || "",
      });
    } catch (err) {
      // The header guards refused a value that came off the wire. The
      // message it is about was already accepted, so throwing here would
      // reach the peer as a temporary failure and buy an endless retry
      // of a message this server will always refuse to report on.
      // Record it and answer the caller instead.
      b.audit.safeEmit({
        action:   "blamepost.mail.delivery.report_unbuildable",
        outcome:  "failure",
        metadata: {
          origin:    origin,
          informing: _screenForDisplay(bounceOpts.to),
          about:     _screenForDisplay(bounceOpts.recipient),
          reason:    _screenForDisplay((err && err.message) || String(err)),
        },
      });
      log.error("delivery report for " + _screenForDisplay(bounceOpts.to) + " about " +
        _screenForDisplay(bounceOpts.recipient) + " could not be composed: " +
        _screenForDisplay((err && err.message) || String(err)));
      return {
        delivered: [],
        deferred:  [],
        // The row this branch builds is the fourth reader of the same
        // address, beside the counter, the trail and the log line above.
        // It names whoever the failed message claimed to be from, which
        // is a stranger's bytes going back to a caller that prints them,
        // so it is screened the way every other row this module hands
        // back is.
        failed:    [_screenedReportRow({
          recipient:  bounceOpts.to,
          reason:     (err && err.message) || String(err),
          reasonCode: statusCode,
          mxHost:     null,
          dsnSent:    false,
        })],
        reportUnsent: true,
      };
    }
    var detail = {
      origin:     origin,
      informing:  bounceOpts.to,
      about:      bounceOpts.recipient,
      statusCode: statusCode,
      report:     composed,
      summary:    "no delivery report sent to " + bounceOpts.to +
                  " about " + bounceOpts.recipient,
    };
    var outcome = _mayGenerateReport(bounceOpts.to)
      ? await _sendReport(detail)
      : _recordUnsentReport({
        origin:     detail.origin,
        informing:  detail.informing,
        about:      detail.about,
        statusCode: detail.statusCode,
        bytes:      Buffer.byteLength(composed, "utf8"),
        summary:    detail.summary,
      });
    // The composed report travels back with the outcome, so an operator
    // asking what a sender was told gets the report itself rather than
    // only the fact that one went.
    outcome.report = composed;
    return outcome;
  }

  // ---- reports arriving about this server's own mail ------------------------

  // The RFC 3464 vocabulary the reader works from, taken off the
  // vendored surface rather than restated here. A field name or an
  // action token written a second time in this file is a second answer
  // to what a report says, and the copy is the one that goes stale.
  var dsn = b.mailBounce && b.mailBounce.dsn ? b.mailBounce.dsn : null;
  if (!dsn || typeof dsn.parse !== "function" || !dsn.ACTIONS ||
      !dsn.PER_MESSAGE_FIELDS || !dsn.PER_RECIPIENT_FIELDS) {
    throw new TypeError("blamepost.mail.delivery.create: the vendored framework exposes no " +
      "RFC 3464 report reader. This server sends mail on its own behalf and a report about " +
      "it is the only notice that a reporting endpoint or an operator address has stopped " +
      "working, so a build that cannot read one refuses to assemble rather than collecting " +
      "reports nobody will ever look at.");
  }

  // The key one RFC 3464 field arrives under, found by its canonical
  // spelling in the framework's own table. Writing the lower case key
  // here instead would keep working after the table stopped carrying
  // the field, and the reader would then read undefined and report
  // nothing. This way the build refuses.
  function _dsnKey(table, canonicalName) {
    var keys = Object.keys(table);
    for (var i = 0; i < keys.length; i += 1) {
      if (table[keys[i]] === canonicalName) return keys[i];
    }
    throw new TypeError("blamepost.mail.delivery.create: the vendored RFC 3464 field table " +
      "no longer carries " + canonicalName + ", which the report reader reads its verdict " +
      "from. Refresh the vendored tree and read the diff before composing against it.");
  }

  var FIELD_FINAL_RECIPIENT    = _dsnKey(dsn.PER_RECIPIENT_FIELDS, "Final-Recipient");
  var FIELD_ORIGINAL_RECIPIENT = _dsnKey(dsn.PER_RECIPIENT_FIELDS, "Original-Recipient");
  var FIELD_ACTION             = _dsnKey(dsn.PER_RECIPIENT_FIELDS, "Action");
  var FIELD_STATUS             = _dsnKey(dsn.PER_RECIPIENT_FIELDS, "Status");
  var FIELD_DIAGNOSTIC         = _dsnKey(dsn.PER_RECIPIENT_FIELDS, "Diagnostic-Code");
  var FIELD_REPORTING_MTA      = _dsnKey(dsn.PER_MESSAGE_FIELDS,   "Reporting-MTA");
  var FIELD_ARRIVAL_DATE       = _dsnKey(dsn.PER_MESSAGE_FIELDS,   "Arrival-Date");
  var FIELD_ENVELOPE_ID        = _dsnKey(dsn.PER_MESSAGE_FIELDS,   "Original-Envelope-Id");

  // The address this server puts on the mail it sends about itself, in
  // the one form addresses are compared in everywhere else here. A
  // postmaster the operator wrote in a form the address reader refuses
  // leaves this null, and a null identity matches nothing, so the reader
  // stays off rather than matching every message.
  var reportingIdentityParsed = address.parse(postmaster);
  var reportingIdentity = reportingIdentityParsed.ok ? reportingIdentityParsed.address : null;

  var reportsExamined    = 0;
  var reportsRead        = 0;
  var reportsUnreadable  = 0;
  var reportedRecipients = 0;
  var reportsLastReadAt  = null;
  var recentReports      = [];

  // One counter per action RFC 3464 section 2.3.3 defines, built from
  // the framework's own table rather than from a list written here.
  // Every token gets its own: `relayed` and `expanded` are not
  // deliveries and folding them into one would put a number under a
  // name the report never used, which is the same defect as reading a
  // recipient the report did not name.
  var reportedByAction = Object.create(null);
  Object.keys(dsn.ACTIONS).forEach(function (token) { reportedByAction[token] = 0; });

  function _reportedActions() {
    var out = Object.create(null);
    Object.keys(reportedByAction).forEach(function (token) {
      out[token] = reportedByAction[token];
    });
    return out;
  }

  // The value half of a typed RFC 3464 field. Section 2.3.1 writes a
  // recipient as `address-type; address` and section 2.3.6 writes a
  // diagnostic as `diagnostic-type; diagnostic`, so the part before the
  // first semicolon names the encoding rather than the value.
  //
  // Written here because the framework strips it for the one recipient
  // it derives its own verdict from and hands every other group back as
  // the header said it, and the table it exports names the field rather
  // than reading it. A value with no tag at all is a value: legacy
  // senders write a bare address, and reading that as an empty one
  // would refuse reports that say something perfectly clear.
  //
  // The type token is not screened against a list. Section 2.3.1 admits
  // extension types outright, and RFC 6533 added `utf-8` to the two
  // that existed, so a reader that refused what it did not recognize
  // would refuse a conforming report from a receiver doing nothing
  // wrong.
  function _afterTypeTag(value) {
    var text = _text(value).trim();
    var semi = text.indexOf(";");
    if (semi === -1) return text;
    return text.slice(semi + 1).trim();
  }

  function _isReportingIdentity(candidate) {
    if (reportingIdentity === null || typeof candidate !== "string") return false;
    var parsed = address.parse(candidate);
    return parsed.ok && parsed.address === reportingIdentity;
  }

  function _rememberReport(entry) {
    recentReports.push(entry);
    if (recentReports.length > MAX_RECENT_ARRIVING_REPORTS) {
      recentReports = recentReports.slice(recentReports.length - MAX_RECENT_ARRIVING_REPORTS);
    }
  }

  // A report that presented itself as one and could not be read. It is
  // recorded rather than dropped: the difference between a reporting
  // endpoint that is fine and one whose reports this server cannot read
  // is invisible to an operator otherwise, and both end with nothing in
  // the counters that says a failure was reported.
  function _reportUnreadable(mailbox, why) {
    reportsUnreadable += 1;
    var reason = _screenForDisplay(why);
    _rememberReport({ at: Date.now(), unreadable: true, reason: reason });
    b.audit.safeEmit({
      action:   "blamepost.mail.delivery.report_unreadable",
      outcome:  "failure",
      metadata: { mailbox: _screenForDisplay(mailbox), reason: reason },
    });
    log.error("a delivery report filed for " + _screenForDisplay(mailbox) +
      " could not be read, so nothing in it is believed: " + reason);
    return { read: false, reason: "unreadable", detail: reason };
  }

  /**
   * @primitive blamepost.mail.delivery.reports
   * @signature delivery.reports
   * @since     0.1.0
   * @status    experimental
   * @spec      RFC 3464 (DSN), RFC 3462 (multipart/report), RFC 3463 (enhanced status), RFC 6533 (internationalized recipients)
   * @related   blamepost.mail.delivery.bounce, blamepost.mail.mailbox.onFiled
   *
   * The other direction of RFC 3464. `bounce` composes the reports this
   * server owes other people; this reads the ones other people send back
   * about the mail this server sends on its own behalf.
   *
   * A report addressed to an account is that account's mail and is left
   * alone: it lands in their mailbox and a person reads it. The mail
   * this server sends about itself has nobody like that behind it. Its
   * reverse path is the reporting identity the operator configured, and
   * a report saying a receiver's transport reporting endpoint has
   * stopped accepting mail is the only notice anybody gets that this
   * server has quietly stopped honoring something it publishes. So a
   * report filed for that one address is read, and every other message
   * is passed over untouched.
   *
   * `receive` returns a verdict and changes nothing else. That is the
   * whole security posture and it is deliberate. A report is a document
   * a stranger composed and addressed here; anybody can write a well
   * formed one naming any message, and this server retains nothing that
   * could prove the report is about a message it actually sent. It
   * issues no envelope identifier, so `Original-Envelope-Id` is a value
   * the sender of the report chose. The spool holds only recipients that
   * are still being retried, and a message that was accepted and bounced
   * afterwards left the spool at the moment it was accepted. There is
   * nothing to match against, so nothing is matched, and nothing in the
   * outbound queue moves because a report arrived. The counters and the
   * audit rows are the whole effect.
   *
   * What is read is read whole. RFC 3464 section 2.3.3 makes `Action`
   * mandatory in every per recipient group and names the five tokens it
   * may carry, and the framework parser derives its verdict from the
   * first group alone, so a report whose second recipient carries a
   * token nobody defined would otherwise be reported as though that
   * recipient had never been mentioned. Every group is read here, every
   * `Action` is checked against the framework's own table, and a report
   * with one bad group is refused entire rather than half kept: a half
   * read report is a number an operator would act on that the report
   * never actually claimed.
   *
   * `recent()` returns the last few verdicts, screened for printing,
   * which is what answers the question the counters raise. Everything in
   * one has been through the same screening as a peer's refusal, because
   * every value in a report was written by somebody else.
   *
   * @example
   *   delivery.reports.receive(raw, { arrivedFor: "postmaster@example.com" });
   *   delivery.describe().reports.byAction.failed;
   */
  function receiveReport(rfc822, receiveOpts) {
    var options = receiveOpts || {};
    if (typeof options !== "object" || Array.isArray(options)) {
      throw new TypeError("delivery.reports.receive: opts must be an object carrying " +
        "arrivedFor, the address the message was filed for");
    }
    if (!_isReportingIdentity(options.arrivedFor)) {
      return { read: false, reason: "not-a-reporting-identity" };
    }
    reportsExamined += 1;

    var bytes = Buffer.isBuffer(rfc822) ? rfc822 : Buffer.from(_text(rfc822), "utf8");
    if (bytes.length > MAX_ARRIVING_REPORT_BYTES) {
      return _reportUnreadable(options.arrivedFor,
        "the message is " + bytes.length + " bytes, past the " +
        MAX_ARRIVING_REPORT_BYTES + " a report is read up to");
    }

    // Whether this is a report at all is the framework's answer rather
    // than a substring test on a header. A message with no
    // message/delivery-status part is ordinary mail to the operator,
    // which is most of what arrives at this address, and recording one
    // of those would bury the reports the counters exist to surface.
    var claimsToBeAReport;
    try {
      var tree = b.safeMime.parse(bytes, MESSAGE_PARSE_CAPS);
      claimsToBeAReport = b.safeMime.findFirst(tree, function (part) {
        return !!part.leaf && part.leaf.contentType === "message/delivery-status";
      }) !== null;
    } catch (structureError) {
      // A message the framework's own reader refuses. Which of the two
      // it was cannot be settled from here, so it is recorded: at this
      // address an extra row costs an operator one line, and staying
      // quiet costs them the only notice that a reporting endpoint has
      // broken.
      return _reportUnreadable(options.arrivedFor,
        "the message structure could not be read: " +
        ((structureError && structureError.message) || String(structureError)));
    }
    if (!claimsToBeAReport) return { read: false, reason: "not-a-report" };

    // The framework's report reader works on text, so the octets have to
    // be decoded to reach it, and a decode is only the identity for
    // bytes that really are UTF-8. RFC 6533 is what makes that the right
    // demand rather than a convenience: it defines the internationalized
    // form of these fields as UTF-8, so a report carrying anything else
    // is one this reader has no defined way to read. Decoding it anyway
    // would substitute a replacement character for every sequence it did
    // not recognize and then record the result as what the far side
    // said. The message is untouched in the mailbox either way, so an
    // operator who needs the original still has it.
    if (!nodeBuffer.isUtf8(bytes)) {
      return _reportUnreadable(options.arrivedFor,
        "the report carries octets that are not UTF-8, which is the encoding RFC 6533 " +
        "defines these fields in, so nothing in it can be read without inventing characters");
    }

    var parsed;
    try {
      parsed = dsn.parse(bytes.toString("utf8"));
    } catch (parseError) {
      return _reportUnreadable(options.arrivedFor,
        (parseError && parseError.message) || String(parseError));
    }

    var groups = (parsed.raw && parsed.raw.allRecipients) || [];
    if (groups.length === 0) {
      return _reportUnreadable(options.arrivedFor,
        "the report names no recipients, so it says nothing about anything");
    }
    if (groups.length > MAX_ARRIVING_REPORT_RECIPIENTS) {
      return _reportUnreadable(options.arrivedFor,
        "the report names " + groups.length + " recipients, past the " +
        MAX_ARRIVING_REPORT_RECIPIENTS + " one report is read up to");
    }

    var read = [];
    for (var i = 0; i < groups.length; i += 1) {
      var group = groups[i];
      var recipient = _afterTypeTag(
        group[FIELD_FINAL_RECIPIENT] || group[FIELD_ORIGINAL_RECIPIENT] || "");
      if (recipient.length === 0) {
        return _reportUnreadable(options.arrivedFor,
          "recipient group " + (i + 1) + " of " + groups.length + " carries no " +
          dsn.PER_RECIPIENT_FIELDS[FIELD_FINAL_RECIPIENT] + ", so there is no address it " +
          "is about");
      }
      var action = String(group[FIELD_ACTION] || "").toLowerCase().trim();
      if (action.length === 0) {
        return _reportUnreadable(options.arrivedFor,
          "recipient group " + (i + 1) + " of " + groups.length + " carries no " +
          dsn.PER_RECIPIENT_FIELDS[FIELD_ACTION] + ", which RFC 3464 section 2.3.3 " +
          "requires, so what the report says happened to that address is unstated");
      }
      if (!Object.prototype.hasOwnProperty.call(dsn.ACTIONS, action)) {
        return _reportUnreadable(options.arrivedFor,
          "recipient group " + (i + 1) + " of " + groups.length + " carries the action " +
          JSON.stringify(action) + ", which is not one of the tokens RFC 3464 section " +
          "2.3.3 defines");
      }
      read.push({
        recipient:  _screenForDisplay(recipient),
        action:     action,
        status:     _screenForDisplay(_text(group[FIELD_STATUS] || "").trim()),
        diagnostic: _screenForDisplay(_afterTypeTag(group[FIELD_DIAGNOSTIC] || "")),
      });
    }

    // Counted only once the whole report has been read, so a report
    // refused on its last group leaves nothing behind from its first.
    reportsRead += 1;
    reportsLastReadAt = Date.now();
    reportedRecipients += read.length;
    for (var c = 0; c < read.length; c += 1) {
      reportedByAction[read[c].action] += 1;
    }

    var perMessage = (parsed.raw && parsed.raw.perMessage) || {};
    var entry = {
      at:           reportsLastReadAt,
      unreadable:   false,
      reportingMta: _screenForDisplay(perMessage[FIELD_REPORTING_MTA] || ""),
      arrivalDate:  _screenForDisplay(perMessage[FIELD_ARRIVAL_DATE] || ""),
      // Kept as what the report said and never used to look anything
      // up. This server issues no envelope identifier, so every value
      // that ever appears here was chosen by whoever composed the
      // report, and treating one as a key would be treating a stranger's
      // string as the name of a message this server sent.
      originalEnvelopeId: _screenForDisplay(perMessage[FIELD_ENVELOPE_ID] || ""),
      // Rows of its own rather than the ones handed back below, so a
      // caller that edits the verdict it was given does not edit the
      // record kept for the operator.
      recipients: read.slice(0, MAX_SHOWN_ARRIVING_RECIPIENTS).map(function (row) {
        return Object.assign({}, row);
      }),
      recipientCount: read.length,
    };
    _rememberReport(entry);

    b.audit.safeEmit({
      action:   "blamepost.mail.delivery.report_received",
      outcome:  "success",
      metadata: {
        mailbox:        _screenForDisplay(options.arrivedFor),
        reportingMta:   entry.reportingMta,
        recipientCount: read.length,
        actions:        read.slice(0, MAX_SHOWN_ARRIVING_RECIPIENTS)
          .map(function (row) { return row.action; }),
        recipients:     read.slice(0, MAX_SHOWN_ARRIVING_RECIPIENTS)
          .map(function (row) { return row.recipient; }),
      },
    });

    return { read: true, recipients: read.slice() };
  }

  // Copied down to the rows. A shallow copy would hand back the same
  // recipient objects the record holds, so a caller that edited what it
  // read would edit what the next caller reads, and the record an
  // operator opened to find out what a receiver said would say whatever
  // the last reader left in it.
  function recentReportsRead() {
    return recentReports.map(function (entry) {
      var copy = Object.assign({}, entry);
      if (Array.isArray(entry.recipients)) {
        copy.recipients = entry.recipients.map(function (row) {
          return Object.assign({}, row);
        });
      }
      return copy;
    });
  }

  // The shape `blamepost.mail.mailbox.onFiled` calls with. It takes the
  // filed message event, keeps the two fields the reader needs, and
  // lets the rest go.
  //
  // It exists so the wiring reads as one line where the server is
  // assembled rather than as a closure written there. What it must never
  // do is throw. The mailbox layer catches whatever comes out of an
  // observer precisely because filing is the operation a peer is waiting
  // on, and leaning on that catch rather than returning cleanly would
  // turn every reader defect into an audit row about the mailbox instead
  // of one about the report.
  function observeFiled(event) {
    if (!event || typeof event !== "object") return;
    // A reporting identity that is an alias files its mail under the
    // destination account, so the envelope recipient is checked first.
    var arrivedFor = _isReportingIdentity(event.recipient) ? event.recipient : event.address;
    receiveReport(event.raw, { arrivedFor: arrivedFor });
  }

  /**
   * @primitive blamepost.mail.delivery.queue
   * @signature delivery.queue
   * @since     0.1.0
   * @status    stable
   * @spec      internal (design: on-disk outbound spool for transient failures)
   * @related   blamepost.mail.delivery.send
   *
   * The outbound spool, which is what `blamepost queue` reads and
   * drives. `list` returns every waiting descriptor sorted by the time
   * it becomes due. `count` is the same number without reading each
   * body. `held` is the part of that count waiting on something other
   * than a receiver's verdict, grouped by what would have to change and
   * carrying the moment the oldest of them was queued; no delivery path
   * here writes an entry there, so it counts only descriptors that
   * arrive with the hold flag set, and it empties as those entries are
   * attempted.
   * `show` reads one entry with everything already tried on it. `runDue`
   * retries everything whose moment has arrived and returns what
   * happened to each. `remove` drops one entry by id, which is how an
   * operator abandons a message addressed to a domain that is never
   * coming back.
   *
   * `remove(id, { reason, notice })` needs both and refuses without
   * either. It is the only verb here that destroys a message no receiver
   * refused, and the two questions asked of it afterwards are always the
   * same: which messages went and why, and whether their senders were
   * told. Both are collected where the destroying happens rather than by
   * each surface that reaches it. A reason of spacing alone records
   * nothing and is refused with the rest. The id is read first, so an
   * operator who mistyped it hears about the id rather than about the
   * reason they did supply.
   *
   * `notice` says whether the sender is written to, and the caller has
   * to say. `notice.status` is the enhanced status to report the
   * cancellation under; `notice.withheld` is the reason no report is
   * owed. Both answers are legitimate and neither is this module's to
   * pick: a routine cancellation should tell the sender, while a
   * cancellation made during an incident, on mail a stolen credential
   * sent, must not tell whoever stole it which messages were caught. A
   * default would hand one of those to a caller that never considered
   * the question. The refusal comes before the removal, so a caller that
   * has not decided cannot destroy a message to find out.
   *
   * A report goes out through `bounce`, so it carries the empty reverse
   * path, is bounded by the same generator, and quotes the cancelled
   * message's own headers as RFC 3462 §3 asks. Those are read off the
   * volume before the removal, because that is the only moment they
   * exist. Nothing is written to anybody unless the message actually
   * left: a removal the volume refused cancelled nothing, and a report
   * on it would tell a sender an operator stopped mail that is still
   * going out.
   *
   * `remove` answers
   * `{ id, removed, outcome, left, destroyed, reason, requestedBecause,
   * reported, withheld }`, and every field is read off the volume rather
   * than assumed. `reported` says whether the sender was written to.
   * `withheld` names why not, and is one of `message-not-cancelled`
   * where nothing left the volume, `message-destroyed-in-part` where the
   * message was destroyed and the entry beside it stayed, so there are
   * no headers left to quote back, `null-return-path` for a report being
   * cancelled, `no-sender-recorded` where no descriptor named anybody,
   * or the caller's own word. Both are always present, because a verdict
   * that carried the erasure alone reads as an erasure everybody was
   * told about.
   * `requestedBecause` is the reason as this call accepted it, trimmed,
   * so every surface records one value rather than its own reading of
   * what the operator typed. `reason` is a different field and carries
   * what the VOLUME said when it would not give a part up.
   * `removed` means something left. `not-spooled` means there was nothing
   * under that name: the message had already gone, which is past
   * cancelling and has to be treated as sent. `refused` means the volume
   * kept a part and NOTHING was destroyed, so the message is still on
   * disk, the sweep will go on retrying it, and a rerun once the volume
   * lets go reaches the same message. `incomplete` means part of the
   * entry was destroyed and part of it stayed: the message is past
   * sending whatever happens next, and a rerun reaches only the
   * remainder. `left` names the parts that stayed, `destroyed` the parts
   * that went, and `reason` carries what the volume said.
   *
   * A caller that files a row does it on `removed` alone: the other
   * three are cancellations that did not happen in full, and recording
   * them as cancellations tells an operator working through a
   * compromised account's outbound mail that a message was stopped while
   * it is with the receiver. `refused` and `incomplete` are told apart in
   * what the caller SAYS, because the operator's next move differs: one
   * is worth running again for the message, and the other is a message
   * that has already gone whichever way the fault is cleared.
   *
   * Three read the spool as a bounded place rather than as a list.
   * `capacity` is how full it is and what it is allowed to hold, counted
   * off the volume rather than remembered, so it stays right across a
   * restart and across an operator clearing an entry by hand. `admits`
   * is the decision itself: it takes `{ entries, bytes, origin }` and
   * answers null when there is room, or the refusal to raise when there
   * is not. Both listeners ask it once per message, before anything has
   * been committed, which is the only moment refusing is free. `claim`
   * takes one entry so nothing else attempts it, and answers null when
   * somebody already has it.
   *
   * `origin` decides which share of the ceiling a message may take, and
   * the shares differ by who chooses the volume. `inbound` is mail
   * arriving from a stranger for forwarding, whose volume belongs to
   * whoever writes to the alias, so it stops short of the ceiling and
   * accounts that have authenticated keep room to send. `report` is a
   * delivery report this server generated, whose volume belongs to
   * whoever addressed the message it is about, so it stops shortest of
   * all. Anything else reaches the whole ceiling.
   *
   * A message leaves this spool on somebody's answer or on the end of
   * the retry budget: a peer accepted it, a peer or a domain's own zone
   * refused it permanently, the budget ran out and a report went to its
   * sender, or an operator removed it. `waiting` is therefore the number
   * to watch. A queue that keeps growing while nothing is being
   * delivered is a posture to change or a receiver to contact.
   *
   * `list` takes an optional `{ account, destination }`. `account`
   * matches the envelope sender, `destination` the recipient's domain,
   * and both are canonicalized before comparison so the answer does not
   * depend on how the operator capitalized what they typed. A value
   * that is not a usable address or domain throws rather than matching
   * nothing, because an empty list is the same sentence a correct empty
   * answer produces. An unreadable descriptor is returned whatever the
   * filter says: it carries no sender or recipient to compare, and it
   * is the one entry that needs a person. Each row carries
   * `attemptsRecorded` and `lastAttempt`, so a listing answers "has
   * this been tried, and what did the far side say" without carrying
   * every attempt into every row.
   *
   * `show(id)` is that entry on its own, with `history`, one row per
   * attempt, and `projection`, which says how it ends if nothing
   * changes. An id that is not one this server minted is refused
   * rather than turned into a path, and a well formed id with nothing
   * behind it reads as `null`, which is a message that is no longer
   * waiting rather than an error.
   *
   * `runDue` reports one row per entry it touched, with an `outcome` of
   * `delivered`, `failed`, `waiting`, `error`, `abandoned`, `removed`
   * or `claimed`. Only `delivered`, `failed` and `abandoned` take the
   * entry off disk. `waiting` and `error` leave it spooled with the
   * moment of its next attempt moved forward, `abandoned` is an entry
   * that has nothing left to try against a fault on this side rather
   * than a peer's, `removed` is one an operator took out of the
   * spool while the attempt was in flight, which is left out rather
   * than written back, and `claimed` is one another process is already
   * attempting, which is left exactly as it was found.
   *
   * An `abandoned` entry whose budget ran out sends its sender a report
   * under RFC 3463 status 4.4.7, which says the message was held here as
   * long as this server would hold it rather than that a receiver
   * refused the address. Two of them send nothing, and both silences are
   * recorded rather than assumed: a delivery report has the empty
   * reverse path and so has nobody to tell, and an entry whose message
   * had already left the volume was settled by whoever took it, who
   * decided then what its sender hears.
   *
   * `claimed` is why draining the spool is safe to run twice at once.
   * Every mutating verb on the data volume is serialized by the
   * single-opener lock except this one, which never opens the database
   * so that it still works on a server whose volume will not open. The
   * claim replaces the lock at the granularity that keeps that true.
   *
   * Everything all three hand back is safe to print. The addresses and
   * the far side's words go through `b.guardText` on the way out, so a
   * caller can write a row straight into a terminal or a page without
   * screening it again, and an entry that has sat on disk across
   * restarts is as safe as one spooled a moment ago. The bytes on disk are untouched,
   * which is where to look when a refusal has to be read exactly as it
   * was written. Filtering still compares the stored values, so an
   * address is matched as it is rather than as it prints.
   *
   * @example
   *   var waiting = await delivery.queue.list();
   *   var entry   = await delivery.queue.show(waiting[0].id);
   *   var report  = await delivery.queue.runDue();
   */
  // A filter an operator typed, refused loudly rather than quietly
  // matching nothing. An unparseable address that returned an empty list
  // would read as "this account has nothing waiting", which is the same
  // sentence a correct empty answer produces and the opposite of the
  // truth. The address module already refuses with a message naming what
  // was wrong, so it does the work.
  function _listFilter(opts) {
    var want = {};
    if (opts && opts.account !== undefined && opts.account !== null) {
      want.account = address.canonical(opts.account, "queue.list account filter").address;
    }
    if (opts && opts.destination !== undefined && opts.destination !== null) {
      want.destination = address.canonicalDomain(opts.destination,
        "queue.list destination filter");
    }
    return want;
  }

  // An unreadable descriptor is kept whatever the filter says. It has no
  // sender and no recipient to compare, and dropping it would hide the
  // one entry an operator has to act on by hand.
  function _matchesFilter(entry, want) {
    if (entry.unreadable) return true;
    if (want.account !== undefined) {
      var from = address.parse(entry.from);
      if (!from.ok || from.address !== want.account) return false;
    }
    if (want.destination !== undefined) {
      var to = address.parse(entry.recipient);
      if (!to.ok || to.domain !== want.destination) return false;
    }
    return true;
  }

  // Every descriptor on disk, whole. The sweep reads this one, because
  // it has to carry each entry's own record forward onto the next
  // attempt; the listing an operator reads is projected from it.
  async function _readEntries(want) {
    var files = b.atomicFile.listDir(spoolDir, {
      filter: function (name) { return name.slice(-5) === ".json"; },
    });
    var out = [];
    for (var i = 0; i < files.length; i += 1) {
      var id = files[i].name.slice(0, -5);
      var entry;
      try {
        entry = await _readDescriptor(id);
      } catch (_e) {
        // A descriptor that cannot be read is a half written file left
        // by a crash between the body write and the rename. It is
        // reported rather than hidden, so `blamepost queue list` shows
        // it and `blamepost queue remove` clears it.
        entry = { id: id, unreadable: true };
      }
      if (_matchesFilter(entry, want)) out.push(entry);
    }
    out.sort(function (x, y) {
      return (x.nextAttemptAt || 0) - (y.nextAttemptAt || 0);
    });
    return out;
  }

  function _lastAttemptOf(entry) {
    var rows = Array.isArray(entry.history) ? entry.history : [];
    return rows.length ? rows[rows.length - 1] : null;
  }

  // The values on an entry that came from somewhere else: two addresses
  // whoever sent the message chose, two texts whoever refused it wrote,
  // and the sentence beside a hold flag, which no delivery path here
  // sets and which therefore only ever arrives on a descriptor somebody
  // else wrote.
  //
  // This list and the one below are complete because `_readDescriptor`
  // makes them complete. It hands back the fields `_writeDescriptor`
  // writes and nothing else, each as the type it was written as, so the
  // strings on an entry are exactly these five plus the id, and the id
  // is the file's own name rather than anything the file said. A reader
  // screening a named set of fields out of an object of unknown shape
  // would be an allowlist against input that chooses its own keys.
  var FOREIGN_TEXT_FIELDS = ["from", "recipient", "reason", "reasonCode", "heldBecause"];

  // One entry, safe to print.
  //
  // Every reader of this module puts what it gets back in front of a
  // person: `blamepost queue list` writes it into a terminal, the admin
  // queue page renders it, and the JSON form of either is read in a
  // terminal too. So the screening is here, at the one boundary all of
  // them cross, rather than repeated in each of them where a new reader
  // arrives without it. The descriptor on disk is untouched and still
  // holds what arrived.
  function _screenedEntry(entry) {
    var row = {};
    Object.keys(entry).forEach(function (k) { row[k] = entry[k]; });
    for (var i = 0; i < FOREIGN_TEXT_FIELDS.length; i += 1) {
      var field = FOREIGN_TEXT_FIELDS[i];
      if (row[field] === undefined || row[field] === null) continue;
      row[field] = _screenForDisplay(row[field]);
    }
    return row;
  }

  // The same treatment for anything else this module hands back for a
  // person to read: a row of an entry's attempt record, and a row of
  // what a sweep did. A receiver name is a DNS answer and belongs in
  // the list for the same reason the rest do, and so does the outcome:
  // a sweep writes its own word there, and a row read back off a
  // descriptor carries whatever the file said happened.
  var REPORTED_TEXT_FIELDS = ["recipient", "reason", "reasonCode", "error", "mxHost", "outcome"];

  function _screenedReportRow(row) {
    var out = {};
    Object.keys(row).forEach(function (k) { out[k] = row[k]; });
    for (var i = 0; i < REPORTED_TEXT_FIELDS.length; i += 1) {
      var field = REPORTED_TEXT_FIELDS[i];
      if (out[field] === undefined || out[field] === null) continue;
      out[field] = _screenForDisplay(out[field]);
    }
    return out;
  }

  function _screenedHistory(entry) {
    var rows = Array.isArray(entry.history) ? entry.history : [];
    return rows.map(_screenedReportRow);
  }

  // The composer's per recipient answer, made safe to hand back.
  //
  // The three lists on it carry text this server did not write. A
  // `reason` is whatever settled the recipient, which for a lookup that
  // failed is the failure's own message and for a refusal is what came
  // back from the far side, and `mxHost` is a name out of somebody
  // else's zone. Both are printed by `blamepost queue flush` into a
  // console table and rendered on the administration queue page, which
  // are the same two readers the listing verbs screen for.
  //
  // The copy is made here rather than in place, so what was already
  // written to the spool keeps what arrived: the descriptor is the record
  // of what a peer actually said, and the screen runs on every read.
  function _screenedOutcome(outcome) {
    if (outcome === null || typeof outcome !== "object") return outcome;
    var out = {};
    Object.keys(outcome).forEach(function (k) {
      out[k] = Array.isArray(outcome[k]) ? outcome[k].map(function (row) {
        return row !== null && typeof row === "object" ? _screenedReportRow(row) : row;
      }) : outcome[k];
    });
    return out;
  }

  // A listing is read a hundred entries at a time, so it carries the
  // last thing that happened rather than everything that ever did. The
  // whole record is one `show` away.
  function _listRow(entry) {
    var row = _screenedEntry(entry);
    delete row.history;
    var last = _lastAttemptOf(entry);
    row.lastAttempt = last === null ? null : _screenedReportRow(last);
    return row;
  }

  // How this entry ends if nothing changes, which is the half of "why
  // is this stuck" that a record of the past cannot answer.
  //
  // An entry whose descriptor sets the hold flag is not spending the
  // budget, so counting its ending in attempts would be a fiction:
  // `attemptsRemaining` is null and the sentence says what releases it,
  // which is the next attempt. Everything else is counted, and the
  // sentence names who hears about it and when.
  //
  // The hold reason is read off the entry rather than assumed, because a
  // descriptor that sets the flag and records no reason still reads as
  // held and should say what is known, which is that nobody refused it.
  //
  // An entry that IS a delivery report ends differently and says so. Its
  // reverse path is the empty one RFC 5321 §6.1 puts on every report, so
  // there is nobody to write to when it runs out of attempts, and a
  // sentence promising one would name a sender that does not exist.
  function _projectEnding(entry) {
    var last = _lastAttemptOf(entry);
    var held = entry.held === true || (last !== null && last.held === true);
    var spent = typeof entry.attempt === "number" ? entry.attempt : 0;
    var remaining = Math.max(0, maxAttempts - spent);
    var because = _text(entry.heldBecause || "") ||
      "no receiver has refused this message, so nothing is counting down against it";
    var recorded = _text(entry.reason || "");
    var ending = _isNullSender(entry.from)
      ? "After " + remaining + " more attempt(s) this message is given up on. It is a " +
        "delivery report, which travels with an empty reverse path, so there is nobody " +
        "to tell that it did not arrive."
      : "After " + remaining + " more attempt(s) this message is given up on and a " +
        "delivery report is sent to " + _screenForDisplay(entry.from) + ".";
    return {
      held:              held,
      attemptsSpent:     spent,
      attemptsAllowed:   maxAttempts,
      attemptsRemaining: held ? null : remaining,
      nextAttemptAt:     entry.nextAttemptAt || 0,
      ifItNeverSucceeds: held
        ? "This entry carries a hold flag that no delivery path here sets: " +
          _screenForDisplay(because) +
          ". The next attempt clears the flag and puts the message back on the " +
          "ordinary retry budget, where it ends like any other message" +
          (recorded ? ", and the last attempt ended with " +
            _screenForDisplay(recorded) : "") +
          ". Release it now with `blamepost queue flush`."
        : ending,
    };
  }

  async function queueList(opts) {
    var entries = await _readEntries(_listFilter(opts));
    return entries.map(_listRow);
  }

  function queueCount() {
    return b.atomicFile.listDir(spoolDir, {
      filter: function (name) { return name.slice(-5) === ".json"; },
    }).length;
  }

  // Whether one entry is waiting on something other than a receiver's
  // verdict. The flag on the descriptor is the answer; the last
  // attempt's own row is read as well so an entry written before the
  // flag existed still reads correctly rather than reading as one
  // attempt away from being dropped.
  function _isHeldEntry(entry) {
    if (entry.held === true) return true;
    var last = _lastAttemptOf(entry);
    return last !== null && last.held === true;
  }

  // What the spool is holding, and what would have to change to release
  // it.
  //
  // A spool that keeps mail rather than destroying it has to be a place
  // an operator can see into, or it becomes a place mail goes to be
  // forgotten. Nothing here is a fault on its own: a held message is a
  // message that still exists. What matters is the shape of the pile,
  // which is why the answer is grouped by cause rather than returned as
  // one number, and why the oldest entry is named. One cause holding
  // thousands of messages is a posture to change or an upstream fix to
  // follow; a handful of causes holding one message each is ordinary.
  //
  // Read from the descriptors rather than from this process's memory,
  // so a server that has just booted gives the same answer as the one
  // that spooled them.
  async function queueHeld() {
    var entries = await _readEntries({});
    var counts = new Map();
    var messages = 0;
    var oldest = null;
    for (var i = 0; i < entries.length; i += 1) {
      var entry = entries[i];
      if (entry.unreadable || !_isHeldEntry(entry)) continue;
      messages += 1;
      if (typeof entry.queuedAt === "number" && (oldest === null || entry.queuedAt < oldest)) {
        oldest = entry.queuedAt;
      }
      var why = _screenForDisplay(_text(entry.heldBecause || "") ||
        "no receiver has refused this message, so nothing is counting down against it");
      counts.set(why, (counts.get(why) || 0) + 1);
    }
    var reasons = [];
    counts.forEach(function (count, reason) {
      reasons.push({ reason: reason, messages: count });
    });
    reasons.sort(function (x, y) {
      if (y.messages !== x.messages) return y.messages - x.messages;
      return x.reason < y.reason ? -1 : (x.reason > y.reason ? 1 : 0);
    });
    return { messages: messages, oldestQueuedAt: oldest, reasons: reasons };
  }

  async function queueShow(id) {
    _assertSpoolId(id, "show");
    var entry;
    try {
      entry = await _readDescriptor(id);
    } catch (_e) {
      // Nothing by that name is waiting, which is an answer rather than
      // a fault: the message may have been delivered, given up on, or
      // removed by an operator since the id was read.
      return null;
    }
    var shown = _screenedEntry(entry);
    shown.history = _screenedHistory(entry);
    shown.projection = _projectEnding(entry);
    // The body's own size, measured on the volume rather than read off
    // the descriptor, which carries no size and could not be believed
    // about one. `null` says the body is gone, which is the orphan half
    // of a pair and a different answer from a message of no bytes.
    shown.sizeBytes = _bodySizeBytes(entry.id);
    return shown;
  }

  // The size of one waiting body, or null when it is not there. The
  // listing walks the whole directory for its census; one entry is one
  // name, so it is asked for directly.
  function _bodySizeBytes(id) {
    var found = b.atomicFile.listDir(spoolDir, {
      includeStat: true,
      filter:      function (name) { return name === id + BODY_SUFFIX; },
    });
    if (found.length !== 1) return null;
    return typeof found[0].sizeBytes === "number" ? found[0].sizeBytes : null;
  }

  // The reason a removal is made for, refused when it is not one.
  //
  // Held here rather than at each surface, because it is a rule about
  // the act and not about any one way of asking for it. Two surfaces
  // reach this verb today and each carried its own copy of the rule,
  // which is two statements of one requirement to keep in step and one
  // of them going quiet the day a third surface arrives without it. A
  // surface still collects the sentence, because collecting it is what a
  // surface does, and this is what refuses the removal when it did not
  // arrive.
  //
  // Trimmed, and refused when trimming empties it. A row whose reason is
  // a run of spaces answers no better than one with nothing in it, and
  // an operator who typed a space by accident finds out here rather than
  // at the audit read months later. The trimmed value comes back on the
  // verdict, so both surfaces record the sentence this call accepted
  // instead of each recording its own reading of it.
  //
  // A throw rather than a verdict, because this is the entry point an
  // operator's surface reaches with something it built: an argument that
  // is not one is a fault in the caller, while every value the verdict
  // carries is a reading of the volume.
  function _requireRemovalReason(value) {
    if (typeof value !== "string" || value.trim().length === 0) {
      throw new TypeError("delivery.queue.remove: opts.reason is required (why this message " +
        "is being taken out of the queue). Removing an entry destroys a message no receiver " +
        "refused, and the audit row it leaves answers nothing later without one");
    }
    return value.trim();
  }

  // Whether the sender of a cancelled message is written to, said by the
  // caller and refused when it was not said at all.
  //
  // A cancellation destroys two things. The message is one; the sender's
  // belief that it arrived is the other, and nothing else on this server
  // ever corrects it, because no receiver refuses a message that never
  // left. Unless somebody writes to whoever sent it, they go on
  // believing it went. Deciding that is a policy, and it belongs beside
  // the rule that requires the sentence, for the same reason the
  // sentence does: a rule kept in the surfaces is a rule the next
  // surface arrives without.
  //
  // What it is NOT is a policy this module can pick. Both answers are
  // right in their own place. The console cancels routinely and writing
  // to the sender is the courteous thing; the command line is reached
  // during an incident, on mail a stolen credential sent, where the
  // "sender" is whoever stole it and a report tells an attacker which
  // messages were caught. A default here hands one of those to a caller
  // that never considered the question, and the row it leaves does not
  // say which applied.
  //
  // So the caller states it and the module enforces that it was stated.
  // `notice.status` is the enhanced status to report the cancellation
  // under; `notice.withheld` is the reason no report is owed. This is
  // the same pair the sweep's own abandonment takes, deliberately: two
  // shapes for one question would be the drift this is closing.
  //
  // A throw rather than a verdict, and thrown in front of the removal.
  // Every value the verdict carries is a reading of the volume, and this
  // is a caller that has not decided; raising once the pair had gone
  // would destroy a message to make the point.
  function _requireRemovalNotice(value) {
    var chosen = value && typeof value === "object" ? value : null;
    if (chosen === null || (!chosen.status && !chosen.withheld)) {
      throw new TypeError("delivery.queue.remove: opts.notice is required and must name " +
        "either the enhanced status to report this cancellation to its sender under, or the " +
        "reason no report is owed. Cancelling destroys a message no receiver refused, and " +
        "its sender goes on believing it arrived unless somebody tells them, so a caller " +
        "that has not decided which cannot make the decision by omission");
    }
    return {
      status:   chosen.status ? String(chosen.status) : null,
      withheld: chosen.withheld ? String(chosen.withheld) : null,
    };
  }

  // The headers a report about a spooled message quotes, read off the
  // volume while the message is still on it.
  //
  // RFC 3462 §3 asks for the original headers because they are how a
  // sender tells one report from another: the recipient and the status
  // are the same on every message they sent to that address, and the
  // quoted block is the only thing that names which one this is. So it
  // has to be read BEFORE the removal, which is the only moment it
  // exists.
  //
  // Drop-silent by design. A body the volume will not give up is a
  // reason to send a thinner report, never a reason to send none and
  // never a reason to stop the removal that is already the caller's
  // decision. An empty block composes a report the framework accepts.
  async function _spooledHeaderBlock(id) {
    try {
      var holding = await _holdSpoolBody(id);
      if (holding.error !== null || holding.held === null) return "";
      return reportedHeaderBlock(holding.held);
    } catch (_err) {
      return "";
    }
  }

  // The descriptor of an entry that may not have one, for a caller that
  // treats its absence as an answer rather than as a fault. A descriptor
  // that is not there, or that a crash left half written, names nobody,
  // and `null` is what says so.
  async function _descriptorIfAny(id) {
    try {
      var entry = await _readDescriptor(id);
      return entry && typeof entry === "object" ? entry : null;
    } catch (_err) {
      return null;
    }
  }

  // Take one entry out of the queue on somebody's decision, and answer
  // with what happened to it rather than with what was attempted.
  //
  // Both surfaces that reach this write the answer down, and both write
  // down the same two things: what the volume did, and whether the
  // sender was told. Neither is a claim this call can be taken on trust
  // about, because both are claims about the volume. So both are read
  // off it here and handed back, rather than each surface recording its
  // own intent as though it were an outcome. A caller that asked for a
  // report and did not get one would otherwise file a row saying one
  // went.
  //
  // The report goes out through `bounce`, which is this module's one
  // report path: the RFC 3464 body is built by the framework composer
  // with the header guards run over every field, generation is rate
  // bounded per sender and in total, and the message travels the
  // ordinary outbound chain carrying the empty reverse path.
  //
  // Nothing is written to anybody unless the message actually left the
  // volume. A removal the volume refused cancelled nothing and the sweep
  // goes on retrying, and a removal that found nothing is a message that
  // had already gone; a report on either is this server telling a sender
  // an operator stopped mail that is still going out or has already
  // arrived. `incomplete` is silent for the same reason from the other
  // side: the message is destroyed, its headers went with it, and what
  // the sender should be told about a half-destroyed entry is not
  // knowable from here.
  //
  // The id is read before the reason and the reason before the notice.
  // An id that is not one this server minted is a typo an operator meets
  // on the way in, and telling them about a reason they did give would
  // send them looking in the wrong place for it.
  //
  // The entry is CLAIMED for the length of this call where it can be,
  // with the same `_claimEntry` the sweep takes before it attempts
  // anything. A cancellation is two unlinks with a suspension between
  // them and the sweep is another writer on the same two files, so an
  // unclaimed removal and a sweep can each finish half of one entry:
  // `_dropSpooled` says what that costs and refuses to put a message
  // back without the claim that makes putting it back safe.
  //
  // An entry another attempt is already holding is still cancelled, and
  // that is deliberate. This is the verb an operator reaches for during
  // an incident, on mail an account somebody else is using is sending;
  // refusing until the attempt in flight has finished would leave that
  // mail going out for as long as a connect takes to time out, and the
  // sweep is running every minute, so "try again" is not a remedy. What
  // changes without the claim is only the answer to a volume that keeps
  // the descriptor: the message stays destroyed rather than being put
  // back, so the verdict is that the entry was destroyed in part, which
  // is the truth of it, instead of a message put back beside a
  // descriptor the attempt has already decided was settled.
  async function queueRemove(id, opts) {
    _assertSpoolId(id, "remove");
    var because = _requireRemovalReason(opts && opts.reason);
    var notice  = _requireRemovalNotice(opts && opts.notice);

    var claim = _claimEntry(id);
    try {
      return await _removeEntry(id, because, notice, claim !== null);
    } finally {
      if (claim !== null) claim.release();
    }
  }

  // The cancellation itself, with the claim already taken or already
  // known to belong to somebody else. Split out so the claim is taken
  // and given back in one place and every path out of the removal passes
  // through it.
  async function _removeEntry(id, because, notice, held) {
    // Read while the message is still there. Everything below this line
    // is about a message that has gone.
    var entry   = notice.status !== null ? await _descriptorIfAny(id) : null;
    var quoted  = notice.status !== null ? await _spooledHeaderBlock(id) : "";

    var verdict = await _dropSpooled(id, {
      restoreOnRefusal:   held,
      notRestoredBecause: "the message is not put back, because another attempt is holding " +
        "this entry and a message put back beside a descriptor that attempt has already " +
        "cleared is one nothing lists and nothing sends",
    });
    verdict.requestedBecause = because;

    var owed     = notice.status;
    var withheld = notice.withheld;
    if (verdict.removed !== true) {
      owed = null;
      // Two states arrive here and they are not the same thing to
      // whoever reads the row. Nothing left the volume, which is a
      // message this server did not cancel. Or the message itself was
      // destroyed and the entry beside it stayed, which is a
      // cancellation that ran and could not be finished: the message can
      // never be sent, and the reason nobody was told is that the
      // headers a report would have quoted went with it. Recording the
      // second as the first says this server did not cancel a message
      // whose body it destroyed.
      withheld = verdict.outcome === "incomplete"
        ? "message-destroyed-in-part"
        : "message-not-cancelled";
    }
    var named = entry !== null &&
      typeof entry.from === "string" && typeof entry.recipient === "string" &&
      entry.recipient.length > 0;
    if (owed !== null && (!named || _isNullSender(entry.from))) {
      // RFC 5321 §6.1 puts the empty reverse path on every report, so a
      // cancelled report ends in silence rather than starting a loop of
      // reports about reports. A message body with no descriptor beside
      // it, and a descriptor a crash left half written, name nobody at
      // all: that is the same silence for a different reason, and the
      // row records the one that is true of it rather than the one that
      // sounds closest.
      owed     = null;
      withheld = named ? "null-return-path" : "no-sender-recorded";
    }

    var reported = false;
    if (owed !== null) {
      var outcome = await bounce({
        to:              entry.from,
        recipient:       entry.recipient,
        reason:          "Delivery of this message was cancelled by the operator of this " +
                         "server before it reached its recipient.",
        statusCode:      owed,
        originalHeaders: quoted,
        origin:          "cancelled",
      });
      reported = !(outcome && outcome.reportUnsent === true);
      if (!reported) withheld = "report-recorded-unsent";
    }

    // Both keys on every verdict. One that carried the erasure alone
    // reads as an erasure everybody was told about.
    verdict.reported = reported;
    verdict.withheld = reported ? null : withheld;
    // Screened on the way out for the reason every other row this module
    // hands back is. The `reason` on a refused removal is what the volume
    // said when it would not give up a file, and `blamepost queue remove`
    // prints it into a console table while the administration page
    // renders the same value.
    return _screenedReportRow(verdict);
  }

  // Take one entry so nothing else attempts it, for a caller driving
  // the spool itself rather than through a sweep. The id is refused
  // before it becomes a path, the same way every other verb refuses it,
  // because this one creates a file under the spool directory and an id
  // from anywhere else would create it somewhere on the volume.
  //
  // Answers a handle with `release()`, or null when somebody else holds
  // the entry. Null is an answer rather than a fault: the entry is being
  // attempted, which is what the caller wanted to happen to it.
  function queueClaim(id) {
    _assertSpoolId(id, "claim");
    return _claimEntry(id);
  }

  // Hand the sender the report this server owes them for giving up.
  // Answers null when the report reached the report path, and the word
  // that says why not when it did not.
  //
  // Everything here happens after the entry has left the volume, so a
  // throw out of it would take the sweep's row with it and leave a
  // message destroyed with nothing recording that nobody was told.
  // `bounce` records its own refusals rather than raising them; what the
  // guard covers is the argument check at its front, which a descriptor
  // carrying an address that check rejects can still reach.
  //
  // The sentence the sender reads says what happened rather than what
  // failed inside this server. It names the number of attempts, because
  // that is the difference between a receiver refusing the message and
  // this server running out of patience with a fault of its own, and it
  // carries what the last attempt met, because on an entry nobody
  // refused that is the only diagnostic there is.
  //
  // `quoted` is the message's own header block, read off the volume by
  // the caller before the pair was taken apart. RFC 3462 §3 puts it in
  // the last part of the report, and it is how a sender tells this
  // report from the others: the recipient and the status are the same on
  // every message they sent to that address, so without it the report
  // says only that "a message" never arrived.
  //
  // The origin is named rather than left to default, because this
  // refusal shares `bounce` with the inbound no-such-mailbox path and an
  // operator filtering the trail for reports that were owed and never
  // sent cannot tell a budget that ran out from an address that does not
  // exist here on anything else in the row.
  async function _tellSenderTheServerGaveUp(entry, attempt, reason, statusCode, quoted) {
    var summary = "no delivery report sent to " + entry.from + " about " + entry.recipient;
    var outcome;
    try {
      outcome = await bounce({
        to:         entry.from,
        recipient:  entry.recipient,
        reason:     "This server tried to deliver this message " + attempt +
                    " time(s) over its retry schedule and gave up. The last attempt " +
                    "ended with: " + _text(reason),
        statusCode:      statusCode,
        originalHeaders: quoted || "",
        origin:          "gave-up",
      });
    } catch (err) {
      _recordUnsentReport({
        origin:     "gave-up",
        informing:  entry.from,
        about:      entry.recipient,
        statusCode: statusCode,
        bytes:      0,
        limit:      "the report could not be composed: " +
                    ((err && err.message) || String(err)),
        summary:    summary,
      });
      return "report-could-not-be-built";
    }
    return outcome && outcome.reportUnsent === true ? "report-recorded-unsent" : null;
  }

  // Give up on one entry, tell whoever there is to tell, and say what
  // happened in the places somebody might be looking: the audit trail,
  // the error log, and the row the sweep hands back.
  //
  // Giving up destroys a message no receiver ever refused. What makes
  // that defensible is that its sender finds out: somebody told "this
  // never arrived" can send it again, and somebody told nothing believes
  // it went. So `notice` carries what is owed and the row records the
  // answer, on the branch that reports and on the branch that does not.
  //
  // `notice.status` is the enhanced status to report under, or null when
  // nobody is owed a report; `notice.withheld` says why not.
  //
  // Two cases withhold rather than report.
  //
  // A message whose body has already gone is one somebody else has
  // settled. The spool writes the message before the descriptor and
  // removes it before the descriptor, so a descriptor with nothing
  // beside it is always a removal that got half way: an operator
  // cancelling the message, or an attempt that delivered it or was
  // permanently refused and then could not take the descriptor off the
  // volume. Each of those has already decided what the sender hears.
  // The browser console writes to them, the command line deliberately
  // does not, and a message a peer accepted must never be reported as
  // failed. None of which is knowable from here, so a report would be a
  // guess, and one of the guesses tells a sender their delivered mail
  // bounced while another undoes a cancellation an operator chose to
  // make quietly.
  //
  // A report has nobody to report to. RFC 5321 §6.1 puts the empty
  // reverse path on every one, so a report that itself runs out of
  // attempts ends in silence rather than starting a loop of reports
  // about reports. `bounce` closes that itself; it is read here as well
  // so the row says which of the two silences this was.
  //
  // The report goes out through `bounce`, which is this module's one
  // report path: the RFC 3464 body is built by the framework composer
  // with the header guards run over every field, generation is rate
  // bounded per sender and in total, and the message travels the
  // ordinary outbound chain carrying the empty reverse path. A report
  // that cannot be built or cannot be sent is recorded there instead,
  // and `describe().reportsUnsent` counts it.
  //
  // The entry leaves the volume BEFORE anything is sent, and that order
  // is load-bearing. A removal the volume refuses raises out of here
  // with nothing written to anybody, which is right: the message is
  // still spooled and the sweep will attempt it again, so a sender told
  // it failed would have been told about mail that is still going out.
  async function _abandon(entry, attempt, reason, notice) {
    // Refused in front of the removal, where refusing still costs
    // nothing. A caller that named neither a status to report under nor
    // a reason for withholding one has not decided what the sender
    // hears, and the row it would leave says a message was destroyed and
    // nobody was told without saying why. Raising after the pair had
    // gone would destroy the message to make the point.
    if (!notice || (!notice.status && !notice.withheld)) {
      throw new TypeError("delivery: giving up on a spooled message needs either the " +
        "enhanced status to report it to its sender under, or the reason no report is " +
        "owed. A message destroyed with neither leaves nobody able to say whether its " +
        "sender was told");
    }
    // Read while the message is still on the volume, which is the only
    // moment its headers exist. RFC 3462 §3 quotes them so the sender
    // can tell which of their messages this report is about, and by the
    // line below there is nothing left to read them from.
    //
    // Read only where a report is going to be composed: this is a full
    // read of the message, and an abandonment that has already decided
    // to tell nobody has nothing to spend it on.
    var quoted = notice.status && !_isNullSender(entry.from)
      ? await _spooledHeaderBlock(entry.id) : "";

    await _dropSpooledOrRaise(entry.id);

    var owed     = notice.status ? notice.status : null;
    var withheld = notice.withheld ? notice.withheld : null;
    var reported = false;
    if (owed !== null && _isNullSender(entry.from)) {
      owed     = null;
      withheld = "null-return-path";
    }
    if (owed !== null) {
      var refusal = await _tellSenderTheServerGaveUp(entry, attempt, reason, owed, quoted);
      reported = refusal === null;
      if (!reported) withheld = refusal;
    }

    b.audit.safeEmit({
      action:   "blamepost.mail.delivery.spool_abandoned",
      outcome:  "failure",
      metadata: {
        id:               entry.id,
        recipient:        _screenForDisplay(entry.recipient),
        attempt:          attempt,
        attemptsRecorded: entry.attemptsRecorded || 0,
        reason:           _screenForDisplay(reason),
        // Whether the sender was written to, and when they were not,
        // why. Both keys on every row: one that recorded the erasure
        // alone reads as an erasure everybody was told about.
        reported:         reported,
        withheld:         withheld,
      },
    });
    log.error("outbound spool entry " + entry.id + " for " +
      _screenForDisplay(entry.recipient) + " abandoned after " + attempt +
      " attempt(s): " + _screenForDisplay(reason) + ". " + (reported
        ? "A delivery report went to " + _screenForDisplay(entry.from) + "."
        : "No delivery report was sent: " + withheld + "."));
    return _screenedReportRow({
      id: entry.id, recipient: entry.recipient, outcome: "abandoned", error: reason,
    });
  }

  // Move one entry's schedule forward without sending it, and give up
  // on it only where giving up is somebody's answer rather than this
  // server's timer.
  //
  // Two things arrive here. An attempt that threw is a local fault: an
  // unreadable body, a resolver that failed, an envelope the composer
  // refuses. A policy question the pinned resolver could not answer is
  // not a fault at all, and the row it reports says `waiting` and
  // carries the enhanced status, because the message is fine and the
  // answer is missing.
  //
  // Neither of them is a receiver refusing this message, so neither ends
  // it on its own. The budget advances, because an entry has to carry a
  // record of how long it has been failing, and reaching the end of that
  // budget ends the message with a report to its sender. That is the
  // trade the budget is for: a sender who hears "this never arrived" can
  // send it again, and one who hears nothing cannot. It is only worth
  // making because the report reaches them.
  //
  // `label` names which of the two this is. Its default is the fault,
  // because that is what a throw means and a caller that says nothing
  // is a throw.
  async function _rescheduleAfterFault(entry, now, err, label) {
    var shape = label || { outcome: "error", reasonCode: entry.reasonCode };
    var reason = (err && err.message) || String(err);
    var attempt = (entry.attempt || 0) + 1;
    var recorded = (entry.attemptsRecorded || 0) + 1;

    // The message itself has gone while the descriptor stayed. That is
    // what an interrupted removal leaves, and what a sweep overlapping
    // an operator's cancellation produces. Nothing an attempt can do
    // brings it back, so retrying only spends the budget against a
    // fault no peer owns, and rewriting the descriptor would put a
    // cancelled message back in the queue an operator just cleared.
    // This is an abandonment that destroys nothing: what it would have
    // sent is already off disk.
    //
    // And nobody is written to about it. Whoever took the message away
    // has already settled what its sender hears, and this side of the
    // pair carries no record of which of them it was.
    if (!b.atomicFile.exists(_bodyPath(entry.id))) {
      return await _abandon(entry, attempt,
        "the spooled message body is missing, so there is nothing left to send: " + reason,
        { status: null, withheld: "message-already-settled-elsewhere" });
    }

    // The budget is spent and no receiver ever refused this message, so
    // the report says the message expired here rather than that an
    // address would not take it.
    if (attempt >= maxAttempts) {
      return await _abandon(entry, attempt, reason, { status: ABANDONED_STATUS });
    }

    // The rewrite clears any hold flag the descriptor carried, which is
    // what releases such an entry back into the ordinary budget.
    var held = false;
    var heldBecause = "";
    var waitMs = backoffMs[Math.min(attempt - 1, backoffMs.length - 1)];
    await _writeDescriptor({
      id:               entry.id,
      from:             entry.from,
      recipient:        entry.recipient,
      attempt:          attempt,
      nextAttemptAt:    now + waitMs,
      reason:           reason,
      reasonCode:       shape.reasonCode,
      requireTls:       entry.requireTls,
      held:             held,
      heldBecause:      heldBecause,
      queuedAt:         entry.queuedAt,
      attemptsRecorded: recorded,
      history:          _appendHistory(entry.history, {
        at:         now,
        outcome:    shape.outcome,
        attempt:    attempt,
        mxHost:     null,
        reason:     reason,
        reasonCode: shape.reasonCode,
        requireTls: entry.requireTls === true,
        held:       held,
      }),
    });
    var row = {
      id:         entry.id,
      recipient:  entry.recipient,
      outcome:    shape.outcome,
      attempt:    attempt,
      reason:     reason,
      reasonCode: shape.reasonCode,
      held:       held,
      retryAt:    now + waitMs,
    };
    // A fault also answers under the key the sweep's own error rows use,
    // because that is what `blamepost queue flush` prints for one.
    if (shape.outcome === "error") row.error = reason;
    return _screenedReportRow(row);
  }

  // Retry every descriptor whose next attempt time has passed. A
  // recipient that answers transiently again keeps its pair on disk
  // with a fresh attempt count, a fresh moment and one more line in its
  // own record, so the framework's retry budget eventually converts it
  // to a permanent failure and the report path runs.
  //
  // The pair comes off disk only once an attempt has finished and there
  // is nothing left to retry: a delivery the peer accepted, a refusal
  // the peer made permanent, or an entry whose message is no longer
  // beside it. Removing it before the attempt would mean a throw from
  // the composer takes the descriptor and the message with it, and the
  // message is then gone from a queue that exists precisely so it
  // survives a failure.
  async function queueRunDue(runOpts) {
    runOpts = runOpts || {};
    var now = typeof runOpts.now === "number" ? runOpts.now : Date.now();
    var entries = await _readEntries({});
    var results = [];

    // Every row a sweep reports is printed by `blamepost queue flush`
    // and rendered on the admin queue page, and it carries an address
    // somebody else chose and a refusal somebody else wrote. One
    // funnel, so a row added later cannot arrive without the screen.
    function report(row) { results.push(_screenedReportRow(row)); }

    for (var i = 0; i < entries.length; i += 1) {
      var entry = entries[i];
      if (entry.unreadable) continue;
      if (!runOpts.force && (entry.nextAttemptAt || 0) > now) continue;
      if (inFlight.has(entry.id)) continue;
      // The claim comes before the attempt and before anything is read,
      // because everything after it either sends the message or
      // rewrites its schedule, and both of those are wrong to do to an
      // entry another process is already holding. An entry somebody
      // else has is reported rather than skipped in silence: an
      // operator who ran a flush and saw nothing happen needs to know
      // the server was working on it, not that the message was
      // overlooked.
      var claim = _claimEntry(entry.id);
      if (claim === null) {
        report({ id: entry.id, recipient: entry.recipient, outcome: "claimed" });
        continue;
      }
      inFlight.add(entry.id);
      try {
        // A descriptor whose recipient is not an address was damaged on
        // the volume, and the message is kept for the operator rather than
        // handed to the composer, which would answer it as a recipient
        // that does not exist and bounce it to the sender.
        if (typeof entry.recipient !== "string" || entry.recipient.length === 0) {
          throw new Error("outbound spool entry " + entry.id + " holds a descriptor that names " +
            "no recipient, so it was not attempted. The message stays in the queue; " +
            "`blamepost queue show " + entry.id + "` prints the entry.");
        }
        // The same question the first attempt asked, asked again over
        // the pinned resolver. A retry is a new decision about whether
        // to put this message on the wire, and answering it from what
        // was known an hour ago is how a receiver's new policy gets
        // ignored for as long as the message is queued.
        var unanswered = await _mtaStsUnanswered(_domainOf(entry.recipient));
        if (unanswered !== null) {
          // The retry never reaches the composer, so its outcome lists
          // never exist. The receiver is owed this one all the same:
          // an MTA-STS record their sender cannot read is exactly what
          // RFC 8460 §4.3 has a policy-failure type for.
          await _observeTlsRpt(entry.recipient, {
            delivered:  false,
            held:       false,
            mxHost:     null,
            reason:     unanswered.reason,
            reasonCode: unanswered.reasonCode,
          });
          report(await _rescheduleAfterFault(entry, now, new Error(unanswered.reason), {
            outcome:    "waiting",
            reasonCode: unanswered.reasonCode,
          }));
          continue;
        }
        var body = await b.atomicFile.read(_bodyPath(entry.id), {
          maxBytes: MAX_SPOOLED_BODY_BYTES,
        });
        var wire = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
        // Normalized for the same reason `send` normalizes it: a
        // descriptor can spell the empty reverse path `<>`, and handing
        // that literal over reaches the address guard rather than the
        // wire.
        var entryFrom = _isNullSender(entry.from) ? REPORT_REVERSE_PATH : entry.from;
        var outcome = await deliver({
          from:       entryFrom,
          to:         [entry.recipient],
          rfc822:     wire,
          requireTls: entry.requireTls === true,
          attempt:    entry.attempt || 0,
        });
        var recorded = (entry.attemptsRecorded || 0) + 1;
        var stillWaiting = _settleVerdicts(outcome);
        await _observeOutcome(outcome);
        var accepted = (outcome.delivered || [])[0] || null;
        var refused  = (outcome.failed || [])[0] || null;
        if (stillWaiting.length > 0 && !b.atomicFile.exists(_bodyPath(entry.id))) {
          // The entry was taken out of the spool while this attempt was
          // in flight, which is what an operator cancelling a message
          // from the admin page or the command line does. The message
          // was already in memory when that happened, so writing the
          // descriptor back would put a cancelled message into the queue
          // the operator had just cleared. Report it and leave the spool
          // alone.
          b.audit.safeEmit({
            action:   "blamepost.mail.delivery.spool_removed_mid_attempt",
            outcome:  "success",
            metadata: { id: entry.id, recipient: _screenForDisplay(entry.recipient) },
          });
          report({ id: entry.id, recipient: entry.recipient, outcome: "removed" });
        } else if (stillWaiting.length > 0) {
          // The descriptor alone: only the schedule and the record
          // changed, and rewriting the body would copy the whole message
          // again on every retry for no gain.
          await _writeDescriptor({
            id:               entry.id,
            from:             entryFrom,
            recipient:        entry.recipient,
            attempt:          stillWaiting[0].attempt,
            nextAttemptAt:    now + stillWaiting[0].retryAfterMs,
            reason:           stillWaiting[0].reason,
            reasonCode:       stillWaiting[0].reasonCode,
            requireTls:       entry.requireTls === true,
            queuedAt:         entry.queuedAt,
            attemptsRecorded: recorded,
            history:          _appendHistory(entry.history, {
              at:         now,
              outcome:    "deferred",
              attempt:    stillWaiting[0].attempt,
              mxHost:     stillWaiting[0].mxHost,
              reason:     stillWaiting[0].reason,
              reasonCode: stillWaiting[0].reasonCode,
              requireTls: entry.requireTls === true,
            }),
          });
          report({
            id:         entry.id,
            recipient:  entry.recipient,
            outcome:    "waiting",
            attempt:    stillWaiting[0].attempt,
            mxHost:     stillWaiting[0].mxHost || null,
            reason:     stillWaiting[0].reason,
            reasonCode: stillWaiting[0].reasonCode,
            retryAt:    now + stillWaiting[0].retryAfterMs,
          });
        } else if (accepted) {
          await _dropSpooledOrRaise(entry.id);
          report({
            id:        entry.id,
            recipient: entry.recipient,
            outcome:   "delivered",
            attempt:   entry.attempt || 0,
            mxHost:    accepted.mxHost || null,
          });
        } else {
          // Permanently refused. Nothing more is going to happen to the
          // message, so the pair goes, but not before whoever sent it
          // is accounted for: a refusal the composer could not build a
          // report from would otherwise take the message off disk with
          // nobody told.
          _noteUnreportedFailures(outcome.failed, entryFrom);
          await _dropSpooledOrRaise(entry.id);
          report({
            id:         entry.id,
            recipient:  entry.recipient,
            outcome:    "failed",
            attempt:    entry.attempt || 0,
            mxHost:     (refused && refused.mxHost) || null,
            reason:     refused && refused.reason,
            reasonCode: refused && refused.reasonCode,
          });
        }
      } catch (err) {
        // One recipient's fault must never stop the sweep, and it must
        // never cost the message either.
        var recovery;
        try {
          recovery = await _rescheduleAfterFault(entry, now, err);
        } catch (spoolErr) {
          // The spool itself refused a write, which is a disk problem
          // rather than a delivery one. The pair stays as it is and the
          // next sweep tries again; both errors go into the row so an
          // operator sees the disk one, which is the actionable half.
          recovery = {
            id:        entry.id,
            recipient: entry.recipient,
            outcome:   "error",
            error:     ((err && err.message) || String(err)) + "; rescheduling failed: " +
                       ((spoolErr && spoolErr.message) || String(spoolErr)),
          };
        }
        report(recovery);
      } finally {
        inFlight.delete(entry.id);
        claim.release();
      }
    }
    // A forced drain is an operator act and takes a row, exactly as
    // cancelling a message off the same spool does. The ordinary drain
    // does not: it is this server running, once a minute, forever, and a
    // row per tick would bury the trail an incident review reads under
    // its own heartbeat. `force` is what separates them, and it is set by
    // the two surfaces an operator drives and by nothing else, so the
    // row is filed here rather than on each of them and both spell the
    // act the same way.
    //
    // Recorded after the sweep so it says what the sweep touched. A row
    // written first would claim a run that a fault part way through
    // turned into something else, and the count is the part an operator
    // asked the question for: pressing the button and having nothing
    // happen is the answer they are looking for as often as not.
    //
    // `safeEmit` is drop-silent by design: the attempts have already been
    // made, and a trail that cannot be written is not a reason to report
    // a finished drain as a failure.
    if (runOpts.force === true) {
      b.audit.safeEmit({
        action:   "blamepost.mail.queue.run_forced",
        outcome:  "success",
        actor:    auditActor.current(),
        metadata: { touched: results.length, waiting: entries.length },
      });
    }
    return { ran: results.length, results: results };
  }

  // ---- TLS-RPT: composing and sending what accumulated ------------------

  // One accumulated failure, as RFC 8460 §4.4 writes it. `mxHost` is
  // omitted rather than sent as null when the framework never named a
  // receiver, because an absent optional field is what a reader expects
  // and a null is a value they have to special-case. `sending-mta-ip`
  // and `receiving-ip` are absent for the same reason: no socket was
  // opened, so this server has nothing truthful to put in them.
  //
  // A reason carrying an address is dropped rather than sent. The
  // reasons that reach a failure row are written by the transport and
  // by the policy chain, and none of the reachable ones names a
  // mailbox: they name a status, a mail exchanger or a domain. That is
  // an enumeration of text this server does not own, though, and a
  // report is the one place where being wrong about it hands a
  // stranger an account's address. Refusing the whole value on the one
  // character an address cannot do without costs nothing real and
  // does not need the enumeration to stay correct.
  function _tlsRptFailureDetail(row) {
    var detail = {
      "result-type":          row.resultType,
      "failed-session-count": row.count,
    };
    if (row.mxHost) detail["receiving-mx-hostname"] = row.mxHost;
    if (row.reason && String(row.reason).indexOf("@") === -1) {
      detail["failure-reason-code"] = row.reason;
    }
    return detail;
  }

  // RFC 8460 §5.3 names the report file after the two domains and the
  // period, so a receiver filing thousands of them can tell one from
  // another without opening it.
  function _tlsRptFilename(domain, record, now) {
    return hostname + "!" + domain + "!" +
      Math.floor(record.since / TIME.seconds(1)) + "!" +
      Math.floor(now / TIME.seconds(1)) + ".json.gz";
  }

  // The report as mail, per RFC 8460 §5.3.
  //
  // The subject is built here rather than taken from the one the
  // framework prepares, because that one puts the submitter's name in
  // the Report Domain slot where §5.3 puts the receiver's, and a
  // receiver filing by that header would file every report under the
  // sender.
  //
  // Where a receiver's report is owed, read through the one derivation
  // that decides what an address means here.
  //
  // It came out of somebody else's DNS record, so the spelling is theirs
  // and `rua=mailto:tls@example.com.` is a legitimate thing for them to
  // publish: RFC 1035 §2.3.1 makes the absolute form the same name. It
  // becomes both the envelope recipient and a header line, and only one
  // spelling is a forward path RFC 5321 §4.1.2 admits, so what leaves is
  // the derived name rather than the published one. A record naming
  // nothing readable is refused, and the report goes to whichever other
  // destination the receiver published.
  function _tlsRptDestination(published, domain) {
    var derived = address.parse(published);
    if (!derived.ok) {
      throw new TypeError("the rua destination " + JSON.stringify(String(published)) +
        " published at _smtp._tls." + domain + " is not a usable address");
    }
    return derived.written;
  }

  // The destination is derived by the caller, which is also what puts it
  // in the envelope, so the header a receiver files by and the path it
  // was handed name one mailbox in one spelling.
  function _tlsRptMailMessage(prepared, reportTo, domain, report, record, now) {
    var subject = "Report Domain: " + domain + " Submitter: " + hostname +
      " Report-ID: <" + String(report["report-id"] || "") + ">";
    var body = Buffer.isBuffer(prepared.body) ? prepared.body : Buffer.from(String(prepared.body));
    var encoded = body.toString("base64").replace(/(.{76})/g, "$1\r\n");
    return Buffer.from([
      "From: " + postmaster,
      "To: " + reportTo,
      "Subject: " + b.safeBuffer.foldHeaderText(subject, " "),
      "Date: " + new Date(now).toUTCString(),
      "Message-ID: <tlsrpt-" + b.crypto.generateToken(12) + "@" + hostname + ">",
      "MIME-Version: 1.0",
      "Auto-Submitted: auto-generated",
      "TLS-Report-Domain: " + domain,
      "TLS-Report-Submitter: " + hostname,
      "Content-Type: application/tlsrpt+gzip",
      "Content-Disposition: attachment; filename=\"" +
        _tlsRptFilename(domain, record, now) + "\"",
      "Content-Transfer-Encoding: base64",
      "",
      encoded,
      "",
    ].join("\r\n"), "utf8");
  }

  // What one reading of a domain's accumulator carried, in the shape
  // `_tlsRptSettle` subtracts.
  //
  // Derived in one place because every caller that acts on a reading
  // afterwards has to take back exactly what it judged and nothing else.
  // Two derivations of "what this run saw" is two answers about how much
  // to subtract, and the one that is too large erases observations
  // nobody has reported yet.
  function _tlsRptCarried(record) {
    var carried = { successful: record.successful, byKey: Object.create(null) };
    for (var i = 0; i < record.failures.length; i += 1) {
      carried.byKey[record.failures[i].key] = record.failures[i].count;
    }
    return carried;
  }

  // Take one domain's accumulator off the volume, but only while the
  // reading that decided it still describes what is there.
  //
  // Every decision to remove the whole file is made from a record read
  // before the write chain for that domain was entered, and
  // `_observeTlsRpt` writes into that chain from the delivery path
  // whenever a session with that receiver ends. Handing the removal to
  // the chain puts it BEHIND whatever is already queued, so the file the
  // decision described is not the file the removal lands on: an
  // accumulator judged to be carrying nothing gains the first failure
  // this server has ever recorded against that receiver, and the removal
  // takes it. Nothing else holds that failure. A report is composed from
  // this file and from nowhere else, so the receiver is never told, and
  // no error is raised anywhere.
  //
  // So the reading is taken AGAIN inside the turn that acts, the way
  // `_tlsRptSettle` above takes it, and the removal stands down when it
  // no longer describes what is on disk. The next run reads the file and
  // reports it.
  async function _tlsRptDropWhenStill(name, stillDroppable) {
    await _tlsRptSerial(name, async function () {
      var current = await _readTlsRptRecord(name);
      if (!stillDroppable(current)) return;
      await _dropTlsRptRecord(name);
    });
  }

  // Whether an accumulator holds nothing anybody is owed. A file in that
  // state is read on every run and composes no report, so it goes.
  function _tlsRptHoldsNothing(record) {
    return record === null || (record.successful === 0 && record.failures.length === 0);
  }

  // Whether an accumulator agrees with the name it is filed under. A
  // file that does not is not evidence of anything: a report addressed
  // on the strength of it would name a receiver this server never
  // measured.
  function _tlsRptNameDisagrees(record, name) {
    if (record === null) return true;
    var folded = address.parseDomain(record.domain);
    return !folded.ok || folded.domain !== name;
  }

  // Take the counts a report carried back out of the accumulator,
  // rather than removing the file.
  //
  // Subtracting is what keeps a delivery that happened while the report
  // was in flight. Removing the file would discard it, and re-reading
  // and rewriting the whole file would discard it in a wider window.
  // Nothing is subtracted until a report has actually reached somebody,
  // so a submission that failed leaves every count where it was.
  async function _tlsRptSettle(domain, reported) {
    await _tlsRptSerial(domain, async function () {
      var current = await _readTlsRptRecord(domain);
      if (current === null) return;
      current.successful = Math.max(0, current.successful - reported.successful);
      var kept = [];
      for (var i = 0; i < current.failures.length; i += 1) {
        var row = current.failures[i];
        var already = reported.byKey[row.key] || 0;
        var left = (row.count || 0) - already;
        if (left > 0) {
          row.count = left;
          kept.push(row);
        }
      }
      current.failures = kept;
      if (current.successful === 0 && kept.length === 0) {
        await _dropTlsRptRecord(domain);
        return;
      }
      await _writeTlsRptRecord(current);
    });
  }

  async function _tlsRptReportOn(record, now, runOpts) {
    var domain = record.domain;
    // The start and the end are one pair, and the pair is what a
    // receiver reads. `_readTlsRptRecord` already refuses a start later
    // than the moment it read the file, and the reasoning for that is
    // written there. This is the same rule stated against the moment the
    // report is actually built, so the two values on the wire cannot run
    // backwards whatever the run was handed for its clock.
    if (record.since > now) record = Object.assign({}, record, { since: now });
    var where;
    try { where = await posture.tlsRptEndpoint(domain, { dnsLookup: _tlsRptLookup() }); }
    catch (err) {
      where = { state: "unsettled", rua: [], why: (err && err.message) || String(err) };
    }

    // A receiver whose record could not be read is not a receiver that
    // published nothing. The counts stay and the next run asks again.
    if (where.state === "unsettled") {
      b.audit.safeEmit({
        action:   "blamepost.mail.delivery.tls_rpt_endpoint_unsettled",
        outcome:  "failure",
        metadata: { domain: _screenForDisplay(domain), reason: _screenForDisplay(where.why) },
      });
      return {
        domain:  domain,
        outcome: "unsettled",
        reason:  _screenForDisplay(where.why),
      };
    }

    // Nobody asked, so nothing this run judged is owed and none of it is
    // kept. Taken back out of the accumulator rather than removed with
    // it: reading the zone is a lookup, and a session with the same
    // receiver can fail while it runs. That failure was never judged
    // here, and the answer this branch acted on can be a different
    // answer by the next run, which is a receiver that publishes a
    // TLS-RPT record tomorrow being owed what failed today.
    if (where.state === "absent") {
      await _tlsRptSettle(domain, _tlsRptCarried(record));
      return { domain: domain, outcome: "no-endpoint" };
    }

    var reported = _tlsRptCarried(record);

    // One entry per policy the period's attempts were actually judged
    // under. RFC 8460 §4.4 carries an array of them for this: a domain
    // that publishes an MTA-STS policy and TLSA records is refused under
    // one or the other, and putting a DANE refusal inside the MTA-STS
    // entry sends them to read a document that had nothing to do with
    // it.
    //
    // The domain's own type leads, and it is the entry the successful
    // sessions belong to: nothing records which policy covered a
    // delivery that worked, and what this server read for the domain is
    // the honest answer to that. An entry holding neither a success nor
    // a failure is left out rather than sent as a row of zeros.
    var groups = Object.create(null);
    var order = [record.policyType];
    var failureCount = 0;
    groups[record.policyType] = { count: 0, details: [] };
    for (var i = 0; i < record.failures.length; i += 1) {
      var row = record.failures[i];
      var rowType = _tlsRptPolicyTypeOf(row, record.policyType);
      if (groups[rowType] === undefined) {
        groups[rowType] = { count: 0, details: [] };
        order.push(rowType);
      }
      failureCount += row.count;
      groups[rowType].count += row.count;
      groups[rowType].details.push(_tlsRptFailureDetail(row));
    }

    var policies = [];
    for (var g = 0; g < order.length; g += 1) {
      var type = order[g];
      var group = groups[type];
      var successes = type === record.policyType ? record.successful : 0;
      if (successes === 0 && group.details.length === 0) continue;
      policies.push({
        type:         type,
        // The document is the MTA-STS policy this server read, so it is
        // quoted back only in the entry that is about it.
        policyString: type === TLS_RPT_POLICY_STS ? record.policyString : [],
        domain:       domain,
        mxHosts:      record.mxHosts,
        successCount: successes,
        failureCount: group.count,
        failures:     group.details,
      });
    }

    var report = b.network.smtp.tlsRpt.recordShape({
      organization: hostname,
      contact:      postmaster,
      datestart:    new Date(record.since).toISOString(),
      dateend:      new Date(now).toISOString(),
      policies:     policies,
    });

    var submission = await b.network.smtp.tlsRpt.submit(report, {
      rua:        where.rua,
      httpClient: runOpts.httpClient === undefined
        ? tlsRptSubmitOpts.httpClient : runOpts.httpClient,
      timeoutMs:  runOpts.timeoutMs === undefined
        ? tlsRptSubmitOpts.timeoutMs : runOpts.timeoutMs,
    });

    var accepted = 0;
    var queued = 0;
    var refused = [];
    // Where a receiver published its report address in a spelling this
    // server did not send to. A `rua=mailto:` value ending in the root
    // dot is the ordinary case: that is a legal absolute name and the
    // framework folds the dot so the report can be addressed at all.
    // The report goes to the right mailbox either way, so nothing here
    // is a fault to refuse. What was missing is the record. A receiver
    // that later says no report ever arrived is asking which address
    // this server wrote to, and without this the trail cannot answer.
    var respelled = [];
    var rows = (submission && submission.results) || [];
    for (var r = 0; r < rows.length; r += 1) {
      var entry = rows[r];
      if (entry.kind === "https") {
        if (entry.ok === true) { accepted += 1; continue; }
        refused.push(String(entry.uri) + ": " + String(entry.error || "refused"));
        continue;
      }
      // A prepared body is not a sent report. The framework hands it
      // back with ok true because it validated the destination, and
      // reading that as delivery is exactly how a capability comes to be
      // half claimed. It counts once it is on the outbound path.
      if (entry.kind === "mailto" && entry.mailto) {
        try {
          // Derived once, so the envelope this hands over and the header
          // the receiver files by cannot be two spellings of one name.
          var reportTo = _tlsRptDestination(entry.mailto.to, domain);
          await send({
            from:   postmaster,
            to:     [reportTo],
            rfc822: _tlsRptMailMessage(entry.mailto, reportTo, domain, report, record, now),
          });
          queued += 1;
          // Recorded after the send rather than before it, so the row
          // describes a report that actually went out.
          if (entry.mailto.published !== reportTo) {
            respelled.push(String(entry.mailto.published) + " -> " + String(reportTo));
          }
        } catch (err) {
          refused.push(String(entry.uri) + ": " + ((err && err.message) || String(err)));
        }
        continue;
      }
      refused.push(String(entry.uri) + ": " + String(entry.error || "unusable rua entry"));
    }

    if (accepted === 0 && queued === 0) {
      tlsRptUnsent += 1;
      b.audit.safeEmit({
        action:   "blamepost.mail.delivery.tls_rpt_unsent",
        outcome:  "failure",
        metadata: {
          domain:   _screenForDisplay(domain),
          reportId: _screenForDisplay(String(report["report-id"] || "")),
          reason:   _screenForDisplay(refused.join("; ")),
        },
      });
      log.error("the TLS report owed to " + _screenForDisplay(domain) +
        " reached none of the destinations it published: " + _screenForDisplay(refused.join("; ")));
      return {
        domain:  domain,
        outcome: "unsent",
        reason:  _screenForDisplay(refused.join("; ")),
      };
    }

    await _tlsRptSettle(domain, reported);
    if (accepted > 0) tlsRptSubmitted += 1;
    if (queued > 0) tlsRptQueued += 1;
    b.audit.safeEmit({
      action:   "blamepost.mail.delivery.tls_rpt_sent",
      outcome:  "success",
      metadata: {
        domain:     _screenForDisplay(domain),
        reportId:   _screenForDisplay(String(report["report-id"] || "")),
        submitted:  accepted,
        queued:     queued,
        successful: record.successful,
        failed:     failureCount,
        // Empty when every report went to the address exactly as its
        // receiver published it, which is the ordinary case. Always
        // present, so a row that predates the field is told apart from
        // one that had nothing to report.
        respelled:  _screenForDisplay(respelled.join("; ")),
      },
    });
    return {
      domain:     domain,
      outcome:    accepted > 0 ? "submitted" : "queued",
      submitted:  accepted,
      queued:     queued,
      successful: record.successful,
      failed:     failureCount,
      reportId:   String(report["report-id"] || ""),
    };
  }

  /**
   * @primitive blamepost.mail.delivery.tlsRpt
   * @signature delivery.tlsRpt
   * @since     0.1.0
   * @status    stable
   * @spec      RFC 8460
   * @related   blamepost.mail.posture.tlsRptEndpoint, blamepost.mail.delivery.send
   *
   * The reports this server owes the domains it delivers to. `observed`
   * reads what has accumulated, one row per receiving domain. `run`
   * composes a report for each of them and sends it where that domain's
   * zone says to send it.
   *
   * `run` reports one row per domain it considered, with an `outcome`
   * of `submitted`, `queued`, `no-endpoint`, `unsettled` or `unsent`.
   * `submitted` means an HTTPS destination accepted the report and
   * `queued` means it went onto the outbound path as mail, which is
   * where RFC 8460 §5.3 puts a `mailto:` destination. `no-endpoint` is
   * a domain that publishes no TLS-RPT record, whose observations are
   * dropped because nobody asked for them. `unsettled` is a lookup that
   * could not complete, which keeps them, because a resolver that was
   * briefly unreachable is not a receiver waiving a report. `unsent` is
   * a published destination that refused it, which keeps them too.
   *
   * Only what a report carried is taken back out of the accumulator, so
   * a delivery that happened while the report was in flight survives
   * into the next one.
   *
   * @opts
   *   now:        number,   // the moment the period ends; default now
   *   httpClient: object,   // HTTPS submission client; the framework's own when omitted
   *   timeoutMs:  number,   // per destination submission timeout
   *
   * @example
   *   var run = await delivery.tlsRpt.run();
   *   run.results.filter(function (r) { return r.outcome === "unsent"; });
   */
  async function tlsRptObserved() {
    var files = _tlsRptFiles();
    var out = [];
    for (var i = 0; i < files.length; i += 1) {
      var record = await _readTlsRptRecord(_tlsRptDomainInFile(files[i].name));
      if (record === null) continue;
      var failed = 0;
      var rows = [];
      for (var f = 0; f < record.failures.length; f += 1) {
        var row = record.failures[f];
        failed += row.count;
        rows.push({
          resultType: row.resultType,
          // The policy the report files this failure under, which is
          // not always the one this server read for the domain: a
          // refusal over the receiver's TLSA records belongs to those
          // records whatever else the domain publishes.
          policyType: _tlsRptPolicyTypeOf(row, record.policyType),
          mxHost:     row.mxHost,
          count:      row.count,
          reason:     _screenForDisplay(row.reason || ""),
        });
      }
      out.push({
        domain:     record.domain,
        since:      record.since,
        policyType: record.policyType,
        mxHosts:    record.mxHosts.slice(),
        successful: record.successful,
        failed:     failed,
        failures:   rows,
      });
    }
    out.sort(function (x, y) { return x.domain < y.domain ? -1 : (x.domain > y.domain ? 1 : 0); });
    return out;
  }

  async function tlsRptRun(runOpts) {
    runOpts = runOpts || {};
    var now = typeof runOpts.now === "number" ? runOpts.now : Date.now();
    var files = _tlsRptFiles();
    var results = [];
    for (var i = 0; i < files.length; i += 1) {
      var name = _tlsRptDomainInFile(files[i].name);
      var record = await _readTlsRptRecord(name);
      // A file that cannot be read, or whose recorded domain is not the
      // one its name claims, is not evidence of anything. It goes rather
      // than being carried into a report addressed on the strength of it.
      //
      // Removed by the name the listing gave rather than by anything
      // read out of the file, and through the one function that builds a
      // path under this directory. The listing filtered on the extension
      // that function appends, so the two agree by construction and
      // there is no second way in here. The reading is taken again
      // inside the removal, because a session with this receiver can end
      // while this loop is working through the directory and the file it
      // writes is a valid record under the same name.
      if (_tlsRptNameDisagrees(record, name)) {
        await _tlsRptDropWhenStill(name, function (current) {
          return _tlsRptNameDisagrees(current, name);
        });
        continue;
      }
      var domain = address.parseDomain(record.domain).domain;
      if (_tlsRptHoldsNothing(record)) {
        await _tlsRptDropWhenStill(domain, _tlsRptHoldsNothing);
        continue;
      }
      results.push(await _tlsRptReportOn(record, now, runOpts));
    }
    tlsRptLastRunAt = now;
    return { ran: results.length, results: results };
  }

  /**
   * @primitive blamepost.mail.delivery.start
   * @signature delivery.start()
   * @since     0.1.0
   * @status    stable
   * @spec      internal (design: spool sweep lifecycle)
   * @related   blamepost.mail.delivery.queue
   *
   * Arm the sweep timer so spooled recipients are retried as they come
   * due, and the reporting timer so the TLS reports this server owes
   * its peers are sent on their period. Calling it twice is harmless;
   * the second call keeps the first timers. A process that only sends,
   * such as one CLI invocation, never calls this and so never holds the
   * event loop open.
   *
   * @example
   *   delivery.start();
   */
  function start() {
    if (!tlsRptTimer) {
      tlsRptTimer = b.safeAsync.repeating(function () {
        return tlsRptRun({});
      }, tlsRptIntervalMs, {
        unref: true,
        name:  "blamepost-tls-rpt-report",
        onError: function (err) {
          // Hot path observability sink. A report that could not be
          // composed is recorded and the timer keeps running; throwing
          // here would take the process down over one receiver's zone.
          try {
            b.audit.safeEmit({
              action:   "blamepost.mail.delivery.tls_rpt_run_failed",
              outcome:  "failure",
              metadata: { error: _screenForDisplay((err && err.message) || String(err)) },
            });
          } catch (_e) {
            // allow:swallow-unverified the audit sink is the reporting
            // path itself and swallows inside safeEmit, and this handler
            // runs on a repeating timer where a throw ends the process.
          }
        },
      });
    }
    if (sweepTimer) return sweepTimer;
    sweepTimer = b.safeAsync.repeating(function () {
      return queueRunDue({});
    }, sweepIntervalMs, {
      unref: true,
      name:  "blamepost-outbound-sweep",
      onError: function (err) {
        // Hot path observability sink. A sweep failure is recorded and
        // the timer keeps running; throwing here would take the process
        // down over one unreachable peer.
        try {
          b.audit.safeEmit({
            action:   "blamepost.mail.delivery.sweep_failed",
            outcome:  "failure",
            metadata: { error: _screenForDisplay((err && err.message) || String(err)) },
          });
        } catch (_e) {
          // allow:swallow-unverified the audit sink is the reporting path
          // itself and swallows inside safeEmit, and this handler runs on
          // the retry timer where a throw ends the process and the queue
          // with it.
        }
      },
    });
    return sweepTimer;
  }

  /**
   * @primitive blamepost.mail.delivery.stop
   * @signature delivery.stop()
   * @since     0.1.0
   * @status    stable
   * @spec      internal (design: spool sweep lifecycle)
   * @related   blamepost.mail.delivery.start
   *
   * Disarm the sweep and reporting timers. Shutdown calls it before the
   * listeners drain so no new outbound attempt starts while connections
   * close. Spooled entries stay on disk and are picked up by the next
   * boot, and so do the observations a report has not carried yet.
   *
   * @example
   *   delivery.stop();
   */
  function stop() {
    if (tlsRptTimer) {
      tlsRptTimer.stop();
      tlsRptTimer = null;
    }
    if (!sweepTimer) return;
    sweepTimer.stop();
    sweepTimer = null;
  }

  function describe() {
    return {
      hostname:        hostname,
      postmaster:      postmaster,
      spoolDir:        spoolDir,
      requireTls:      requireTls,
      sweepIntervalMs: sweepIntervalMs,
      sweeping:        sweepTimer !== null,
      waiting:         queueCount(),
      // How full the spool is and what it is allowed to hold. It is the
      // number to watch on a server whose outbound path is stalled:
      // `messages` climbing toward `maxMessages` is the moment before
      // account holders start being refused, and `refused` above zero
      // says they already are.
      //
      // `forwarding` is the depth at which that stops being a forecast.
      // It is the ceiling `_admitToSpool` already applies to a message
      // arriving for an alias, published rather than recomputed, so a
      // reader can tell "this spool is filling" from "this spool has
      // begun refusing mail it would otherwise have taken". Anything
      // that has to decide whether a queue is in trouble wants that
      // number and has no other way to know it: `maxMessages` is the
      // last boundary rather than the first, and a reader deriving the
      // share for itself would be a second arithmetic that can disagree
      // with the one the spool acts on and still look right.
      spool:           Object.assign(queueCapacity(), {
        forwarding: { maxMessages: strangerMessages, maxBytes: strangerBytes },
      }),
      // The transport security this server demands of the peers it
      // delivers to, echoed back so an operator reading a stalled queue
      // can see the posture that produced it.
      policy: {
        mtaSts:          stsMode,
        dane:            daneMode,
        dnssecValidated: deliverPolicy.dnssecValidated === true,
        maxAttempts:     maxAttempts,
        backoffMs:       backoffMs.slice(),
      },
      // How long one outbound attempt waits for the recipient domain's
      // MX answer and for the peer itself. Reported beside the policy
      // because the two decide the same thing between them: a queue
      // standing still is either a posture refusing to hand a message
      // over or a wait too short for the receiver in front of it, and a
      // reader holding only the posture cannot tell those apart. A wait
      // reported as null is one nobody wrote, and the composer's own
      // applies.
      timeouts: {
        mxLookupMs: outboundTimeouts.mxLookupMs,
        perHostMs:  outboundTimeouts.perHostMs,
      },
      // Reports owed and not sent since this process started, which is
      // the ones the generation bound refused. Any number above zero
      // means senders are not hearing about undeliverable mail; the
      // error log carries who and about what. A number that keeps
      // climbing is a run of mail to addresses that do not exist here,
      // and the bound doing its job.
      reportsUnsent:   reportsUnsent,
      // Whether a message can reach a peer at all, and if not, what to
      // do about it. `queue.held()` is the part of the spool waiting on
      // something other than a receiver's verdict, which is the entries
      // whose descriptors carry the hold flag.
      wireDelivery: {
        available: wireDelivery.available,
        reason:    wireDelivery.reason,
        issues:    wireDelivery.issues.slice(),
      },
      // The reports this server owes the domains it delivers to.
      // `domainsObserved` is how many receivers have something waiting
      // to be told; `reportsUnsent` above zero means a receiver asked
      // for reports and is not getting them, and the error log carries
      // which receiver and which destination refused.
      tlsRpt: {
        reportingIntervalMs: tlsRptIntervalMs,
        reporting:           tlsRptTimer !== null,
        domainsObserved:     _tlsRptFiles().length,
        reportsSubmitted:    tlsRptSubmitted,
        reportsQueued:       tlsRptQueued,
        reportsUnsent:       tlsRptUnsent,
        lastRunAt:           tlsRptLastRunAt,
      },
      // The reports other people have sent back about the mail this
      // server sends on its own behalf. `byAction.failed` above zero is
      // the number that matters: something this server publishes an
      // obligation to send is not arriving, and `recent` names the
      // address it could not reach. `unreadable` above zero says
      // somebody is reporting and this server cannot read what they
      // sent, which needs the same attention for the opposite reason.
      //
      // Nothing here is bound to a message this server actually sent.
      // Anyone can compose a report and address it to this identity, so
      // these are counts of what arrived rather than a record of what
      // happened, and no part of the outbound path reads them.
      reports: {
        identity:   reportingIdentity,
        examined:   reportsExamined,
        read:       reportsRead,
        unreadable: reportsUnreadable,
        recipients: reportedRecipients,
        byAction:   _reportedActions(),
        lastReadAt: reportsLastReadAt,
        recent:     recentReportsRead(),
      },
    };
  }

  return {
    send:     send,
    bounce:   bounce,
    queue: {
      list:     queueList,
      count:    queueCount,
      held:     queueHeld,
      show:     queueShow,
      runDue:   queueRunDue,
      remove:   queueRemove,
      capacity: queueCapacity,
      orphans:  queueOrphans,
      // Two answers to one question, and which one a caller wants is
      // decided by whether it is going to write. `admits` reports; it
      // holds nothing and its answer is spent the moment anybody else
      // asks. `reserve` answers the same thing and KEEPS the room until
      // the caller releases it, which is what a caller with a mailbox
      // write and a conversation ahead of it needs, and what stops two
      // connections crossing the last slot together.
      admits:   _admitToSpool,
      reserve:  _holdSpool,
      claim:    queueClaim,
    },
    tlsRpt: {
      observed: tlsRptObserved,
      run:      tlsRptRun,
    },
    reports: {
      receive: receiveReport,
      observe: observeFiled,
      recent:  recentReportsRead,
    },
    start:    start,
    stop:     stop,
    describe: describe,
  };
}

module.exports = {
  create:                 create,
  wireDeliveryStatus:     wireDeliveryStatus,
  daneEnforcementStatus:  daneEnforcementStatus,
  // How a failed recipient outcome is read as an RFC 8460 §4.3 result
  // type, exported so the reading can be measured on its own. One of the
  // conditions it separates needs the receiver's own policy document,
  // which the vendored composer fetches over HTTPS from a host no test
  // can stand up, so there is no other point at which that condition can
  // be put beside the one it has to be told apart from.
  tlsRptResultFor:        tlsRptResultFor,
  // The refusal a full outbound queue makes, exported so the listeners
  // recognize it rather than matching the sentence it carries.
  SPOOL_FULL_CODE:        SPOOL_FULL_CODE,
  // How long a message body may be on disk without a descriptor before
  // it counts as one nothing claims. Exported so a reader of the
  // reconciliation reads the window this module actually applies rather
  // than a second copy of the number.
  SPOOL_SETTLE_MS:        SPOOL_SETTLE_MS,
};
