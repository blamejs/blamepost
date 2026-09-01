// SPDX-License-Identifier: Apache-2.0
// Copyright (c) blamejs contributors
"use strict";
// Emit a NIST SP 800-218 (SSDF) / OMB M-22-18 producer self-attestation as
// a machine-readable JSON artifact for a given release.
//
// Run via:
//   node scripts/generate-ssdf-attestation.js \
//     --version 0.1.0 --commit <sha> --date 2026-07-04T00:00:00Z \
//     > ssdf-attestation.json
//
//   # or with --out:
//   node scripts/generate-ssdf-attestation.js --commit <sha> --date <ts> \
//     --out ssdf-attestation.json
//
// Operator-run at release time; the artifact is suitable for attaching to
// the GitHub release. Downstream consumers who require SSDF
// supplier-compliance evidence (OMB M-22-18 / M-23-16 self-attestation)
// obtain it from the producer.
//
// WHAT THIS IS, AND WHAT IT IS NOT.
//   This is a PRODUCER SELF-ATTESTATION, the machine-readable companion to
//   the CISA / OMB "Secure Software Development Attestation Form". It is the
//   producer's own assertion that the SSDF practices below are in force,
//   mapped to this project's REAL implementing controls. It is NOT a
//   third-party audit, NOT a FedRAMP authorization, and NOT a CMVP
//   validation. Its trust derives from the release boundary that carries
//   it: the SSH-signed tag, the SLSA L3 npm provenance, and the
//   Sigstore-keyless SBOM signature. The trust roots documented in
//   SECURITY.md sign this file by signing the release that contains it.
//
// Each statement carries its NIST SSDF practice IDs (PO/PS/PW/RV.*) and
// names the specific implementing control so the assertion is auditable,
// not aspirational. Output is deterministic: the timestamp comes from
// --date / SOURCE_DATE_EPOCH (never an unseeded clock), and the same inputs
// produce byte-identical output.

var fs   = require("node:fs");
var path = require("node:path");

var ROOT     = path.resolve(__dirname, "..");
var PKG_PATH = path.join(ROOT, "package.json");

// ---------------------------------------------------------------------
// Argument + environment resolution. Config-time inputs THROW on bad shape
// (operator catches a typo at invocation). This is an entry-point script,
// not a hot path.
// ---------------------------------------------------------------------

function _parseArgs(argv) {
  var out = {};
  for (var i = 0; i < argv.length; i++) {
    var a = argv[i];
    if (a === "--out")        { out.out        = argv[++i]; continue; }
    if (a === "--version")    { out.version    = argv[++i]; continue; }
    if (a === "--commit")     { out.commit     = argv[++i]; continue; }
    if (a === "--date")       { out.date       = argv[++i]; continue; }
    if (a === "--repository") { out.repository = argv[++i]; continue; }
    if (a === "-h" || a === "--help") { out.help = true; continue; }
    throw new Error("generate-ssdf-attestation: unrecognized argument: " + a);
  }
  return out;
}

// Deterministic timestamp: --date (RFC 3339) wins; else SOURCE_DATE_EPOCH
// (seconds since the Unix epoch); else fail closed. Never an unseeded clock.
function _resolveTimestamp(args, env) {
  if (typeof args.date === "string" && args.date.length > 0) {
    var t = new Date(args.date);
    if (isNaN(t.getTime())) {
      throw new TypeError("generate-ssdf-attestation: --date is not a valid date: " + args.date);
    }
    return t.toISOString();
  }
  var epoch = env.SOURCE_DATE_EPOCH;
  if (typeof epoch === "string" && epoch.length > 0) {
    if (!/^[0-9]+$/.test(epoch)) {
      throw new TypeError("generate-ssdf-attestation: SOURCE_DATE_EPOCH must be integer seconds, got: " + epoch);
    }
    var secs = parseInt(epoch, 10);
    if (!isFinite(secs) || secs < 0) {
      throw new TypeError("generate-ssdf-attestation: SOURCE_DATE_EPOCH out of range: " + epoch);
    }
    return new Date(secs * 1000).toISOString();
  }
  throw new Error(
    "generate-ssdf-attestation: no deterministic timestamp source. " +
    "Pass --date <RFC3339> or set SOURCE_DATE_EPOCH (no unseeded clock is used)."
  );
}

// Software version: --version wins; else package.json. Cross-check when both
// are present so a tag/package drift fails the cut here too.
function _resolveVersion(args, pkg) {
  if (typeof args.version === "string" && args.version.length > 0) {
    if (pkg.version && args.version !== pkg.version) {
      throw new Error(
        "generate-ssdf-attestation: --version (" + args.version +
        ") does not match package.json version (" + pkg.version + ")"
      );
    }
    return args.version;
  }
  if (typeof pkg.version === "string" && pkg.version.length > 0) return pkg.version;
  throw new Error("generate-ssdf-attestation: no version (pass --version or set package.json version)");
}

// Source-control commit: --commit wins; else GITHUB_SHA; else fail closed.
// The per-statement controls are auditable only against a specific source
// revision, so an attestation without a commit anchor asserts controls
// against no identifiable tree.
function _resolveCommit(args, env) {
  if (typeof args.commit === "string" && args.commit.length > 0) return args.commit;
  var sha = env.GITHUB_SHA;
  if (typeof sha === "string" && sha.length > 0) return sha;
  throw new Error(
    "generate-ssdf-attestation: no commit source. Pass --commit <sha> or set " +
    "GITHUB_SHA. The attestation's statements are checkable only against a " +
    "specific source revision."
  );
}

// Normalize the package.json repository field to a bare https URL.
function _resolveRepository(args, pkg) {
  if (typeof args.repository === "string" && args.repository.length > 0) return args.repository;
  var r = pkg.repository;
  var url = (r && typeof r === "object" && typeof r.url === "string") ? r.url
          : (typeof r === "string" ? r : "");
  url = url.replace(/^git\+/, "").replace(/\.git$/, "");
  if (url.length === 0) return null;
  return url;
}

// ---------------------------------------------------------------------
// The attestation document.
//
// Structure follows the OMB M-22-18 / CISA "Secure Software Development
// Attestation Form": producer identity, software identity, then the four
// attestation-statement groups the Form covers. Each statement is mapped to
// its NIST SP 800-218 v1.1 practice ID(s) and the control in this repository
// that implements it, so the assertion is checkable against the source tree
// at `commit`.
//
// SSDF practice families:
//   PO  Prepare the Organization
//   PS  Protect the Software
//   PW  Produce Well-Secured Software
//   RV  Respond to Vulnerabilities
// ---------------------------------------------------------------------

function _attestationStatements() {
  return [
    {
      "id": "secure-build-environment",
      "form_section": "1. Secure software development environment",
      "summary": "Software is developed and built in secure environments with separated, least-privilege, ephemeral CI.",
      "statements": [
        {
          "ssdf": ["PO.5.1", "PO.5.2"],
          "claim": "Builds run only in GitHub-hosted ephemeral runners; every release job declares the minimum permissions it needs and elevates per-job (workflow-level contents:read; id-token:write only where OIDC signing requires it).",
          "control": ".github/workflows/npm-publish.yml per-job permissions blocks; no self-hosted runners.",
        },
        {
          "ssdf": ["PO.3.1", "PO.3.2", "PS.1.1"],
          "claim": "The build environment's integrity is established by SLSA Build L3 provenance: a non-falsifiable attestation binds the published artifact to the exact workflow run, commit, and tag that produced it.",
          "control": "slsa-framework/slsa-github-generator emits blamejs-blamepost-<version>.intoto.jsonl; npm publish --provenance attaches the SLSA v1 provenance to the registry tarball.",
        },
        {
          "ssdf": ["PO.5.1"],
          "claim": "Third-party GitHub Actions are SHA-pinned; the two tag-pinned exceptions (the SLSA reusable workflow and aquasecurity/trivy-action) are documented in .pinact.yaml with the structural reason each cannot be SHA-verified online. A lockfile pin-currency gate runs in the publish workflow; Action-SHA currency is checked on demand.",
          "control": ".github/workflows/*.yml SHA pins; .pinact.yaml exceptions; scripts/pin-all.js --check (npm-publish.yml validate job); scripts/check-actions-currency.js (on-demand).",
        },
      ],
    },
    {
      "id": "provenance-and-component-trust",
      "form_section": "2. Provenance and trust of software components",
      "summary": "The provenance of code and components is established and maintained; a complete SBOM accompanies every release.",
      "statements": [
        {
          "ssdf": ["PW.4.1", "PW.4.4"],
          "claim": "Zero npm runtime dependencies. The one piece of third-party code that ships is the blamejs framework, vendored under lib/vendor/ by a single scripted entry point from the published registry tarball, whose publisher-recorded SHA-512 integrity digest is verified before the archive is extracted; the refresh fails closed and extracts nothing when the digest does not match or when no integrity value is published. The resolved tarball URL and that digest are recorded in lib/vendor/MANIFEST.json alongside a SHA-256 hash of the extracted tree, and hand-edits to the vendored tree are refused. The release does not publish if any runtime dependency component appears in the SBOM.",
          "control": "scripts/vendor-update.sh (sole path into lib/vendor/, integrity-verified before extraction); lib/vendor/MANIFEST.json integrity + SHA-256 tree hashes; scripts/refresh-vendor-manifest.js; scripts/check-vendor-currency.js; npm-publish.yml runtime-deps gate.",
        },
        {
          "ssdf": ["PS.3.1", "PS.3.2"],
          "claim": "Each release ships a CycloneDX 1.6 SBOM of the npm dependency tree (empty by the zero-runtime-dep contract); the vendored-tree view is generated on demand from the SHA-256-pinned vendor manifest.",
          "control": "sbom.cdx.json (npm tree) attached to the GitHub release; scripts/build-vendored-sbom.js renders lib/vendor/MANIFEST.json as a CycloneDX document, verifying every recorded hash against the on-disk bytes.",
        },
        {
          "ssdf": ["PS.2.1"],
          "claim": "Release integrity is verifiable through independent trust roots, each detecting tampering with the others: SLSA L3 npm provenance, a Sigstore-keyless SBOM signature, SSH-signed annotated tags, and a per-tarball SHA-256 sidecar. Operator-run tooling additionally produces SHA3-512 digests and an ML-DSA-65 (FIPS 204) tarball signature with node:crypto.",
          "control": "cosign sign-blob (sbom.cdx.json.sigstore); SSH-signed tags enforced by the release-tags ruleset; <tarball>.sha256 attached to the GitHub release; scripts/sha3-digest.js + scripts/sign-release-artifact.js (operator-run). Verification recipes in SECURITY.md.",
        },
      ],
    },
    {
      "id": "trusted-source-and-vuln-checking",
      "form_section": "3. Trusted source-code supply chains and automated vulnerability checking",
      "summary": "Good-faith effort to maintain trusted source-code supply chains and to perform automated vulnerability scanning on every release.",
      "statements": [
        {
          "ssdf": ["RV.1.1", "RV.1.2", "PW.7.2"],
          "claim": "Every release is scanned for known vulnerabilities before publish: OSV-Scanner runs against the committed lockfile that pins the build toolchain, and against the vendored tree; the release fails on any finding. A vendored-dependency currency gate refuses a stale, potentially-vulnerable pin.",
          "control": "OSV-Scanner steps in npm-publish.yml (--lockfile=package-lock.json; -r lib/vendor/); scripts/check-vendor-currency.js.",
        },
        {
          "ssdf": ["PW.8.2", "PW.7.1"],
          "claim": "Wire-protocol readers refuse malformed input with the protocol's own error code rather than tolerating it for client compatibility, and each listener is exercised over a real socket by an integration suite that runs every file in its own process against a live server, not against the parser's own idea of what it emitted.",
          "control": "test/integration/*.test.js driven by scripts/test-integration.js; scripts/check-services.js confirms every listener is bound before the suite starts; scripts/check-swallow-coverage.js proves each non-re-throwing catch is execution-covered.",
        },
        {
          "ssdf": ["PS.1.1", "PO.5.2"],
          "claim": "Source-side supply-chain integrity is enforced at the repository boundary: protected default branch (no force-push, no non-linear merge, required status checks, required signed commits) and protected release tags (no deletion, no re-pointing) so a published tag cannot be silently rewritten.",
          "control": "main-protection + release-tags GitHub rulesets; SSH-signed commits/tags required server-side.",
        },
      ],
    },
    {
      "id": "vulnerability-disclosure-and-response",
      "form_section": "4. Vulnerability disclosure and response",
      "summary": "A vulnerability disclosure program and a process to respond to and remediate reported vulnerabilities are maintained.",
      "statements": [
        {
          "ssdf": ["RV.1.3", "RV.2.1"],
          "claim": "A coordinated vulnerability-disclosure process is published: a private reporting channel via GitHub Security Advisories, a coordinated embargo window, and reporter credit on disclosure.",
          "control": "SECURITY.md (GitHub private security advisories, coordinated-disclosure timeline).",
        },
        {
          "ssdf": ["RV.2.2", "RV.3.3"],
          "claim": "Fixes are delivered through a stable, signed release path with a published deprecation policy; remediations are described in operator-facing release notes, and the CHANGELOG is rendered from that single structured source rather than written twice.",
          "control": "scripts/release.js orchestrated flow; release-notes/v<version>.json single source, folded into the minor series file release-notes/v<minor>.x.json by scripts/consolidate-release-notes.js and rendered into CHANGELOG.md by scripts/generate-changelog-entry.js --rebuild; scripts/gen-migrating.js renders MIGRATING.md from the deprecations declared in source.",
        },
        {
          "ssdf": ["RV.3.1", "RV.3.4"],
          "claim": "Root-cause analysis is institutional: a confirmed defect class is swept across the whole tree and encoded as a recurrence detector so the same class cannot silently reappear in a later release.",
          "control": "codebase-patterns class-level detectors (test/layer-0-primitives/codebase-patterns.test.js); behavioral regression tests ship with each fix.",
        },
      ],
    },
  ];
}

function buildAttestation(opts) {
  var pkg = opts.pkg;
  var name = pkg.name || "@blamejs/blamepost";
  return {
    "$schema_note": "NIST SP 800-218 (SSDF v1.1) / OMB M-22-18 producer self-attestation, machine-readable form.",
    "attestation_type": "producer-self-attestation",
    "attestation_format": "blamejs/ssdf-attestation",
    "attestation_format_version": "1.0",
    "framework": {
      "name": "NIST SP 800-218",
      "title": "Secure Software Development Framework (SSDF) Version 1.1",
      "reference_form": "OMB M-22-18 / CISA Secure Software Development Attestation Form",
    },
    "generated": opts.timestamp,
    "producer": {
      "name": "blamejs",
      "url": "https://github.com/blamejs/blamepost",
      "security_contact": "https://github.com/blamejs/blamepost/security/advisories/new",
      "vulnerability_disclosure": "https://github.com/blamejs/blamepost/security",
    },
    "software": {
      "name": name,
      "version": opts.version,
      "repository": opts.repository,
      "commit": opts.commit,
      "license": pkg.license || null,
    },
    "attestation_statement":
      "blamejs attests, as the producer of " + name + " version " + opts.version +
      ", that the secure software development practices enumerated below are " +
      "followed for this release, mapped to NIST SP 800-218 (SSDF v1.1) " +
      "practices. This is a self-attestation; its authenticity is bound to the " +
      "signed release artifacts described in SECURITY.md (SSH-signed tag, SLSA " +
      "L3 provenance, Sigstore SBOM signature).",
    "sections": _attestationStatements(),
    "verification": {
      "note": "This attestation is not independently signed; it is covered by the release trust roots that sign the release containing it.",
      "trust_roots": [
        "SLSA L3 npm provenance (npm publish --provenance + blamejs-blamepost-<version>.intoto.jsonl)",
        "Sigstore-keyless SBOM signature (sbom.cdx.json.sigstore)",
        "SSH-signed annotated git tag (release-tags ruleset, enforced server-side)",
        "Per-tarball SHA-256 sidecar (<tarball>.sha256, attached to the GitHub release)",
        "Operator-run deep verification (scripts/sha3-digest.js SHA3-512 digests; scripts/sign-release-artifact.js ML-DSA-65 signature, FIPS 204, node:crypto)",
      ],
      "recipes": "SECURITY.md -> 'Verifying release authenticity'",
    },
  };
}

function main() {
  var args = _parseArgs(process.argv.slice(2));

  if (args.help) {
    process.stderr.write(
      "Usage: node scripts/generate-ssdf-attestation.js " +
      "[--version <v>] [--commit <sha>] [--date <RFC3339>] " +
      "[--repository <url>] [--out <path>]\n" +
      "Timestamp source (required, deterministic): --date or SOURCE_DATE_EPOCH.\n" +
      "Commit source (required): --commit or GITHUB_SHA.\n"
    );
    return;
  }

  var pkg;
  try {
    pkg = JSON.parse(fs.readFileSync(PKG_PATH, "utf8"));
  } catch (e) {
    process.stderr.write("[generate-ssdf-attestation] failed to read package.json: " + e.message + "\n");
    process.exit(1);
    return;
  }

  var doc = buildAttestation({
    pkg:        pkg,
    version:    _resolveVersion(args, pkg),
    commit:     _resolveCommit(args, process.env),      // env-driven release script
    repository: _resolveRepository(args, pkg),
    timestamp:  _resolveTimestamp(args, process.env),   // env-driven release script
  });

  var json = JSON.stringify(doc, null, 2) + "\n";

  if (typeof args.out === "string" && args.out.length > 0) {
    fs.writeFileSync(args.out, json);
    process.stderr.write("[generate-ssdf-attestation] wrote " + args.out + "\n");
  } else {
    process.stdout.write(json);
  }
}

main();
