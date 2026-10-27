# syntax=docker/dockerfile:1.7
#
# All-in-one blamepost image: MX, submission, IMAP, POP3, ManageSieve and
# the web UI (webmail + admin + JMAP) in a single Node process.
#
# Build context is the repository root.
#
# Two stages:
#   - stage `src` uses cgr.dev/chainguard/node:latest-dev. It stages the
#     source tree and is the source of the libatomic shared object the
#     runtime image lacks.
#   - stage `runtime` uses cgr.dev/chainguard/node:latest and runs as
#     nonroot, UID 65532.
#
# What the runtime image actually carries, measured rather than assumed.
# Its own package inventory under /var/lib/db/sbom lists busybox, npm and
# node-gyp, so a shell at /bin/sh and an npm on the path are both present
# and come from the base. No operating system package manager is: there
# is no apk, apt, dnf or yum, so nothing in the image can install a
# package from the network.
#
# blamepost adds none of that and depends on none of it. Everything the
# image is configured to run is an argument array: the entry point is the
# Node binary, the default command is the server, the health probe is a
# Node expression, and the operator commands in the quick start are
# `node bin/blamepost.js <verb>`. Nothing is handed to a shell for word
# splitting, so the base image's shell is reachable only by someone who
# already has execution inside the container.
#
# That distinction is worth stating precisely because an operator sizing
# what a code execution defect in a mail parser would reach reads it as
# the answer. The repository's integration suite measures the set inside
# the built image and fails when it changes, so a base image bump that
# adds a package manager is reviewed rather than inherited.
#
# There is no `npm ci` anywhere in this build. blamepost has ZERO npm
# runtime dependencies: the framework it composes is vendored under
# lib/vendor/blamejs and ships in the tree. Nothing is resolved from a
# registry at image-build time, which removes the whole class of
# build-time supply-chain risk. devDependencies exist for the test and
# lint gates and never enter the image.
#
# The vendored Argon2id native module ships glibc prebuilds; Wolfi is
# glibc-based, so those load without a rebuild.
#
# Base images are digest-pinned in source for reproducible local builds
# and supply-chain provenance. Dependabot's docker updater bumps these
# digests so they track Chainguard's continuous CVE rebuilds instead of
# freezing. The committed digest never reaches the vulnerability gate:
# release-container.yml resolves the rolling tag to a FRESH digest at
# build time and passes it via the BASE_SRC / BASE_RUNTIME build args,
# overriding these defaults, so the scanned image always carries current
# patches and scan == publish. A local `docker build` with no build args
# uses the pinned digest; the human-readable tag is retained alongside it
# for readability and as the rolling source the release workflow resolves.
#
# Each ARG carries a record of the Node version measured inside the image
# it pins, one line per published platform, naming the digest the
# measurement was taken from. A digest is opaque: nothing else in this
# repository says which runtime the image actually ships, so nothing else
# could tell an operator that a base image had dropped below the floor
# `engines.node` declares. Each record names its digest so the two move
# together, and scripts/check-node-floor.js fails when a record and its
# ARG stop matching. Bumping a digest therefore costs one measurement per
# platform, and both platforms are covered because the release publishes
# both.
#
# Reading the version out of an image, without emulation, on either
# platform:
#
#   id=$(docker create --platform linux/arm64 <image>@<digest>)
#   docker cp "$id:/var/lib/db/sbom" ./sbom && ls ./sbom | grep nodejs
#   docker rm -f "$id"
#
# On the host's own platform the runtime answers directly, which is the
# cross-check that the package name and the running binary agree:
#
#   docker run --rm --entrypoint /usr/bin/node <image>@<digest> -p process.version
#
# node: 26.12.1 on linux/amd64 in sha256:1ac2b87f6683faf0b4df19431bf73d0a40c5bcaa0da2073cad9f815571f593e4
# node: 26.12.1 on linux/arm64 in sha256:1ac2b87f6683faf0b4df19431bf73d0a40c5bcaa0da2073cad9f815571f593e4
ARG BASE_SRC=cgr.dev/chainguard/node:latest-dev@sha256:1ac2b87f6683faf0b4df19431bf73d0a40c5bcaa0da2073cad9f815571f593e4
# node: 26.12.1 on linux/amd64 in sha256:efa14a42578e5931c351eb562ee2bed3e9c55e9abbfd683e218c88ab3889bcba
# node: 26.12.1 on linux/arm64 in sha256:efa14a42578e5931c351eb562ee2bed3e9c55e9abbfd683e218c88ab3889bcba
ARG BASE_RUNTIME=cgr.dev/chainguard/node:latest@sha256:efa14a42578e5931c351eb562ee2bed3e9c55e9abbfd683e218c88ab3889bcba

FROM ${BASE_SRC} AS src
WORKDIR /home/node
COPY --chown=node:node package.json LICENSE NOTICE README.md SECURITY.md ./
COPY --chown=node:node bin ./bin
COPY --chown=node:node lib ./lib
COPY --chown=node:node docs ./docs
# Pre-create the data directory as an empty skeleton owned by the runtime
# UID, so the nonroot user has a writable data path when the operator
# runs with no volume mounted, which is what the post-publish smoke test
# does. The runtime stage sets the mode; see the note there, because the
# mode decides whether the server starts at all.
RUN mkdir -p /home/node/data-skeleton

FROM ${BASE_RUNTIME} AS runtime

# Explicit USER directive. Chainguard's :latest image already runs as
# `nonroot` (UID 65532) by default, but Trivy's static Dockerfile checker
# (DS-0002) flags any image without an explicit USER line regardless of
# the base image's default. Restate it here.
USER 65532:65532

# libatomic. Node links it at runtime and the runtime image does not ship
# it (the -dev image used for the source stage does). Without this the
# container dies at startup with "error while loading shared libraries:
# libatomic.so.1" before any application code runs.
#
# It is COPIED from the source stage rather than installed, because the
# runtime image has no operating system package manager to install it
# with. Both names are taken because the soname is what the loader
# resolves; Docker materialises the symlink as a regular file, so the
# pair costs ~90 KB.
COPY --from=src /usr/lib/libatomic.so.1* /usr/lib/

# Non-secret defaults baked into the image. Secrets are NEVER ENV-baked.
# That covers the vault passphrase, the bootstrap admin password and any
# DKIM key material. They are injected at runtime via environment, Docker
# secrets, or mounted files.
#
# PRIVILEGED PORTS. This image runs as UID 65532, and ports below 1024
# are the ones a mail server needs. Where the floor sits depends on the
# network namespace the container gets, which is worth knowing before
# choosing between the two supported ways to run it.
#
#   1. Let the container bind the standard ports directly, with the
#      unprivileged port floor lowered inside its own namespace:
#
#        docker run --sysctl net.ipv4.ip_unprivileged_port_start=0 ...
#
#      The sysctl is namespaced, so it changes nothing on the host. It is
#      also already the default in a container's own network namespace on
#      current Docker and on Kubernetes, where the floor reads 0 with no
#      flag at all. Setting it anyway states the requirement rather than
#      inheriting it, so a runtime that has not adopted that default, or
#      an operator who has moved it, still gets a server that binds. This
#      is what compose.yml does and what the operator guide documents as
#      the default.
#
#   2. Keep the floor and move the listeners to unprivileged ports inside
#      the container, publishing the standard ports on the host:
#
#        docker run -e BLAMEPOST_MX_PORT=2525 -p 25:2525 ...
#
#      Every listener port below is overridable, so this needs no image
#      change. This is the answer under host networking, where the floor
#      is the host's own 1024 and where the flag above is refused rather
#      than applied: a namespaced sysctl cannot be set for a namespace
#      the container is sharing. Note that mapped ports rewrite the peer
#      address unless the host network is used, so every per-peer budget
#      the listeners keep counts the runtime's own address instead of the
#      sender's. The operator guide covers the trade-off.
#
# Available environment variables (operator-set at runtime):
#
#   NODE_ENV                      production | development   (default: production)
#   BLAMEPOST_HOSTNAME            public MX hostname         (REQUIRED, e.g. mx.example.com)
#   BLAMEPOST_DATA_DIR            data path                  (default: /var/lib/blamepost)
#   BLAMEPOST_CONFIG              config file path           (default: /etc/blamepost/blamepost.config.json)
#
#   BLAMEPOST_VAULT_PASSPHRASE    seals DKIM private keys and account
#                                 secrets at rest             (REQUIRED)
#   BLAMEPOST_ADMIN_EMAIL         administrator address
#   BLAMEPOST_ADMIN_PASSWORD      administrator password
#                                 Read by `blamepost init` and by nothing
#                                 else. `serve` creates no account, so run
#                                 init once against the data volume:
#                                   node bin/blamepost.js init \
#                                     --admin-email admin@example.com
#                                 It is also the only command that creates an
#                                 account carrying administrator rights;
#                                 `account add` creates an ordinary mailbox.
#                                 Set BOTH of the two above or neither. One
#                                 without the other is refused at start, since
#                                 an email with no password would leave the
#                                 server choosing a credential and logging it.
#                                 With neither set, init generates a password
#                                 and prints it once.
#
#   BLAMEPOST_DNS_ACKNOWLEDGED    must be "1" before the MX listener binds.
#                                 The DNS posture in docs/operator-guide.md
#                                 is an operator-side prerequisite; this gate
#                                 refuses to serve mail until it is confirmed.
#
#   BLAMEPOST_MX_PORT             inbound MX                  (default: 25)
#   BLAMEPOST_SMTPS_PORT          implicit-TLS submission     (default: 465)
#   BLAMEPOST_SUBMISSION_PORT     submission + STARTTLS       (default: 587)
#   BLAMEPOST_IMAP_PORT           IMAP + STARTTLS             (default: 143)
#   BLAMEPOST_POP3_PORT           POP3 + STLS                 (default: 110)
#   BLAMEPOST_MANAGESIEVE_PORT    ManageSieve                 (default: 4190)
#   BLAMEPOST_HTTP_PORT           webmail, admin, JMAP        (default: 8080)
#   BLAMEPOST_HTTPS_PORT          same over TLS               (default: 8443)
#   BLAMEPOST_POP3_ENABLED        POP3 is opt-in              (default: false)
#
#                                 IMAP and POP3 negotiate TLS in band, so
#                                 nothing binds 993 or 995 and there is no
#                                 variable for either. A terminator in
#                                 front of 143 or 110 does not supply
#                                 them: the listener is handed a
#                                 plaintext connection and refuses every
#                                 credential offered over it. A client
#                                 that can only do implicit TLS has no
#                                 route to a mailbox on this image.
#
#   docs/operator-guide.md carries the full settings reference. Every
#   variable this server reads is in the table there, with its default.
#
#   BLAMEPOST_TLS_CERT            certificate chain path      (REQUIRED by serve)
#   BLAMEPOST_TLS_KEY             matching private key path   (REQUIRED by serve)
#                                 Every mail listener requires TLS and none
#                                 has a plaintext mode, so serve refuses to start
#                                 without the pair. Issuing and renewing it is
#                                 the operator's job; mount it into
#                                 /var/lib/blamepost/tls or bind a host path.
#
#   BLAMEPOST_LOG_LEVEL           debug | info | warn | error | fatal
#                                                             (default: info)
#                                 Only debug changes what is written. It adds
#                                 the entries about what this server recovered
#                                 from. The levels above info remove nothing.
ENV NODE_ENV=production \
    BLAMEPOST_DATA_DIR=/var/lib/blamepost \
    BLAMEPOST_HTTP_PORT=8080 \
    BLAMEPOST_HTTPS_PORT=8443

WORKDIR /app
COPY --from=src --chown=65532:65532 /home/node/package.json /home/node/LICENSE /home/node/NOTICE /home/node/README.md /home/node/SECURITY.md ./
COPY --from=src --chown=65532:65532 /home/node/bin ./bin
COPY --from=src --chown=65532:65532 /home/node/lib ./lib
COPY --from=src --chown=65532:65532 /home/node/docs ./docs
# Writable data path for a `docker run` with no volume mounted. Production
# deployments bind a named volume over /var/lib/blamepost. See compose.yml.
COPY --from=src --chown=65532:65532 /home/node/data-skeleton /var/lib/blamepost

# The two directory modes the image ships, set explicitly because both
# were wrong when left to their defaults and neither is visible from any
# source file.
#
# /var/lib/blamepost is the one the server reads. It asserts its
# production posture at boot and refuses a data directory looser than
# 0750, naming the mode and exiting before it binds anything. The
# skeleton arrived at 0755, so `serve` refused, and a fresh named volume
# takes its mode from this directory, so the compose stack inherited the
# same refusal. An operator following the quick start got a container
# that exited on every start.
#
# /app is where the application lives, and the base image ships it
# world-writable at 0777. Nothing needs that: the server runs as the user
# that owns it. Left alone it means any identity with execution inside
# the container can rewrite the code the next start runs.
#
# This runs through the Node binary rather than a shell, because the Node
# binary is the one interpreter the image is guaranteed to carry: it is
# the entry point. Both directories are owned by the runtime user, so no
# step here needs root.
# hadolint shell-checks the argument even in exec form, where Docker runs
# the binary directly and the string is never shell-interpreted. shellcheck
# reads the parentheses of `require('node:fs')` as shell syntax and stops
# there.
# hadolint ignore=SC1088
RUN ["/usr/bin/node", "-e", "var fs=require('node:fs');fs.chmodSync('/app',0o755);fs.chmodSync('/var/lib/blamepost',0o750);"]

# Mail listeners. 110 is declared because POP3 binds it once the operator
# switches POP3 on, and nothing binds 993 or 995 on any configuration.
EXPOSE 25 110 143 465 587 4190
# Web UI: webmail, admin, JMAP.
EXPOSE 8080 8443

VOLUME ["/var/lib/blamepost"]

# The endpoint reports the store, the listener inventory, the certificate
# and the outbound queue, not just that a process is running. It answers
# ok when every one of those passes, and degraded when this server is
# holding a listener shut on purpose and can say why. A fresh volume
# hosts no domain, so port 25 has nothing to receive for until
# `blamepost init` runs. Both of those are a container that is up and
# serving.
#
# A listener that was supposed to take a port and could not is not a
# reading this endpoint produces. The start refuses on that listener,
# releases every port it had already taken, and the process exits, so
# what you get is an exited container and the bind error in
# `docker logs`. The check that covers it lives on /readyz, where it
# refuses with a 503 rather than reducing the verdict.
#
# Two other checks answer degraded and are not startup conditions: the
# certificate inside its expiry window, and the outbound queue no longer
# moving mail. Both answer 200, so this probe calls the container healthy
# for either, and both are slow failures that arrive weeks after the
# thing that caused them. Neither is critical on either probe on purpose,
# because a restart neither renews a certificate nor drains a queue, so
# failing here would ask a supervisor for the one action that cannot
# help. That puts the burden on whoever watches this container: alert on
# a degraded reading from /readyz, not only on an unhealthy container.
#
# A 503 from this endpoint means the message store did not answer. It is
# the one check that refuses here rather than reducing the verdict, and
# it is the one condition a restart can address.
# compose.yml carries the same note beside its copy of this probe.
#
# The probe writes what it read before it exits. A failing streak beside
# an empty output tells an operator that something is wrong and nothing
# whatsoever about what, and this endpoint answers the reason in full to
# a caller on the loopback interface, which is where this runs.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.BLAMEPOST_HTTP_PORT||8080)+'/healthz').then(r=>r.text().then(t=>{process.exitCode=r.ok?0:1;process.stdout.write(t,()=>process.exit(r.ok?0:1))})).catch(e=>{process.stdout.write('probe did not answer: '+((e&&e.message)||e),()=>process.exit(1))})"]

# The Chainguard node image has ENTRYPOINT ["/usr/bin/node"], so CMD is
# the script path Node runs. `serve` is the default subcommand.
CMD ["bin/blamepost.js", "serve"]
