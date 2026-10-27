# rspamd normal worker: the scanning endpoint.
#
# Mounted read-only at /etc/rspamd/local.d/worker-normal.inc by the `scan`
# compose profile. Files under local.d are merged into rspamd's shipped
# configuration rather than replacing it, so this only states what differs
# from the defaults.
#
# The `scan` profile starts the service. blamepost does not send mail to it
# in this release: the MX listener has no setting that reaches a scanner,
# so pointing mail here is operator wiring in front of port 25 or after
# delivery. compose.yml says the same, and ROADMAP.md tracks it under
# anti-abuse and content scanning.
#
# The port is reachable by sibling containers only. compose.yml declares
# `expose`, not `ports`, so it is never published to the host. rspamd has
# no authentication on this endpoint, and an internet-reachable scanner is
# an open relay for scan requests and a denial-of-service target. Keep it
# on the internal network.

bind_socket = "*:11333";

# Bound the work a single message can cause. A crafted archive or a deeply
# nested MIME tree is a cheap way to burn scanner CPU, and the inbound path
# is reachable by anyone who can send you mail.
task_timeout = 20s;
