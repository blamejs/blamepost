# rspamd normal worker: the scanning endpoint blamepost talks to.
#
# Mounted read-only at /etc/rspamd/local.d/worker-normal.inc by the `scan`
# compose profile. Files under local.d are merged into rspamd's shipped
# configuration rather than replacing it, so this only states what differs
# from the defaults.
#
# blamepost reaches this over the compose network by service name. The
# port is exposed to sibling containers only. compose.yml declares
# `expose`, not `ports`, so it is never published to the host. rspamd has
# no authentication on this endpoint, and an internet-reachable scanner is
# an open relay for scan requests and a denial-of-service target. Keep it
# on the internal network.

bind_socket = "*:11333";

# Bound the work a single message can cause. A crafted archive or a deeply
# nested MIME tree is a cheap way to burn scanner CPU, and the inbound path
# is reachable by anyone who can send you mail.
task_timeout = 20s;
