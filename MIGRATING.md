# Migrating

One migration recipe per breaking change. Every deprecated surface listed here also warns from the running process before its removal version, with `BLAMEJS_DEPRECATIONS=warn` set or by default outside production. This file ships in the repository, so you can diff it against the tag you are upgrading from.

Some breaking changes cannot warn at runtime: an on-disk format break, a database migration, or a change to what a listener accepts on the wire has no in-process call to attach a warning to. Those are listed below alongside the runtime deprecations, so the full upgrade path is here rather than spread through the changelog.

## No active deprecations

No `deprecate()`-marked surface is awaiting removal.
