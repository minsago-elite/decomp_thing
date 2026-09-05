# Cold systemd inventory admission

The A13 cold observer admits manager major versions 255–258 only. Extending this
range requires reviewing the corresponding manager enumeration implementation;
version syntax alone does not justify admission. Version and Features queries use
the same pinned user-manager endpoint and trusted inspector as the inventories.
The attachment snapshot includes the observed version as well as feature tokens.
The existing executable, endpoint, manager-owner and invocation checks remain
necessary: a version string is not independent authentication of an implementation.

## Build capabilities are not active policy

The manager's Features property reports compile-time capabilities. `+SELINUX`,
`+APPARMOR` and `+SMACK` do not mean those policies are active, nor that enumeration
is denied or filtered. Version 255 can also append an unsigned
`default-hierarchy=legacy|hybrid|unified` token. Rejecting every unsigned token or
every `+SELINUX` build incorrectly rejects ordinary Ubuntu systemd packages.
See the [v255 feature builder](https://github.com/systemd/systemd/blob/v255/src/basic/build.c)
and [v258 feature builder](https://github.com/systemd/systemd/blob/v258/src/basic/build.c).

The parser requires a bounded, single newline-terminated version and feature line,
unique signed feature names, explicit declarations for all three MAC capabilities,
and at most one recognized trailing hierarchy token. Either sign is allowed.
Unknown metadata, contradictory declarations and unreviewed versions fail closed.
Feature admission does not grant permission to execute or mutate anything.

## Denial is not absence

In the reviewed implementations, `list_units_filtered` and `method_list_jobs`
perform a manager-level SELinux status check before constructing their reply.
A denied check returns an error, not a successful empty or per-unit-filtered
inventory. The loops serialize matching units or jobs; there is no per-entry MAC
omission. See the manager methods in
[v255](https://github.com/systemd/systemd/blob/v255/src/core/dbus-manager.c),
[v256](https://github.com/systemd/systemd/blob/v256/src/core/dbus-manager.c),
[v257](https://github.com/systemd/systemd/blob/v257/src/core/dbus-manager.c) and
[v258](https://github.com/systemd/systemd/blob/v258/src/core/dbus-manager.c).
The extracted `unit_passes_filter` in
[v257](https://github.com/systemd/systemd/blob/v257/src/core/unit.c) and
[v258](https://github.com/systemd/systemd/blob/v258/src/core/unit.c) filters only
states and name patterns. Active SELinux denial is handled by
[the access-check implementation](https://github.com/systemd/systemd/blob/v255/src/core/selinux-access.c).

Accordingly, every failed command, denied transport, malformed result or nonempty
absence inventory still aborts. In particular, a nonzero exit status with empty
output is never absence. AppArmor or Smack transport denials are not exempted.
The exact-name unit and job queries still bracket the bounded exhaustive cgroup
scan; none of these observations loads, starts, stops or reserves the unit name.
This remains an observation under the documented cooperative same-UID assumption,
not exclusion of a name race or a new containment/authority claim.

## Live attachment failure diagnostics

The cold UNIT_ATTACHED integration test retains at most 14 identity-command
results, each with an exit status and at most 1,024 output characters escaped as a
JSON string. It also records snapshot stability, identity presence, cgroup counts
and which snapshot fields changed. These test-only observers cannot substitute a
command result or classification, and production construction installs neither.
Nonzero commands still produce a conservative CHANGED observation; diagnostics
never authorize retry, loading a unit, START, adoption, mutation or release.

## Session-bus registration before attachment snapshots

An already running user manager can answer systemctl through its private socket
before its well-known name is registered on the session bus. The reviewed
[systemd v255 API setup](https://github.com/systemd/systemd/blob/v255/src/core/dbus.c)
requests `org.freedesktop.systemd1` asynchronously. A local first busctl GetUnit
query failed with that name absent while the next lookup succeeded. Completed
[diagnostic CI at c7cea0b](https://github.com/minsago-elite/decomp_thing/actions/runs/33948511482)
confirms the same cause: the first GetUnit returned exit 1 with the manager name
absent; all seven lookups/properties in the second identity observation succeeded.
Features, unit, job and cgroup snapshots were unchanged, while identity presence
and stability changed from false to true. The conservative CHANGED result was
correct for that observation pair. That run contained 1,383 passing tests, 32
skips and this single failure; it is not qualification of the registration fix.

Before either attachment snapshot, the observer now asks only the bus daemon's
`NameHasOwner` method whether that manager name is registered. Successful false
responses may be polled at 25 ms intervals under one two-second admission deadline
and an independent 81-query ceiling. Each command receives the remaining budget;
a reply arriving at or after the deadline cannot admit observation. Transport
failure, nonzero exit status, malformed replies and interruption abort immediately.
The existing command termination/output-reader bounds still apply to cleanup.

This availability preflight does not authenticate a manager or grant any unit,
cgroup or worker authority. Auto-start and interactive authorization remain
disabled. No identity lookup or CHANGED attachment snapshot is retried; the full
two-snapshot classifier and invocation-bound property checks are unchanged.
The test retains only the latest registration response and its bounded query
count, separately from the 14 identity-command results. No systemd lifetime,
BOOT/START timeout, journal transition, receipt format or release gate changes.

Local verification at `6e6e886`: all eight registration tests passed, including
the actual user-bus method envelope and deterministic late/malformed/denied/
interrupted/deadline/count cases. The full-tree and schema selection ran 457
tests: 418 passed, 39 privileged/runtime prerequisite skips, zero failures or
errors. The production cold UNIT_ATTACHED case remains among the local skips;
these results do not replace hosted qualification of the registration fix.
