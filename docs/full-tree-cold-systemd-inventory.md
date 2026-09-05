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
