# Control normalization before preview redaction

Original #267 source dd594c4 passed 22 selected inventory/journal tests. Stack-tip
source 038f751 passed 37 selected authentication/current-config/journal tests.
Both runs used the identical source immediately before their commits, with zero
failures/errors/skips. Original reports and hashes are retained here.

The regression covers NUL, SOH, carriage return and DEL inside a private literal
and a credential-pattern prefix, and normalization of private values themselves.
Normalization precedes matching; raw input/value limits remain enforced before it.
The parent retains its original redactor interface, while descendants retain the
later separate preference allowance and final-formatting privacy check.

All 17 affected branches were pushed atomically. The propagated tip 1deaa24 has
an identical complete tree to tested 038f751. No agent or target executes. Full CI
omitted because its patch lane executes vulnerability reproduction. Partial-secret
advertisements and shared-service integration remain separate outstanding work.
