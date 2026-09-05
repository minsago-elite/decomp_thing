# Failed authentication selection lifetime

Seven tests passed offline on the identical source immediately before 4c8ac05:
one selection regression and six web inspection tests. The selection regression
injects ordinary missing/malformed/non-ACP failure categories, checks that repeated
calls retain the original exception without rerunning selection, and checks that a
new inspector can select again. HTTP inspection tests retain cancellation, cleanup
and ownership coverage using inert callbacks. No external agent or target executes.
Original JUnit reports and hashes are retained here. Full CI omitted because its
patch lane executes vulnerability reproduction.

This is stack-tip evidence. The original #274 inspector has a different signature;
its backport and propagation remain pending. The master integration candidate #366
has not yet acquired the later authentication implementation.
