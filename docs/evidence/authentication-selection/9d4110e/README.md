# Original inspector backport and stack propagation

All five selected tests passed offline on the identical #274 source immediately
before commit 9d4110e: one failed-selection regression and four HTTP inspection
tests using inert callbacks. The regression is adapted to the original inspector's
pre-cancellation signature. Original reports and SHA-256 digests are retained here.

The fix was merged through #279 and all subsequent registered stack members. At
#279, the cancellation-aware implementation and test match the already-verified
tip. The resulting #332 tree at 8d8eee6 is exactly identical to 9b95b35 (verified by
git diff --exit-code), which retains the previous seven-test source verification.
All 15 remote branch updates were pushed atomically without force.

No agent or target executed. Full CI omitted because its patch lane executes
vulnerability reproduction. The shared-service/master candidate #366 remains a
separate integration branch and has not yet incorporated later authentication work.
