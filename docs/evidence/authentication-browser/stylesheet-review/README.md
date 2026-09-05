# Authentication browser stylesheet evidence

Chromium 153.0.8010.12 passed seven original-parent scenarios at 6ad4567 and
15 stack-tip scenarios at 4594862. Both use the exact production APP_CSS emitted
by the Java render fixture, assert loaded stylesheet rules and computed layout,
and record HTML/CSS hashes. Screenshots, traces and result files are retained with
SHA-256 digests. The tip screenshot was visually inspected and shows the styled
dashboard. Status responses are mocked; no agent or uploaded target executes.

The first parent run failed the new CSS check because its differently indented
route handler had not yet received the stylesheet route. The corrected second run
passed. Its older evidence-finalization behavior is a separate existing review;
the retained passing run completed normally. The tip retains protected cleanup and
publishes success after trace/browser finalization.

The fix propagated atomically through all 15 affected branches. The final tip tree
at 48de788 is identical to tested 4594862. Full CI omitted because its patch lane
executes vulnerability reproduction. This verifies mocked browser behavior, not
independent-agent authentication or completion of the master integration #360.
