# Bounded private-fragment filtering

Original #267 source a0ec768 passed 24 inventory/journal tests. Tip 5a5a4c2 passed
23 inventory/HTTP tests. Both runs used identical source immediately before commit,
with zero failures/errors/skips. Reports and hashes are retained here.

Regressions cover near-complete prefixes/suffixes, every alignment of a fifteen-unit
substring, control-normalized private values and unrelated text at the full 1 MiB
private-value budget. The parent has name/description previews; later ID previews
are filtered too. The private eight-unit block index has at most 131,072 entries.
Any contiguous private fragment of fifteen UTF-16 units contains a whole aligned
block; matching final preview text is withheld. Shorter arbitrary fragments are
not claimed confidential; some are conservatively withheld by the same test.

All seventeen affected branches were pushed atomically without force. The final
000e9e80 tree is identical to tested 5a5a4c2. No agent or target executes. Full CI
omitted because its patch lane executes vulnerability reproduction. This scoped
privacy fix does not complete authentication execution or master integration #360.
