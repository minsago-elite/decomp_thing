# Submitted job filters and browser history

Submitting a different valid library filter or explicitly resetting valid filters creates a history entry.
Back and Forward restore the complete documented filter selection and perform only the bounded list read.
An unchanged submitted URL does not add a duplicate entry. Resetting invalid saved filters replaces that
invalid entry, preserving the existing visible recovery and keeping malformed values out of subsequent URLs.
Typing a draft, background refresh and rejected validation do not add entries. Existing cancellation rejects
late results from a filter selection abandoned through browser history.

The focused implementation has one production hunk and four synthetic JSDOM/client controls: all six
filter fields and result identity through Back/Forward; reversible reset and duplicate submission; invalid
saved/draft recovery; and a pending read completed after Back. No actual service, native process, provider,
authenticated session or browser is started by those controls. Original commands, bounds, native fixtures,
assertions and bundle budgets remain unchanged. Qualification uses ordinary Actions on the exact source.

This advances selection preservation in #527 and filter history in #495. Their full original acceptance
criteria remain binding. Run/revision/workspace-tab URL state, comparisons, directory/row pagination,
restored scroll/focus across every resource and full packaged navigation acceptance are not completed by
the filter correction. The design contract remains docs/web-navigation.md; #495 and parent #167 stay open.
