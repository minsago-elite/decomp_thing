# Submitted job filters and browser history

Submitting a different valid library filter or explicitly resetting valid filters creates a history entry.
Back and Forward restore the complete documented filter selection and perform only the bounded list read.
An unchanged submitted URL does not add a duplicate entry. Resetting invalid saved filters keeps the
landed dashboard behaviour: Back returns to the invalid entry and its visible recovery without a read.
Typing a draft, background refresh and rejected validation do not add entries. Existing cancellation rejects
late results from a filter selection abandoned through browser history.

The production behaviour is the landed dashboard filter history; three synthetic JSDOM/client controls cover
all six filter fields and result identity through Back/Forward, reversible reset and duplicate submission, and
a pending read completed after Back. No actual service, native process, provider,
authenticated session or browser is started by those controls. Original commands, bounds, native fixtures,
assertions and bundle budgets remain unchanged. Qualification uses ordinary Actions on the exact source.

This advances selection preservation in #527 and filter history in #495. Their full original acceptance
criteria remain binding. Run/revision/workspace-tab URL state, comparisons, directory/row pagination,
restored scroll/focus across every resource and full packaged navigation acceptance are not completed by
the filter correction. The design contract remains docs/web-navigation.md; #495 and parent #167 stay open.

## Attempt artifact catalog

On attempt Overview and Evidence routes, the retained-artifact catalog keeps its documented Artifacts filter
in the attempt query: `artifacts=run|revision` records that the list was opened and whether it is limited to
the result revision, and `artifactCursor` carries the server's opaque page cursor. Opening the list, changing
the revision filter and paging push history; Refresh returns to the first page with replace. Back, Forward and
reload restore the selection and perform only its bounded catalog read; an entry without these keys shows the
unopened catalog and reads nothing. An invalid saved selection, or a revision scope for an attempt without a
result revision, is explained in place without a read and replaced when the list is opened again. Other attempt
query keys, including the validation selection, are preserved. The router-less embedding keeps the selection in
component state. The attempt tab (Overview, Activity, Evidence, Logs), run and revision are path segments.
