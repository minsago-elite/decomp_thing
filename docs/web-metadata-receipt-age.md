# Receipt age in private views

Each accepted private read is held in memory with its own browser receipt time. Retaining a snapshot retains that time; clearing a snapshot clears its receipt. The timestamp identifies receipt in this tab, not the producer's observation time or the server's present state.

| Displayed snapshot | Receipt lifetime |
| --- | --- |
| Job library | The visible page and its bounded first-page cache keep the same packet. Returning to the cache does not refresh its time. A deferred reorder does not replace the visible packet. Retained empty pages also show age. |
| Job, attempt, attempt history | Accepted identity-bound metadata receives a timestamp. Pending reads and permitted transient failures retain the whole packet; rejection, unavailable identity and replacement binding clear it. |
| Runtime and workflow availability | Both use the accepted bootstrap receipt, outside the wire runtime DTO. Opening either view does not read bootstrap or fabricate a receipt. Older injected snapshots can explicitly report unknown receipt time. |
| Recovery inventory | Only the accepted current client/refresh observation is timestamped. Complete empty inventory remains hidden. |
| Progress pin policy | Only the verified GET receives a timestamp. The PUT response does not refresh editable policy or its receipt. Existing version and idempotency guards remain required. |
| Upload progress | Matching upload-ID observations receive timestamps independently of upload publication. Polling cadence, retry identities and commands retain their existing ownership. |
| Exploration report and retained cases | Discovery and integrity-bound case bytes have separate receipt times. Local filtering, paging and case selection do not read again or change those times. |
| Validation history, selected report, baseline | History keeps its original packet through report selection and paging. A saved baseline keeps the selected report's original receipt, including when saved later. It is separate from a newly read target report. |
| Validation source link | Receipt is published only after both the terminal attempt and exact source commitment have been checked. |
| Source directory, file, range, digest check | Each accepted key-bound read has a separate receipt. Source pins, URLs, ranges, integrity checks, explicit read intents and preview limits retain their authority. |

The shared display clock is sampled every ten seconds while visible and released on hide/unmount. It uses the existing Activity clock's three-coordinate reset and suspended-clock reconciliation without changing its sampling interval. A retained metadata receipt also reconciles its initial receipt-to-mount interval, which can include a long period off the view; that first interval is not bounded by the mounted display timer. Activity receipts are owned by their mounted stream and keep their existing first-sample behavior, copy and controls. Metadata age updates run inside the receipt child; they do not change parent selections, list keys, cursors, request bindings, API calls or server-work lifetime. Repeated age text is outside live regions, including the upload progress status container.

Receipt coordinates are not persisted, added to API DTOs, used as resource keys or used to authorize commands. They do not establish source freshness, integrity, workflow acceptance, equivalence, tool readiness or authenticated ACP effectiveness. Source preview policy is unchanged; a zero maximum still disables preview.

New controls use fake clocks, injected transports, authored response fixtures and JSDOM. They cover initial and remounted suspended intervals, clock cleanup and same-monotonic replacement, stable focus/text selection/URL, cached and deferred library receipts, retained empty pages, independent validation history/report/baseline times, joined source resolution, guarded pin reconciliation and late runtime mounts without new reads. They do not qualify physical scrolling, real browser restart/tab conflicts, real provider/native execution or the full browser hardening outcome. Complete existing frontend and backend regression qualification remains required through ordinary Actions.

Local receipt coordinates use `data-received-at` and a raw ISO timestamp title alongside the exact UTC display. They remain distinct from the persisted server creation/update timestamps represented by `time` elements in job facts. Receipt-age wording, values and the visible-only clock are unchanged. Existing packaged checks still require the exact persisted timestamp list without alteration; a separate injected DOM control binds the local receipt coordinate to its displayed value.
