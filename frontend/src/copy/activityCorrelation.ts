export const activityCorrelationCopy = {
  missing: 'Not recorded: this observation has no correlation for this reference.',
  pending: 'Not compared: this attempt\'s identities are not loaded.',
  unlinkedTask: 'No task evidence page is published.',
  unlinkedSession: 'No session evidence page is published.',
  unlinkedRevision: 'Does not match this attempt\'s input or result revision; no revision evidence is linked.',
  unlinkedWorkflow: 'Does not match this attempt or its predecessor; no evidence page is linked.',
  showTask: 'Show observations for this task on this page',
  browseResult: 'Browse result revision sources',
  matched: {
    attempt: 'Matches this attempt.',
    'previous-attempt': 'Matches the previous attempt.',
    'input-revision': 'Matches this attempt\'s input revision. Input sources are not browsable from this attempt.',
    'result-revision': 'Matches this attempt\'s result revision.',
  },
  openPrevious: 'Open the previous attempt',
  thought: 'Private reasoning withheld. The agent marked this message as reasoning; it is not requested, displayed or used as evidence.',
} as const;
