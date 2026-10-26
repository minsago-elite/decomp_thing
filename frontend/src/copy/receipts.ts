export const receiptCopy = {
  received: 'Received in this tab {time} ({age}). Source observation age and current server state may differ.',
  unknown: 'Receipt time was not recorded in this tab.',
  labels: {
    library: 'Displayed job library', job: 'Job metadata', run: 'Attempt metadata', history: 'Attempt history',
    runtime: 'Runtime report', recovery: 'Recovery inventory', pin: 'Progress pin policy', upload: 'Upload progress',
    exploration: 'Exploration report', explorationCases: 'Exploration case bytes',
    validationHistory: 'Validation history', validationReport: 'Selected validation report', baseline: 'Comparison baseline',
    sourceResolution: 'Source link resolution', directory: 'Source directory metadata', file: 'Source file metadata',
    range: 'Source range bytes', digest: 'Source digest check',
  },
} as const;
