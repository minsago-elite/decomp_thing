import type { StageState } from '../jobs/activityStages';

export const stageLabels = {
  waiting: 'Waiting',
  running: 'Running',
  blocked: 'Blocked or unresolved',
  validating: 'Validating',
  accepted: 'Accepted',
  'rolled-back': 'Rolled back',
  completed: 'Completed without acceptance',
  cancelled: 'Cancelled',
  failed: 'Terminal failure',
  unknown: 'Stage not reported',
} as const satisfies Record<StageState, string>;

export const activityStagesCopy = {
  title: 'Stages',
  attempt: 'Attempt at snapshot',
  attemptUnknown: 'Read activity to show the attempt state.',
  attemptAuthority: 'The attempt state comes from the durable attempt record. Task stages below are journal observations and do not establish acceptance.',
  taskList: 'Reported task stages',
  taskColumn: 'Task digest',
  stageColumn: 'Latest reported stage',
  sinceColumn: 'Reported at sequence',
  observationsColumn: 'Observations on this page',
  untracked: 'No recorded task',
  showTask: 'Show observations for task {digest}',
  showTaskShort: 'Show observations',
  noTasks: 'No stage observations are retained on this page yet.',
  counts: 'Observed tasks: {total}. {summary}',
  countPart: '{label}: {count}',
  progressCount: '{completed} observed tasks reached a final reported stage. The total number of tasks is not reported, so no percentage is shown.',
  progressPercent: '{completed} of {total} tasks finished ({percent}%).',
  pageScope: 'Stages summarize only the observations on this page.',
} as const;
