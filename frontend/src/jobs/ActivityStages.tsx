import { activityStagesCopy as copy, stageLabels } from '../copy/activityStages';
import { message as displayMessage, textMessage } from '../shared/messages';
import { StateMark } from '../shared/StateMark';
import type { Run, WebEvent } from '../api/generated';
import { attemptStage, progressMeasure, stageCounts, stageTone, taskStages } from './activityStages';
import type { StageState } from './activityStages';

const finalStates: readonly StageState[] = ['accepted', 'rolled-back', 'completed', 'cancelled', 'failed'];

function shortDigest(digest: string): string { return `${digest.slice(0, 12)}…`; }

/** Stage summary for the retained page; a task button narrows the existing filter, never the journal. */
export function ActivityStages({ run, events, onSelectTask }: {
  run: Pick<Run, 'state' | 'acceptance'> | null; events: readonly WebEvent[]; onSelectTask?: (digest: string) => void;
}) {
  const stages = taskStages(events);
  // Attempt-wide observations keep their own row but are never counted as a task.
  const counts = stageCounts(stages.filter(stage => stage.taskDigest !== null));
  const finished = finalStates.reduce((sum, state) => sum + counts[state], 0);
  // No producer declares a complete task total yet, so the measure stays a count.
  const measure = progressMeasure(BigInt(finished), null);
  const reported = (Object.keys(stageLabels) as StageState[]).filter(state => counts[state] > 0);
  const attempt = run ? attemptStage(run) : null;
  return <section aria-labelledby="activity-stages-title" class="activity-stages">
    <h3 id="activity-stages-title">{copy.title}</h3>
    <p>{copy.attempt}: {attempt ? <StateMark tone={stageTone(attempt)}>{stageLabels[attempt]}</StateMark> : copy.attemptUnknown}</p>
    <p>{copy.attemptAuthority}</p>
    {stages.length === 0 ? <p>{copy.noTasks}</p> : <>
      <p>{displayMessage(copy.counts, { total: stages.filter(stage => stage.taskDigest !== null).length, summary: reported.map(state => textMessage(copy.countPart, { label: stageLabels[state], count: counts[state] })).join('; ') })}</p>
      <p>{measure.kind === 'percent'
        ? displayMessage(copy.progressPercent, { completed: measure.completed.toString(), total: measure.total.toString(), percent: measure.percent })
        : displayMessage(copy.progressCount, { completed: measure.completed.toString() })}</p>
      <div class="retained-case-table">
        <table>
          <caption>{copy.taskList}</caption>
          <thead><tr><th scope="col">{copy.taskColumn}</th><th scope="col">{copy.stageColumn}</th><th scope="col">{copy.sinceColumn}</th><th scope="col">{copy.observationsColumn}</th></tr></thead>
          <tbody>
            {stages.map(stage => <tr key={stage.taskDigest ?? ''}>
              <th scope="row">{stage.taskDigest ? <>
                <code title={stage.taskDigest}>{shortDigest(stage.taskDigest)}</code>
                {onSelectTask && <><br /><button type="button" aria-label={textMessage(copy.showTask, { digest: shortDigest(stage.taskDigest) })} onClick={() => onSelectTask(stage.taskDigest!)}>{copy.showTaskShort}</button></>}
              </> : copy.untracked}</th>
              <td><StateMark tone={stageTone(stage.state)}>{stageLabels[stage.state]}</StateMark></td>
              <td>{stage.sequence}</td>
              <td>{stage.observations}</td>
            </tr>)}
          </tbody>
        </table>
      </div>
    </>}
    <p>{copy.pageScope}</p>
  </section>;
}
