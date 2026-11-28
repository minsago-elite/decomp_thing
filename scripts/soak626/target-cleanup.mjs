/** Close companion pages and wait until Chromium no longer reports them. */
export async function closeCompanionTargets({ getTargets, closeTarget, primaryTargetId,
  deadlineMs, now = Date.now, delay }) {
  const closeRequested = new Set();
  let remaining = [];
  while (now() < deadlineMs) {
    const { targetInfos } = await getTargets();
    remaining = targetInfos.filter(target => target.type === 'page' && target.targetId !== primaryTargetId);
    for (const target of remaining) {
      if (closeRequested.has(target.targetId)) continue;
      closeRequested.add(target.targetId);
      await closeTarget(target.targetId);
    }
    if (remaining.length === 0) {
      return { closed: true, closeRequests: closeRequested.size, remainingCount: 0 };
    }
    await delay(Math.min(100, Math.max(0, deadlineMs - now())));
  }
  const { targetInfos } = await getTargets();
  remaining = targetInfos.filter(target => target.type === 'page' && target.targetId !== primaryTargetId);
  return { closed: remaining.length === 0, closeRequests: closeRequested.size, remainingCount: remaining.length };
}
