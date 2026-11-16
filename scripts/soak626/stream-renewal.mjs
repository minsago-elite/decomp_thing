/** Waits for a successful stream response counted after the caller's pre-navigation snapshot. */
export async function waitForSuccessfulStreamOpen({ startCount, getCount, deadlineMs, now = Date.now, delay }) {
  while (getCount() === startCount && now() < deadlineMs) await delay(100);
  return getCount() > startCount;
}
