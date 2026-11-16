import { promises as fs } from 'node:fs';

function parseProcStat(text) {
  const close = text.lastIndexOf(')');
  if (close < 0) throw new Error('Malformed /proc stat');
  const pid = Number(text.slice(0, text.indexOf(' ')));
  const fields = text.slice(close + 2).trim().split(/\s+/);
  const parentPid = Number(fields[1]); // fields begin at Linux stat field 3 (state).
  const startTime = Number(fields[19]); // field 22, starttime.
  if (![pid, parentPid, startTime].every(Number.isSafeInteger)) throw new Error('Malformed /proc stat counters');
  return { pid, parentPid, startTime };
}

async function readIdentity(pid) {
  return parseProcStat(await fs.readFile(`/proc/${pid}/stat`, 'utf8'));
}

async function readResources(identity) {
  const { pid } = identity;
  const statusText = await fs.readFile(`/proc/${pid}/status`, 'utf8');
  const rss = statusText.match(/^VmRSS:\s+(\d+)\s+kB$/m);
  if (!rss) throw new Error(`Missing VmRSS for process ${pid}`);
  const descriptors = await fs.readdir(`/proc/${pid}/fd`);
  return { ...identity, rssBytes: Number(rss[1]) * 1024, fdCount: descriptors.length };
}

/** Snapshot a Linux process tree without retaining command lines, paths, or descriptor targets. */
export async function sampleProcessTree(rootPid) {
  const entries = await fs.readdir('/proc', { withFileTypes: true });
  const pids = entries.filter((entry) => entry.isDirectory() && /^\d+$/.test(entry.name)).map((entry) => Number(entry.name));
  const processes = [];
  for (const pid of pids) {
    try { processes.push(await readIdentity(pid)); }
    catch (error) {
      if (['ENOENT', 'ESRCH', 'EACCES'].includes(error.code)) continue;
      throw error;
    }
  }
  const byPid = new Map(processes.map((process) => [process.pid, process]));
  if (!byPid.has(rootPid)) throw new Error('Packaged JVM launcher exited during resource sampling');
  const selected = new Map([[rootPid, byPid.get(rootPid)]]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const process of processes) {
      if (!selected.has(process.pid) && selected.has(process.parentPid)) {
        selected.set(process.pid, process);
        changed = true;
      }
    }
  }
  const tree = [];
  for (const identity of selected.values()) {
    try { tree.push(await readResources(identity)); }
    catch (error) {
      if (['ENOENT', 'ESRCH', 'EACCES'].includes(error.code)) continue;
      throw error;
    }
  }
  if (!tree.some((process) => process.pid === rootPid)) throw new Error('Packaged JVM launcher exited during resource sampling');
  return {
    rootPid,
    rootStartTime: byPid.get(rootPid).startTime,
    processCount: tree.length,
    jvmTreeRssBytes: tree.reduce((sum, process) => sum + process.rssBytes, 0),
    fdCount: tree.reduce((sum, process) => sum + process.fdCount, 0),
    processIdentities: tree.map(({ pid, startTime }) => ({ pid, startTime })),
  };
}
