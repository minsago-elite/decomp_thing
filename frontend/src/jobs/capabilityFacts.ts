import type { Capability, ExecutionLimits } from '../api/generated';
import { commonCopy } from '../copy/common';
import { jobCopy as copy } from '../copy/job';
import { textMessage } from '../shared/messages';

interface CapabilityFact {
  key: 'contractVersion' | 'executionLimits' | keyof ExecutionLimits;
  label: string;
  value: string;
}

const limitLabels = {
  wallClockMs: copy.reportedWallClockLimit,
  idleMs: copy.reportedIdleLimit,
  maxOutputBytes: copy.reportedOutputLimit,
  maxToolCalls: copy.reportedToolCallLimit,
} satisfies Record<keyof ExecutionLimits, string>;

function limitValue(key: keyof ExecutionLimits, value: unknown): string {
  if (typeof value !== 'string') return copy.capabilityNotReported;
  const decimal = /^(?:0|[1-9][0-9]{0,19})$/.exec(value);
  // JavaScript's end anchor can stop before a final line break; require the whole value.
  if (decimal?.[0] !== value || BigInt(value) > 18446744073709551615n) return copy.capabilityNotReported;
  switch (key) {
    case 'wallClockMs': case 'idleMs': return textMessage(copy.capabilityMilliseconds, { value });
    case 'maxOutputBytes': return textMessage(commonCopy.bytes, { value });
    case 'maxToolCalls': return value;
  }
}

/** Format the last capability report only; no defaults, selection or admission decisions. */
export function reportedCapabilityFacts(capability: Pick<Capability, 'agentContractVersion' | 'limits'>): CapabilityFact[] {
  const version = capability.agentContractVersion;
  const facts: CapabilityFact[] = [{ key: 'contractVersion', label: copy.reportedAgentContractVersion,
    value: typeof version === 'number' && Number.isInteger(version) && version >= 1 && version <= 65535
      ? String(version) : copy.capabilityNotReported }];
  const limits = capability.limits;
  if (limits === null || typeof limits !== 'object' || Array.isArray(limits)) {
    facts.push({ key: 'executionLimits', label: copy.reportedExecutionLimits, value: copy.capabilityNotReported });
  } else {
    for (const key of ['wallClockMs', 'idleMs', 'maxOutputBytes', 'maxToolCalls'] as const) {
      facts.push({ key, label: limitLabels[key], value: limitValue(key, limits[key]) });
    }
  }
  return facts;
}
