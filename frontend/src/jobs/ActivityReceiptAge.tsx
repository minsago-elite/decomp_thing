import { activityReceiptAgeCopy as copy, receiptAge } from '../copy/attempt';
import { message as displayMessage } from '../shared/messages';
import { formatExactTimestamp } from './metadataFormat';
import { useReceiptAge } from '../shared/useReceiptAge';
import type { ReceiptTime } from '../shared/receiptTime';

export type ActivityReceiptTime = ReceiptTime;

/** Elapsed receipt age uses this tab's monotonic clock and reconciles time spent suspended. */
export function ActivityReceiptAge({ receipt, visible }: { receipt: ActivityReceiptTime; visible: boolean }) {
  const age = receiptAge(useReceiptAge(receipt, visible));
  return <>{displayMessage(copy.received, { time: <time dateTime={receipt.at} title={receipt.at}>{formatExactTimestamp(receipt.at)}</time>, age })}</>;
}
