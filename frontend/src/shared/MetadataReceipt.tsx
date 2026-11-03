import { receiptCopy as copy } from '../copy/receipts';
import { receiptAge } from '../copy/receiptAge';
import { formatExactTimestamp } from '../copy/format';
import { commonCopy } from '../copy/common';
import { useBrowserAvailability } from '../session/useBrowserAvailability';
import { message } from './messages';
import type { ReceiptTime } from './receiptTime';
import { useReceiptAge } from './useReceiptAge';

function ReceiptText({ receipt, visible }: { receipt: ReceiptTime; visible: boolean }) {
  const age = receiptAge(useReceiptAge(receipt, visible, true));
  return <>{message(copy.received, {
    time: <span data-received-at={receipt.at} title={receipt.at}>{formatExactTimestamp(receipt.at)}</span>, age,
  })}</>;
}

/** A local display clock never refreshes data or announces repeated live-region updates. */
export function MetadataReceipt({ kind, receipt }: { kind: keyof typeof copy.labels; receipt: ReceiptTime | undefined }) {
  const { visible } = useBrowserAvailability();
  return <p class="metadata-receipt" aria-label={copy.labels[kind]}>{message(commonCopy.labeledValue, { label: copy.labels[kind], value: receipt
    ? <ReceiptText receipt={receipt} visible={visible} /> : copy.unknown })}</p>;
}
