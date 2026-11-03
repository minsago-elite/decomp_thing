import { textMessage } from '../shared/messages';
import { pluralForm } from './format';

export const activityReceiptAgeCopy = {
  "received": "Last activity received: {time} ({age} in this tab). This is receipt age, not the age of the source observations.",
  "lessThan10SecondsAgo": "less than 10 seconds ago",
  "secondsAgo": "about {count} seconds ago",
  "minuteAgo": "about {count} minute ago",
  "minutesAgo": "about {count} minutes ago",
  "hourAgo": "about {count} hour ago",
  "hoursAgo": "about {count} hours ago",
  "dayAgo": "about {count} day ago",
  "daysAgo": "about {count} days ago"
} as const;

/** Relative receipt age is display copy; the monotonic clock remains in the component. */
export function receiptAge(seconds: number): string {
  const copy = activityReceiptAgeCopy;
  if (seconds < 10) return copy.lessThan10SecondsAgo;
  if (seconds < 60) return textMessage(copy.secondsAgo, { count: Math.floor(seconds / 10) * 10 });
  const unit = (size: number, forms: { one: string; other: string }) => {
    const count = Math.floor(seconds / size);
    return textMessage(pluralForm(count, forms), { count });
  };
  if (seconds < 3600) return unit(60, { one: copy.minuteAgo, other: copy.minutesAgo });
  if (seconds < 86400) return unit(3600, { one: copy.hourAgo, other: copy.hoursAgo });
  return unit(86400, { one: copy.dayAgo, other: copy.daysAgo });
}
