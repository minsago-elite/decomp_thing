import { textMessage } from '../shared/messages';

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
  if (seconds < 10) return activityReceiptAgeCopy.lessThan10SecondsAgo;
  if (seconds < 60) return textMessage(activityReceiptAgeCopy.secondsAgo, { count: Math.floor(seconds / 10) * 10 });
  if (seconds < 3600) return textMessage(seconds < 120 ? activityReceiptAgeCopy.minuteAgo : activityReceiptAgeCopy.minutesAgo, { count: Math.floor(seconds / 60) });
  if (seconds < 86400) return textMessage(seconds < 7200 ? activityReceiptAgeCopy.hourAgo : activityReceiptAgeCopy.hoursAgo, { count: Math.floor(seconds / 3600) });
  return textMessage(seconds < 172800 ? activityReceiptAgeCopy.dayAgo : activityReceiptAgeCopy.daysAgo, { count: Math.floor(seconds / 86400) });
}
