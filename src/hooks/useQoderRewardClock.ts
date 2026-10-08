import { useEffect, useState } from 'react';
import { getQoderRewardWindowEndMs, type QoderAccount } from '../types/qoder';

/** Invalidate reward projections at expiry, including after a sleeping/hidden window resumes. */
export function useQoderRewardClock(accounts: QoderAccount[]): number {
  const [now, setNow] = useState(Date.now);

  useEffect(() => {
    const update = () => setNow(Date.now());
    const onVisible = () => {
      if (document.visibilityState === 'visible') update();
    };
    window.addEventListener('focus', update);
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      window.removeEventListener('focus', update);
      document.removeEventListener('visibilitychange', onVisible);
    };
  }, []);

  useEffect(() => {
    const nextExpiry = accounts.reduce((next, account) => {
      const expiry = getQoderRewardWindowEndMs(account);
      return expiry != null && expiry > now ? Math.min(next, expiry) : next;
    }, Infinity);
    if (!Number.isFinite(nextExpiry)) return;
    // Clamp to the browser's maximum timer delay; overdue timers fire on the next turn.
    const delay = Math.max(1, Math.min(nextExpiry - Date.now(), 2_147_483_647));
    const timer = window.setTimeout(() => setNow(Date.now()), delay);
    return () => window.clearTimeout(timer);
  }, [accounts, now]);

  return now;
}
