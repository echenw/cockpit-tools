import { create } from 'zustand';
import { getProviderCurrentAccountId } from '../services/providerCurrentAccountService';
import { QODER_VARIANT_IDS, qoderAccountSupportsVariant, type QoderAccount, type QoderVariantId } from '../types/qoder';

export type QoderCurrentAccountIds = Record<QoderVariantId, string | null>;

// A window-wide projection of provider_current_state, retained across page mounts.
export const useQoderCurrentAccountStore = create<{ currentIds: QoderCurrentAccountIds }>(() => ({
  currentIds: { qoder: null, qoder_app: null, qoder_cn_ide: null, qoder_cn_app: null },
}));

let refreshSequence = 0;
let pending: { accounts: QoderAccount[]; promise: Promise<QoderCurrentAccountIds> } | null = null;

export function refreshQoderCurrentAccountIds(accounts: QoderAccount[]): Promise<QoderCurrentAccountIds> {
  if (pending?.accounts === accounts) return pending.promise;
  const sequence = ++refreshSequence;
  const promise = Promise.allSettled(QODER_VARIANT_IDS.map(getProviderCurrentAccountId)).then((results) => {
    if (sequence !== refreshSequence) return useQoderCurrentAccountStore.getState().currentIds;
    const previous = useQoderCurrentAccountStore.getState().currentIds;
    const next = { ...previous };
    results.forEach((result, index) => {
      const variant = QODER_VARIANT_IDS[index];
      const id = result.status === 'fulfilled' ? result.value : previous[variant];
      if (result.status === 'rejected') {
        console.error(`Failed to read current Qoder account: ${variant}`, result.reason);
      }
      next[variant] = accounts.some((account) => account.id === id && qoderAccountSupportsVariant(account, variant))
        ? id : null;
    });
    if (QODER_VARIANT_IDS.some((variant) => next[variant] !== previous[variant])) {
      useQoderCurrentAccountStore.setState({ currentIds: next });
    }
    return next;
  }).finally(() => {
    if (sequence === refreshSequence) pending = null;
  });
  pending = { accounts, promise };
  return promise;
}
