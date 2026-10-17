import { useEffect, useMemo } from 'react';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { ensureQoderAccountsLoaded, useQoderAccountStore } from '../stores/useQoderAccountStore';
import { useQoderCurrentAccountStore } from '../stores/useQoderCurrentAccountStore';
import { ACCOUNTS_CHANGED_EVENT, CURRENT_ACCOUNT_CHANGED_EVENT, type AccountSyncEventPayload } from '../utils/accountSyncEvents';
import { QODER_VARIANT_IDS, qoderAccountSupportsVariant, isQoderVariantId, type QoderAccount, type QoderVariantId } from '../types/qoder';

// 后端 provider_current_state 是权威；共享 store 保留窗口内的只读投影。
export function useQoderCurrentAccountIds(accounts: QoderAccount[]) {
  const currentIds = useQoderCurrentAccountStore((state) => state.currentIds);

  useEffect(() => {
    let disposed = false;
    const unlisteners: Array<() => void> = [];
    const refresh = () => {
      if (!disposed) void useQoderAccountStore.getState().fetchAccounts({ silent: true });
    };
    void ensureQoderAccountsLoaded();
    void listen('qoder-accounts-updated', refresh).then((unlisten) => {
      if (disposed) unlisten();
      else unlisteners.push(unlisten);
    }).catch((error) => console.error('Failed to subscribe to Qoder account updates', error));
    for (const eventName of [ACCOUNTS_CHANGED_EVENT, CURRENT_ACCOUNT_CHANGED_EVENT]) {
      void listen<AccountSyncEventPayload>(eventName, ({ payload }) => {
        if (disposed || !payload || !isQoderVariantId(payload.platformId)) return;
        if (payload.sourceWindowLabel === getCurrentWindow().label) return;
        void useQoderAccountStore.getState().fetchAccounts({ silent: true, allowEmpty: payload.reason === 'delete' });
      }).then((unlisten) => {
        if (disposed) unlisten();
        else unlisteners.push(unlisten);
      }).catch((error) => console.error('Failed to subscribe to Qoder account changes', error));
    }
    window.addEventListener('focus', refresh);
    return () => {
      disposed = true;
      window.removeEventListener('focus', refresh);
      unlisteners.forEach((unlisten) => unlisten());
    };
  }, []);

  return useMemo(() => Object.fromEntries(QODER_VARIANT_IDS.map((variant) => [
    variant,
    accounts.some((account) => account.id === currentIds[variant] && qoderAccountSupportsVariant(account, variant))
      ? currentIds[variant] : null,
  ])) as Record<QoderVariantId, string | null>, [accounts, currentIds]);
}
