import {
  QoderAccount,
  QoderVariantId,
  getQoderAccountDisplayEmail,
  getQoderPlanBadge,
  getQoderUsage,
  getQoderAccountVariantId,
  resolveQoderRewardStatus,
} from '../types/qoder';
import * as qoderService from '../services/qoderService';
import { createProviderAccountStore } from './createProviderAccountStore';
import { refreshQoderCurrentAccountIds } from './useQoderCurrentAccountStore';

const QODER_ACCOUNTS_CACHE_KEY = 'agtools.qoder.accounts.cache.v2';
const QODER_CURRENT_ACCOUNT_ID_KEY = 'agtools.qoder.current_account_id';
let accountListLoaded = false;
let initialLoadRequest: Promise<void> | null = null;
export const QODER_REWARD_RETRY_DELAY_MS = 60_000;
const checkedRewardSnapshots = new Map<string, { key: string; retryAt: number }>();

async function loadAccountList(): Promise<QoderAccount[]> {
  const accounts = await qoderService.listQoderAccounts();
  accountListLoaded = true;
  return accounts;
}

// 旧缓存可能含完整 auth.v1.dat 载荷；升级时主动删除，随后由脱敏的 IPC 列表重建。
try {
  localStorage.removeItem('agtools.qoder.accounts.cache');
} catch {
  // 缓存不可用时由 store 继续从后端读取。
}

export const useQoderAccountStore = createProviderAccountStore<QoderAccount, QoderVariantId>(
  QODER_ACCOUNTS_CACHE_KEY,
  {
    listAccounts: loadAccountList,
    deleteAccount: qoderService.deleteQoderAccount,
    deleteAccounts: qoderService.deleteQoderAccounts,
    injectAccount: qoderService.injectQoderAccount,
    refreshToken: qoderService.refreshQoderToken,
    refreshAllTokens: qoderService.refreshAllQoderVariants,
    importFromJson: qoderService.importQoderFromJson,
    exportAccounts: qoderService.exportQoderAccounts,
    updateAccountTags: qoderService.updateQoderAccountTags,
  },
  {
    getDisplayEmail: getQoderAccountDisplayEmail,
    getPlanBadge: getQoderPlanBadge,
    getUsage: getQoderUsage,
    getAccountPlatformId: getQoderAccountVariantId,
  },
  {
    platformId: 'qoder',
    silentMutationRefresh: true,
    currentAccountIdKey: QODER_CURRENT_ACCOUNT_ID_KEY,
    // 通用 store 的单值当前账号固定为国际 IDE；其他变体从后端映射读取。
    acceptEmptyCurrentAccountId: true,
    resolveCurrentAccountId: async (): Promise<string | null> => {
      const ids = await refreshQoderCurrentAccountIds(useQoderAccountStore.getState().accounts);
      return ids.qoder;
    },
  },
);

/** Initial load is shared by page mounts; mutations, focus and events still reload explicitly. */
export function ensureQoderAccountsLoaded(): Promise<void> {
  if (initialLoadRequest) return initialLoadRequest;
  if (accountListLoaded) return Promise.resolve();
  initialLoadRequest = useQoderAccountStore.getState().fetchAccounts({
    silent: useQoderAccountStore.getState().accounts.length > 0,
  }).finally(() => { initialLoadRequest = null; });
  return initialLoadRequest;
}

/** Deduplicate pending/resolved snapshots; unresolved results retry after a cooldown. */
export async function checkUnknownQoderRewardStatuses(accounts: QoderAccount[]): Promise<void> {
  const currentAccounts = useQoderAccountStore.getState().accounts;
  const existingIds = new Set(currentAccounts.map((account) => account.id));
  for (const id of checkedRewardSnapshots.keys()) {
    if (!existingIds.has(id)) checkedRewardSnapshots.delete(id);
  }
  const reservations = new Map<string, { key: string; retryAt: number }>();
  const targets = accounts.filter((account) => {
    if (resolveQoderRewardStatus(account) !== 'unknown') return false;
    // A successful query can return the same expired window with a newer
    // query timestamp. That timestamp must not turn it into another target.
    const key = `${account.reward_claim_status ?? ''}:${account.reward_window_end_at ?? ''}`;
    const previous = checkedRewardSnapshots.get(account.id);
    if (previous?.key === key && Date.now() < previous.retryAt) return false;
    const reservation = { key, retryAt: Infinity };
    reservations.set(account.id, reservation);
    checkedRewardSnapshots.set(account.id, reservation);
    return true;
  });
  if (targets.length === 0) return;
  const resolved = new Set<string>();
  try {
    const updated = await qoderService.batchCheckQoderRewardStatuses(targets.map((account) => account.id));
    if (updated.length > 0) {
      await useQoderAccountStore.getState().fetchAccounts({ silent: true });
      // fetchAccounts records errors without rejecting and can be superseded by
      // another reload. Only a visible, resolved status can end retries; a successful
      // response containing an expired window must still use the cooldown.
      const visible = new Map(useQoderAccountStore.getState().accounts.map((account) => [account.id, account]));
      for (const account of updated) {
        const current = visible.get(account.id);
        if (current
          && current.reward_claim_status === account.reward_claim_status
          && current.reward_window_end_at === account.reward_window_end_at
          && current.reward_status_updated_at === account.reward_status_updated_at
          && resolveQoderRewardStatus(current) !== 'unknown') {
          resolved.add(account.id);
        }
      }
    }
  } finally {
    for (const [id, reservation] of reservations) {
      if (!resolved.has(id) && checkedRewardSnapshots.get(id) === reservation) {
        reservation.retryAt = Date.now() + QODER_REWARD_RETRY_DELAY_MS;
      }
    }
  }
}

// 定时任务刷新全部变体；页面手动批量刷新仍通过服务按当前标签页变体执行。
export async function refreshAllQoderVariants(): Promise<void> {
  await useQoderAccountStore.getState().refreshAllTokens();
}
