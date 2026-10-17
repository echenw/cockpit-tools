import { create } from 'zustand';
import type { PlatformId } from '../types/platform';
import { emitAccountsChanged, emitCurrentAccountChanged } from '../utils/accountSyncEvents';

type ProviderUsage = {
  inlineSuggestionsUsedPercent: number | null;
  chatMessagesUsedPercent: number | null;
  premiumRequestsUsedPercent?: number | null;
  inlineIncluded?: boolean;
  chatIncluded?: boolean;
  premiumIncluded?: boolean;
  allowanceResetAt?: number | null;
  remainingCompletions?: number | null;
  remainingChat?: number | null;
  remainingPremiumRequests?: number | null;
  totalCompletions?: number | null;
  totalChat?: number | null;
  totalPremiumRequests?: number | null;
  usedPremiumRequests?: number | null;
};

type ProviderAccountAugmentation = {
  id: string;
  email?: string | null;
  plan_type?: string | null;
  quota?: unknown;
};

type ProviderService<TAccount, TPlatform extends PlatformId> = {
  listAccounts: () => Promise<TAccount[]>;
  deleteAccount: (accountId: string) => Promise<void>;
  deleteAccounts: (accountIds: string[]) => Promise<void>;
  injectAccount: (accountId: string, platformId?: TPlatform) => Promise<unknown>;
  refreshToken: (accountId: string, platformId?: TPlatform) => Promise<unknown>;
  refreshAllTokens: () => Promise<unknown>;
  importFromJson: (jsonContent: string) => Promise<TAccount[]>;
  exportAccounts: (accountIds: string[]) => Promise<string>;
  updateAccountTags: (accountId: string, tags: string[]) => Promise<TAccount>;
};

type ProviderMapper<TAccount> = {
  getAccountPlatformId?: (account: TAccount) => PlatformId;
  getDisplayEmail: (account: TAccount) => string;
  getPlanBadge: (account: TAccount) => string;
  getUsage: (account: TAccount) => ProviderUsage;
};

type ProviderStoreOptions = {
  platformId: PlatformId;
  /** 单账号操作完成后静默读取权威列表，避免整页加载动画。 */
  silentMutationRefresh?: boolean;
  currentAccountIdKey?: string;
  resolveCurrentAccountId?: () => Promise<string | null>;
  /** 后端可能合法返回 null（如关闭「切号同步官方登录」），允许清空当前账号。 */
  acceptEmptyCurrentAccountId?: boolean;
  persistCurrentAccountId?: boolean;
  hydrateCurrentAccountId?: boolean;
  preserveSourceQuota?: boolean;
};

export interface ProviderAccountStoreState<TAccount, TPlatform extends PlatformId = never> {
  accounts: TAccount[];
  currentAccountId: string | null;
  loading: boolean;
  error: string | null;
  fetchCurrentAccountId: () => Promise<string | null>;
  setCurrentAccountId: (accountId: string | null) => void;
  fetchAccounts: (options?: { allowEmpty?: boolean; silent?: boolean }) => Promise<void>;
  switchAccount: (accountId: string, platformId?: TPlatform) => Promise<void>;
  deleteAccounts: (accountIds: string[]) => Promise<void>;
  refreshToken: (accountId: string, platformId?: TPlatform) => Promise<void>;
  refreshAllTokens: () => Promise<void>;
  importFromJson: (jsonContent: string) => Promise<TAccount[]>;
  exportAccounts: (accountIds: string[]) => Promise<string>;
  updateAccountTags: (accountId: string, tags: string[]) => Promise<TAccount>;
}

export function createProviderAccountStore<
  TAccount extends ProviderAccountAugmentation,
  TPlatform extends PlatformId = never,
>(
  cacheKey: string,
  service: ProviderService<TAccount, TPlatform>,
  mapper: ProviderMapper<TAccount>,
  options: ProviderStoreOptions,
) {
  const currentAccountIdKey = options?.currentAccountIdKey ?? null;
  const hasCurrentAccountResolver = typeof options?.resolveCurrentAccountId === 'function';
  const acceptEmptyCurrentAccountId = options?.acceptEmptyCurrentAccountId === true;
  const shouldPersistCurrentAccountId =
    options?.persistCurrentAccountId ?? !hasCurrentAccountResolver;
  const shouldHydrateCurrentAccountId =
    options?.hydrateCurrentAccountId ?? shouldPersistCurrentAccountId;
  let allowNextEmptyAccountList = false;
  let allowNextEmptyCurrentAccountId = false;
  let fetchAccountsSeq = { current: 0 };
  let fetchCurrentAccountSeq = 0;

  const resolveChangedPlatformIds = (accounts: TAccount[], accountIds: string[]): PlatformId[] => {
    if (!mapper.getAccountPlatformId) return [options.platformId];
    const platformIds = new Set<PlatformId>();
    for (const account of accounts) {
      if (accountIds.includes(account.id)) platformIds.add(mapper.getAccountPlatformId(account));
    }
    return platformIds.size > 0 ? [...platformIds] : [options.platformId];
  };

  const loadCachedAccounts = (): TAccount[] => {
    try {
      const raw = localStorage.getItem(cacheKey);
      if (!raw) return [];
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? (parsed as TAccount[]) : [];
    } catch {
      return [];
    }
  };

  const persistAccountsCache = (accounts: TAccount[]) => {
    try {
      localStorage.setItem(cacheKey, JSON.stringify(accounts));
    } catch {
      // ignore cache write failures
    }
  };

  const loadCurrentAccountId = (): string | null => {
    if (!currentAccountIdKey || !shouldHydrateCurrentAccountId) {
      return null;
    }

    try {
      const raw = localStorage.getItem(currentAccountIdKey);
      const value = raw?.trim();
      return value ? value : null;
    } catch {
      return null;
    }
  };

  const persistCurrentAccountId = (accountId: string | null) => {
    if (!currentAccountIdKey || !shouldPersistCurrentAccountId) {
      return;
    }

    try {
      if (accountId) {
        localStorage.setItem(currentAccountIdKey, accountId);
      } else {
        localStorage.removeItem(currentAccountIdKey);
      }
    } catch {
      // ignore cache write failures
    }
  };

  const normalizeCurrentAccountId = (
    accountId: string | null | undefined,
    accounts: TAccount[],
  ): string | null => {
    const value = accountId?.trim();
    if (!value) return null;
    if (accounts.length === 0) return value;
    return accounts.some((account) => account.id === value) ? value : null;
  };

  const mapAccountsForUnifiedView = (accounts: TAccount[]): TAccount[] => {
    return accounts.map((account) => {
      const email = mapper.getDisplayEmail(account);
      const usage = mapper.getUsage(account);
      const hourlyPct =
        usage.inlineSuggestionsUsedPercent ?? usage.chatMessagesUsedPercent;
      const weeklyPct =
        usage.chatMessagesUsedPercent ?? usage.inlineSuggestionsUsedPercent;
      const quota =
        hourlyPct == null && weeklyPct == null
          ? undefined
          : {
              hourly_percentage: hourlyPct ?? 0,
              weekly_percentage: weeklyPct ?? 0,
              hourly_reset_time: usage.allowanceResetAt ?? null,
              weekly_reset_time: usage.allowanceResetAt ?? null,
              raw_data: {
                remainingCompletions: usage.remainingCompletions,
                remainingChat: usage.remainingChat,
                remainingPremiumRequests: usage.remainingPremiumRequests,
                totalCompletions: usage.totalCompletions,
                totalChat: usage.totalChat,
                totalPremiumRequests: usage.totalPremiumRequests,
                usedPremiumRequests: usage.usedPremiumRequests,
                premiumRequestsUsedPercent: usage.premiumRequestsUsedPercent ?? null,
                inlineIncluded: usage.inlineIncluded === true,
                chatIncluded: usage.chatIncluded === true,
                premiumIncluded: usage.premiumIncluded === true,
              },
            };

      return {
        ...account,
        email,
        plan_type: mapper.getPlanBadge(account),
        quota: options.preserveSourceQuota ? account.quota : quota,
      };
    });
  };

  return create<ProviderAccountStoreState<TAccount, TPlatform>>((set, get) => ({
    accounts: loadCachedAccounts(),
    currentAccountId: loadCurrentAccountId(),
    loading: false,
    error: null,

    fetchCurrentAccountId: async () => {
      const requestId = ++fetchCurrentAccountSeq;
      const accounts = get().accounts;

      if (accounts.length === 0) {
        set({ currentAccountId: null });
        persistCurrentAccountId(null);
        return null;
      }

      if (!options?.resolveCurrentAccountId) {
        const currentAccountId = normalizeCurrentAccountId(get().currentAccountId, accounts);
        set({ currentAccountId });
        persistCurrentAccountId(currentAccountId);
        return currentAccountId;
      }

      try {
        const resolvedAccountId = await options.resolveCurrentAccountId();
        if (requestId !== fetchCurrentAccountSeq) {
          return get().currentAccountId;
        }
        if (
          !resolvedAccountId &&
          get().currentAccountId &&
          accounts.length > 0 &&
          !acceptEmptyCurrentAccountId &&
          !allowNextEmptyCurrentAccountId
        ) {
          console.warn(
            `[Provider Store] 忽略异常空当前账号，保留本地缓存: ${cacheKey}`,
          );
          return get().currentAccountId;
        }
        allowNextEmptyCurrentAccountId = false;
        const currentAccountId = normalizeCurrentAccountId(resolvedAccountId, accounts);
        set({ currentAccountId });
        persistCurrentAccountId(currentAccountId);
        return currentAccountId;
      } catch (error) {
        if (requestId !== fetchCurrentAccountSeq) {
          return get().currentAccountId;
        }
        console.error(`[Provider Store] Failed to resolve current account for ${cacheKey}:`, error);
        const currentAccountId = normalizeCurrentAccountId(get().currentAccountId, accounts);
        set({ currentAccountId });
        persistCurrentAccountId(currentAccountId);
        return currentAccountId;
      } finally {
        if (requestId === fetchCurrentAccountSeq) {
          allowNextEmptyCurrentAccountId = false;
        }
      }
    },

    setCurrentAccountId: (accountId: string | null) => {
      fetchCurrentAccountSeq += 1;
      const currentAccountId = normalizeCurrentAccountId(accountId, get().accounts);
      set({ currentAccountId });
      persistCurrentAccountId(currentAccountId);
    },

    fetchAccounts: async (requestOptions) => {
      const requestId = ++fetchAccountsSeq.current;
      set(requestOptions?.silent ? { error: null } : { loading: true, error: null });
      try {
        const accounts = await service.listAccounts();
        if (requestId !== fetchAccountsSeq.current) {
          return;
        }
        if (accounts.length === 0 && get().accounts.length > 0 && !allowNextEmptyAccountList && !requestOptions?.allowEmpty) {
          console.warn(`[Provider Store] 忽略异常空账号列表，保留本地缓存: ${cacheKey}`);
          set({ loading: false });
          return;
        }
        allowNextEmptyAccountList = false;
        const mapped = mapAccountsForUnifiedView(accounts);
        set({ accounts: mapped, loading: false });
        persistAccountsCache(mapped);
        await get().fetchCurrentAccountId();
      } catch (e) {
        if (requestId !== fetchAccountsSeq.current) {
          return;
        }
        set({ error: String(e), loading: false });
      } finally {
        if (requestId === fetchAccountsSeq.current) {
          allowNextEmptyAccountList = false;
        }
      }
    },

    deleteAccounts: async (accountIds: string[]) => {
      if (accountIds.length === 0) return;
      const previousCurrentAccountId = get().currentAccountId;
      const deleteIdSet = new Set(accountIds);
      allowNextEmptyAccountList = get().accounts.every((account) =>
        deleteIdSet.has(account.id),
      );
      allowNextEmptyCurrentAccountId = previousCurrentAccountId
        ? deleteIdSet.has(previousCurrentAccountId)
        : false;
      const changedPlatformIds = resolveChangedPlatformIds(get().accounts, accountIds);
      try {
        if (accountIds.length === 1) {
          await service.deleteAccount(accountIds[0]);
        } else {
          await service.deleteAccounts(accountIds);
        }
        await get().fetchAccounts();
        for (const platformId of changedPlatformIds) {
          await emitAccountsChanged({
            platformId,
            reason: 'delete',
          });
        }
        const nextCurrentAccountId = get().currentAccountId;
        if (previousCurrentAccountId !== nextCurrentAccountId) {
          await emitCurrentAccountChanged({
            platformId: options.platformId,
            accountId: nextCurrentAccountId,
            reason: 'delete',
          });
        }
      } finally {
        allowNextEmptyAccountList = false;
        allowNextEmptyCurrentAccountId = false;
      }
    },

    switchAccount: async (accountId: string, requestedPlatformId?: TPlatform) => {
      const account = get().accounts.find((item) => item.id === accountId);
      const platformId = requestedPlatformId ?? (account && mapper.getAccountPlatformId
        ? mapper.getAccountPlatformId(account)
        : options.platformId);
      try {
        await service.injectAccount(accountId, requestedPlatformId);
      } catch (error) {
        // 多变体切号可能已写入登录态，但后续启动失败。重新读取实际状态，不广播成功。
        if (mapper.getAccountPlatformId) {
          try {
            await get().fetchAccounts({ silent: options.silentMutationRefresh });
          } catch (refreshError) {
            console.error(`[Provider Store] Failed to refresh accounts after switch error for ${cacheKey}:`, refreshError);
          }
        }
        throw error;
      }
      // acceptEmpty：以后端为准（如 Grok 关闭「切号同步官方登录」时无当前账号）。
      // 其他平台仍乐观写入当前账号，再拉取列表/状态。
      if (acceptEmptyCurrentAccountId && hasCurrentAccountResolver) {
        allowNextEmptyCurrentAccountId = true;
        await get().fetchAccounts({ silent: options.silentMutationRefresh });
      } else {
        get().setCurrentAccountId(accountId);
        await get().fetchAccounts({ silent: options.silentMutationRefresh });
      }
      await emitCurrentAccountChanged({
        platformId,
        accountId: requestedPlatformId !== undefined || platformId !== options.platformId
          ? accountId
          : get().currentAccountId,
        reason: 'switch',
      });
    },

    refreshToken: async (accountId: string, platformId?: TPlatform) => {
      try {
        await service.refreshToken(accountId, platformId);
      } catch (error) {
        // 后端失败前可能已经持久化重登标记或部分刷新结果。
        try {
          await get().fetchAccounts({ silent: options.silentMutationRefresh });
        } catch (refreshError) {
          console.error(`[Provider Store] Failed to reload accounts after refresh error for ${cacheKey}:`, refreshError);
        }
        throw error;
      }
      // 命令快照可能早于并发标签/额度写入；统一读取后端最新状态，
      // 并复用 fetchAccounts 的请求序号，阻止更早的列表响应覆盖结果。
      await get().fetchAccounts({ silent: options.silentMutationRefresh });
    },

    refreshAllTokens: async () => {
      let error: unknown;
      try {
        await service.refreshAllTokens();
      } catch (err) {
        error = err;
      }
      await get().fetchAccounts();
      if (error) {
        throw error;
      }
    },

    importFromJson: async (jsonContent: string) => {
      const accounts = await service.importFromJson(jsonContent);
      await get().fetchAccounts();
      for (const platformId of resolveChangedPlatformIds(accounts, accounts.map((account) => account.id))) {
        await emitAccountsChanged({
          platformId,
          reason: 'import',
        });
      }
      return accounts;
    },

    exportAccounts: async (accountIds: string[]) => {
      return await service.exportAccounts(accountIds);
    },

    updateAccountTags: async (accountId: string, tags: string[]) => {
      const account = await service.updateAccountTags(accountId, tags);
      await get().fetchAccounts({ silent: options.silentMutationRefresh });
      return account;
    },
  }));
}
