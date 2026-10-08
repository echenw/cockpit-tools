import assert from 'node:assert/strict';
import test from 'node:test';
import { clearMocks, mockIPC } from '@tauri-apps/api/mocks';
import type { QoderAccount, QoderVariantId } from '../types/qoder';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

test('Qoder client navigation shares account and current-state projections', async (t) => {
  const previousWindow = Object.getOwnPropertyDescriptor(globalThis, 'window');
  const previousStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
  };
  Object.defineProperty(globalThis, 'window', { configurable: true, value: {} });
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: storage });
  t.after(() => {
    clearMocks();
    if (previousWindow) Object.defineProperty(globalThis, 'window', previousWindow);
    else Reflect.deleteProperty(globalThis, 'window');
    if (previousStorage) Object.defineProperty(globalThis, 'localStorage', previousStorage);
    else Reflect.deleteProperty(globalThis, 'localStorage');
  });
  const accounts: QoderAccount[] = [
    { id: 'intl', variant: 'qoder_app', email: '', created_at: 1, last_used: 1 },
    { id: 'cn', variant: 'qoder_cn_app', email: '', created_at: 1, last_used: 1 },
  ];
  const operations: Array<{ command: string; accountId: string; variantKey: unknown }> = [];
  const switchEvents: Array<{ platformId: unknown; accountId: unknown }> = [];
  let switchError: Error | null = null;
  let listCalls = 0;
  let currentCalls = 0;
  let rewardCalls = 0;
  const firstList = deferred<QoderAccount[]>();
  let listResponse: () => Promise<QoderAccount[]> = () => firstList.promise;
  let rewardResponse: () => Promise<QoderAccount[]> = async () => [];
  let currentResponse: (platform: string) => Promise<string | null> = async (platform) =>
    platform.startsWith('qoder_cn_') ? 'cn' : 'intl';
  mockIPC((command, args) => {
    if (command === 'inject_qoder_account' || command === 'refresh_qoder_token') {
      assert.ok(args && 'accountId' in args && 'variantKey' in args);
      const accountId = String(args.accountId);
      operations.push({ command, accountId, variantKey: args.variantKey });
      if (command === 'inject_qoder_account') {
        if (switchError) throw switchError;
        return 'switched';
      }
      return accounts.find((account) => account.id === accountId);
    }
    if (command === 'plugin:event|emit') {
      assert.ok(args && 'event' in args && 'payload' in args);
      if (args.event === 'accounts:current-changed') {
        const payload = args.payload;
        assert.ok(payload && typeof payload === 'object' && 'platformId' in payload && 'accountId' in payload);
        switchEvents.push({ platformId: payload.platformId, accountId: payload.accountId });
      }
      return;
    }
    if (command === 'list_qoder_accounts') { listCalls++; return listResponse(); }
    if (command === 'get_provider_current_account_id') {
      currentCalls++;
      assert.ok(args && 'platform' in args);
      return currentResponse(String(args.platform));
    }
    if (command === 'batch_check_qoder_reward_statuses') { rewardCalls++; return rewardResponse(); }
    throw new Error(`Unexpected IPC in isolated test: ${command}`);
  });
  const { ensureQoderAccountsLoaded, checkUnknownQoderRewardStatuses, useQoderAccountStore } =
    await import('./useQoderAccountStore.ts');
  const { useQoderCurrentAccountStore, refreshQoderCurrentAccountIds } =
    await import('./useQoderCurrentAccountStore.ts');

  await t.test('duplicate initialization and four client visits do not reload accounts or reset current IDs', async () => {
    const first = ensureQoderAccountsLoaded();
    const duplicate = ensureQoderAccountsLoaded();
    assert.equal(listCalls, 1);
    firstList.resolve(accounts);
    await Promise.all([first, duplicate]);
    assert.deepEqual(useQoderCurrentAccountStore.getState().currentIds, {
      qoder: 'intl', qoder_app: 'intl', qoder_cn_ide: 'cn', qoder_cn_app: 'cn',
    });
    for (let visit = 0; visit < 4; visit++) await ensureQoderAccountsLoaded();
    assert.equal(listCalls, 1);
    assert.equal(currentCalls, 4);
    assert.equal(useQoderCurrentAccountStore.getState().currentIds.qoder_app, 'intl');
  });

  await t.test('returning to the same unknown reward snapshot does not repeat network queries', async () => {
    await checkUnknownQoderRewardStatuses(accounts);
    await checkUnknownQoderRewardStatuses(accounts.map((account) => ({ ...account })));
    assert.equal(rewardCalls, 1);
    await checkUnknownQoderRewardStatuses([{ ...accounts[0], reward_window_end_at: 1 }]);
    assert.equal(rewardCalls, 2, 'a changed status snapshot can be checked again');
    await checkUnknownQoderRewardStatuses([{ ...accounts[0], reward_window_end_at: 1, reward_status_updated_at: 2 }]);
    assert.equal(rewardCalls, 2, 'a newer query timestamp for the same expired window must not create a query loop');
  });

  await t.test('explicit reload still queries current state, accepts logout and rejects cross-region IDs', async () => {
    listResponse = async () => accounts.map((account) => ({ ...account }));
    currentResponse = async (platform) => platform === 'qoder_app' ? 'cn' : null;
    await useQoderAccountStore.getState().fetchAccounts({ silent: true });
    assert.equal(listCalls, 2);
    assert.deepEqual(useQoderCurrentAccountStore.getState().currentIds, {
      qoder: null, qoder_app: null, qoder_cn_ide: null, qoder_cn_app: null,
    });
  });

  await t.test('late current-state responses cannot overwrite a newer authoritative reload', async () => {
    const stale = deferred<string | null>();
    currentResponse = () => stale.promise;
    const earlier = refreshQoderCurrentAccountIds([...accounts]);
    currentResponse = async (platform) => platform.startsWith('qoder_cn_') ? 'cn' : 'intl';
    await refreshQoderCurrentAccountIds([...accounts]);
    stale.resolve(null);
    await earlier;
    assert.equal(useQoderCurrentAccountStore.getState().currentIds.qoder_app, 'intl');
    assert.equal(useQoderCurrentAccountStore.getState().currentIds.qoder_cn_ide, 'cn');
  });

  const clientTargets: Array<{ accountId: string; variant: QoderVariantId }> = [
    { accountId: 'intl', variant: 'qoder' },
    { accountId: 'intl', variant: 'qoder_app' },
    { accountId: 'cn', variant: 'qoder_cn_ide' },
    { accountId: 'cn', variant: 'qoder_cn_app' },
  ];

  await t.test('switching shared App-source accounts targets the selected client and emits one matching notification', async () => {
    const firstOperation = operations.length;
    const firstEvent = switchEvents.length;
    for (const { accountId, variant } of clientTargets) {
      await useQoderAccountStore.getState().switchAccount(accountId, variant);
    }
    assert.deepEqual(operations.slice(firstOperation), clientTargets.map(({ accountId, variant }) => ({
      command: 'inject_qoder_account', accountId, variantKey: variant,
    })));
    assert.deepEqual(switchEvents.slice(firstEvent), clientTargets.map(({ accountId, variant }) => ({
      platformId: variant, accountId,
    })));
    assert.equal(useQoderCurrentAccountStore.getState().currentIds.qoder_cn_ide, 'cn');
  });

  await t.test('current-client refresh keeps the selected variant even when the account source is App', async () => {
    const firstOperation = operations.length;
    for (const { accountId, variant } of clientTargets) {
      await useQoderAccountStore.getState().refreshToken(accountId, variant);
    }
    assert.deepEqual(operations.slice(firstOperation), clientTargets.map(({ accountId, variant }) => ({
      command: 'refresh_qoder_token', accountId, variantKey: variant,
    })));
  });

  await t.test('a launch failure reloads the disk session without announcing a successful switch', async () => {
    useQoderCurrentAccountStore.setState((state) => ({ currentIds: { ...state.currentIds, qoder: null } }));
    const firstEvent = switchEvents.length;
    switchError = new Error('client launch failed after writing the disk session');
    try {
      await assert.rejects(useQoderAccountStore.getState().switchAccount('intl', 'qoder'), /client launch failed/);
      assert.equal(useQoderCurrentAccountStore.getState().currentIds.qoder, 'intl');
      assert.equal(switchEvents.length, firstEvent);
    } finally {
      switchError = null;
    }
  });

  await t.test('a successful switch reports its explicit target when the follow-up list reload fails', async () => {
    const firstEvent = switchEvents.length;
    const previousResponse = listResponse;
    useQoderAccountStore.getState().setCurrentAccountId(null);
    listResponse = async () => { throw new Error('isolated list read failure'); };
    try {
      await useQoderAccountStore.getState().switchAccount('intl', 'qoder');
      assert.deepEqual(switchEvents.slice(firstEvent), [{ platformId: 'qoder', accountId: 'intl' }]);
    } finally {
      listResponse = previousResponse;
    }
  });

  await t.test('successful expired reward responses retry after completion cooldown and stop once resolved', async () => {
    const previousNow = Date.now;
    const previousListResponse = listResponse;
    const previousRewardResponse = rewardResponse;
    const previousState = useQoderAccountStore.getState();
    const previousCurrentIds = useQoderCurrentAccountStore.getState().currentIds;
    let now = Date.UTC(2026, 9, 9, 12);
    let serverAccount: QoderAccount = {
      id: 'expired-reward-fixture', variant: 'qoder', email: '', created_at: 1, last_used: 1,
      reward_claim_status: 'CLAIMED', reward_window_end_at: now - 1_000,
      reward_status_updated_at: Math.floor(now / 1_000),
    };
    const firstResponse = deferred<QoderAccount[]>();
    const initialCalls = rewardCalls;
    let first: Promise<void> | undefined;
    Date.now = () => now;
    listResponse = async () => [serverAccount];
    rewardResponse = () => firstResponse.promise;
    useQoderAccountStore.setState({ accounts: [serverAccount] });
    try {
      first = checkUnknownQoderRewardStatuses(useQoderAccountStore.getState().accounts);
      assert.equal(rewardCalls, initialCalls + 1);
      now += 60_000;
      await checkUnknownQoderRewardStatuses([{ ...serverAccount, reward_status_updated_at: 2 }]);
      assert.equal(rewardCalls, initialCalls + 1, 'an in-flight query must remain deduplicated even after a minute');
      serverAccount = { ...serverAccount, reward_status_updated_at: Math.floor(now / 1_000) };
      firstResponse.resolve([serverAccount]);
      await first;
      rewardResponse = async () => {
        serverAccount = { ...serverAccount, reward_status_updated_at: Math.floor(now / 1_000) };
        return [serverAccount];
      };

      await checkUnknownQoderRewardStatuses(useQoderAccountStore.getState().accounts);
      now += 59_999;
      await checkUnknownQoderRewardStatuses(useQoderAccountStore.getState().accounts);
      assert.equal(rewardCalls, initialCalls + 1, 'successful expired data must wait a full minute after completion');
      now += 1;
      await checkUnknownQoderRewardStatuses(useQoderAccountStore.getState().accounts);
      assert.equal(rewardCalls, initialCalls + 2, 'a successful response with the same expired window must not suppress future retries');
      await checkUnknownQoderRewardStatuses(useQoderAccountStore.getState().accounts);
      assert.equal(rewardCalls, initialCalls + 2, 'a newer query timestamp must not bypass the cooldown');

      now += 60_000;
      serverAccount = {
        ...serverAccount, reward_claim_status: 'CLAIMABLE', reward_window_end_at: now + 86_400_000,
      };
      await checkUnknownQoderRewardStatuses(useQoderAccountStore.getState().accounts);
      assert.equal(rewardCalls, initialCalls + 3);
      assert.equal(useQoderAccountStore.getState().accounts[0].reward_claim_status, 'CLAIMABLE');
      assert.equal(useQoderAccountStore.getState().accounts[0].reward_window_end_at, serverAccount.reward_window_end_at);
      now += 60_000;
      await checkUnknownQoderRewardStatuses(useQoderAccountStore.getState().accounts);
      assert.equal(rewardCalls, initialCalls + 3, 'a resolved, unexpired activity must stop retries');
    } finally {
      firstResponse.resolve([serverAccount]);
      try {
        if (first) await first;
      } finally {
        Date.now = previousNow;
        listResponse = previousListResponse;
        rewardResponse = previousRewardResponse;
        useQoderAccountStore.setState(previousState);
        useQoderCurrentAccountStore.setState({ currentIds: previousCurrentIds });
      }
    }
  });
});
