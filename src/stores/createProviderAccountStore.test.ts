import assert from 'node:assert/strict';
import test, { type TestContext } from 'node:test';
import { createProviderAccountStore } from './createProviderAccountStore';

type Account = { id: string; email: string; tags: string[]; credits: number };

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

function setupStore(t: TestContext, overrides: {
  listAccounts?: () => Promise<Account[]>;
  refreshToken?: (id: string) => Promise<unknown>;
} = {}) {
  const cacheKey = 'test.provider.accounts';
  const originalStorage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage');
  const values = new Map<string, string>();
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => { values.set(key, value); },
      removeItem: (key: string) => { values.delete(key); },
    },
  });
  t.after(() => {
    if (originalStorage) Object.defineProperty(globalThis, 'localStorage', originalStorage);
    else Reflect.deleteProperty(globalThis, 'localStorage');
  });
  let persisted: Account = { id: 'account-a', email: 'sample@example.com', tags: ['old'], credits: 100 };
  const read = () => ({ ...persisted, tags: [...persisted.tags] });
  values.set(cacheKey, JSON.stringify([read()]));
  const store = createProviderAccountStore<Account>(cacheKey, {
    listAccounts: overrides.listAccounts ?? (async () => [read()]),
    refreshToken: overrides.refreshToken ?? (async () => read()),
    updateAccountTags: async (_id, tags) => {
      persisted = { ...persisted, tags: [...tags] };
      return read();
    },
    deleteAccount: async () => {},
    deleteAccounts: async () => {},
    injectAccount: async () => {},
    refreshAllTokens: async () => {},
    importFromJson: async () => [],
    exportAccounts: async () => '[]',
  }, {
    getDisplayEmail: (account) => account.email,
    getPlanBadge: () => 'Pro',
    getUsage: () => ({ inlineSuggestionsUsedPercent: null, chatMessagesUsedPercent: null }),
  }, { platformId: 'qoder', silentMutationRefresh: true });
  return {
    store,
    read,
    setCredits: (credits: number) => { persisted = { ...persisted, credits }; },
    readCache: (): Account[] => JSON.parse(values.get(cacheKey) ?? '[]'),
  };
}

test('a delayed refresh snapshot cannot undo a tag saved while refresh was pending', async (t) => {
  const response = deferred<Account>();
  const fixture = setupStore(t, { refreshToken: async () => response.promise });
  const loadingStates: boolean[] = [];
  const unsubscribe = fixture.store.subscribe((state) => loadingStates.push(state.loading));
  t.after(unsubscribe);

  fixture.setCredits(200);
  const staleResponse = fixture.read();
  const refresh = fixture.store.getState().refreshToken('account-a');
  await fixture.store.getState().updateAccountTags('account-a', ['new']);
  response.resolve(staleResponse);
  await refresh;

  assert.deepEqual(fixture.store.getState().accounts[0].tags, ['new']);
  assert.equal(fixture.store.getState().accounts[0].credits, 200);
  assert.deepEqual(fixture.readCache()[0].tags, ['new']);
  assert.ok(loadingStates.every((loading) => !loading), 'silent mutation sync keeps existing content visible');
});

test('an earlier list response cannot overwrite the authoritative reload after a mutation', async (t) => {
  const earlierList = deferred<Account[]>();
  let firstRead = true;
  let readPersisted!: () => Account;
  const fixture = setupStore(t, {
    listAccounts: async () => {
      if (firstRead) {
        firstRead = false;
        return earlierList.promise;
      }
      return [readPersisted()];
    },
  });
  readPersisted = fixture.read;
  const oldSnapshot = fixture.read();
  const pendingList = fixture.store.getState().fetchAccounts({ silent: true });
  await fixture.store.getState().updateAccountTags('account-a', ['new']);
  earlierList.resolve([oldSnapshot]);
  await pendingList;

  assert.deepEqual(fixture.store.getState().accounts[0].tags, ['new']);
  assert.deepEqual(fixture.readCache()[0].tags, ['new']);
  assert.equal(fixture.store.getState().loading, false);
});
