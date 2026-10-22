import assert from 'node:assert/strict';
import test from 'node:test';
import { loadHookModule } from '../../tests/helpers/reactHookHarness';

function harness(initial: Record<string, string> = {}) {
  const storage = new Map(Object.entries(initial));
  const events: { scope: string; enabled: boolean }[] = [];
  const failures = new Set<string>();
  const api = loadHookModule(new URL('./accountsOverviewFilterPersistence.ts', import.meta.url), {
    '../types/qoder': loadHookModule(new URL('../types/qoder.ts', import.meta.url), {}).exports,
  }, {
    localStorage: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem(key: string, value: string) {
        if (failures.has(key)) throw new Error('Storage write failed');
        storage.set(key, value);
      },
      removeItem: (key: string) => { storage.delete(key); },
    },
    CustomEvent: class {
      detail: { scope: string; enabled: boolean };
      constructor(_type: string, options: { detail: { scope: string; enabled: boolean } }) {
        this.detail = options.detail;
      }
    },
    window: { dispatchEvent(event: { detail: { scope: string; enabled: boolean } }) { events.push(event.detail); } },
  }).exports as typeof import('./accountsOverviewFilterPersistence');
  return { api, storage, events, failures };
}

for (const [ide, app, scope] of [
  ['qoder', 'qoder_app', 'qoder_intl'],
  ['qoder_cn_ide', 'qoder_cn_app', 'qoder_cn'],
] as const) {
  test(`${scope}: both routes retain regional preferences across edits and clearing`, () => {
    const base = (client: string) => `agtools.${client}.accounts_overview_filters`;
    const h = harness({
      [`${base(ide)}.view_mode`]: '"list"',
      [`${base(app)}.view_mode`]: '"grid"',
      [`${base(app)}.tag_filter`]: '["kept-app-tag"]',
    });
    assert.equal(h.api.readAccountsOverviewFilterField(app, 'view_mode', 'grid'), 'list');
    assert.deepEqual(Array.from(h.api.readAccountsOverviewFilterStringArray(ide, 'tag_filter')), ['kept-app-tag']);
    h.api.writeAccountsOverviewFilterField(app, 'sort_by', 'created_at');
    assert.equal(h.api.readAccountsOverviewFilterField(ide, 'sort_by', ''), 'created_at');
    h.api.removeAccountsOverviewFilterField(ide, 'tag_filter');
    assert.deepEqual(Array.from(h.api.readAccountsOverviewFilterStringArray(app, 'tag_filter')), []);
    assert.equal(h.storage.get(`${base(app)}.tag_filter`), '["kept-app-tag"]', 'source preferences stay intact');
    h.api.setAccountsOverviewFilterPersistenceEnabled(app, false);
    assert.equal(h.api.readAccountsOverviewFilterPersistenceEnabled(ide), false);
    assert.equal(h.events.at(-1)?.scope, scope);
    assert.equal(h.api.resolveAccountsOverviewScopeFromQuickSettingsType(app), scope);
    assert.equal(h.api.normalizeAccountsOverviewScope(ide), scope);
    assert.equal(h.api.readAccountsOverviewFilterField(scope === 'qoder_intl' ? 'qoder_cn_app' : 'qoder_app', 'view_mode', 'grid'), 'grid');
    h.api.writeAccountsOverviewFilterField('cursor', 'view_mode', 'grid');
    assert.equal(h.storage.get('agtools.cursor.accounts_overview_filters.view_mode'), '"grid"');
  });
}

test('Qoder preference initialization retries a failed final write without losing copied values', () => {
  const marker = 'agtools.qoder_intl.accounts_overview_filters.persist_enabled';
  const h = harness({
    'agtools.qoder.accounts_overview_filters.view_mode': '"list"',
    'agtools.qoder_app.accounts_overview_filters.persist_enabled': '0',
  });
  h.failures.add(marker);
  assert.equal(h.api.readAccountsOverviewFilterPersistenceEnabled('qoder_app'), false);
  assert.equal(h.storage.has(marker), false);
  assert.equal(h.storage.get('agtools.qoder_intl.accounts_overview_filters.view_mode'), '"list"');
  h.failures.delete(marker);
  assert.equal(h.api.readAccountsOverviewFilterPersistenceEnabled('qoder'), false);
  assert.equal(h.api.readAccountsOverviewFilterField('qoder_app', 'view_mode', 'grid'), 'list');
  h.api.setAccountsOverviewFilterPersistenceEnabled('qoder', true);
  assert.equal(h.api.readAccountsOverviewFilterPersistenceEnabled('qoder_app'), true);
});
