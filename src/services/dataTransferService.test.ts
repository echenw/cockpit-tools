import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
import { loadHookModule } from '../../tests/helpers/reactHookHarness';
import { ALL_PLATFORM_IDS } from '../types/platform';
import type { QoderAccount } from '../types/qoder';
import type { AccountGroup } from './accountGroupService';
import type { DataTransferAccountRef } from './dataTransferService';
import { CODEX_TOP_LAYOUT_STORAGE_KEY, createDefaultCodexTopLayout, normalizeCodexTopLayout } from '../utils/codexTopLayoutPreferences';

function harness() {
  const items = new Map<string, string>();
  const calls: string[] = [];
  const events: string[] = [];
  const groupReads: string[] = [];
  const groupWrites: Array<{ platform: string; groups: AccountGroup[] }> = [];
  const groups = new Map<string, AccountGroup[]>();
  const qoder = { accounts: [] as QoderAccount[] };
  let failLayoutWrite = false;
  const localStorage = {
    getItem: (key: string) => items.get(key) ?? null,
    removeItem: (key: string) => { items.delete(key); },
    setItem: (key: string, value: string) => {
      if (key === CODEX_TOP_LAYOUT_STORAGE_KEY && failLayoutWrite) throw Error('quota');
      items.set(key, value);
    },
  };
  const globals = { localStorage, window: { dispatchEvent: (event: { type: string }) => { events.push(event.type); } },
    Event: class { constructor(readonly type: string) {} },
    CustomEvent: class { constructor(readonly type: string, readonly options: unknown) {} },
  };
  const preferences = loadHookModule(new URL('../utils/codexTopLayoutPreferences.ts', import.meta.url), {}, globals).exports;
  const qoderTypes = loadHookModule(new URL('../types/qoder.ts', import.meta.url), {}).exports as typeof import('../types/qoder');
  const moduleUrl = new URL('./dataTransferService.ts', import.meta.url);
  const source = ts.createSourceFile('service.ts', readFileSync(moduleUrl, 'utf8'), ts.ScriptTarget.ES2022);
  const fallback = new Proxy({}, { get: (_target, key) => {
    if (key === 'getGroupSettings') return async () => ({ groupMappings: {}, groupNames: {}, groupOrder: [] });
    if (key === 'getCodexWakeupState') return async () => ({ enabled: false, tasks: [], model_presets: [] });
    if (key === 'getCodexWakeupCliStatus') return async () => ({});
    if (key === 'loadCurrentAccountRefreshMinutesMap') return () => ({});
    if (key === 'loadWakeupOfficialLsVersionMode') return () => 'auto';
    if (key === 'DEFAULT_WAKEUP_OFFICIAL_LS_VERSION_MODE') return 'auto';
    return async () => [];
  } });
  const imports: Record<string, unknown> = {};
  for (const statement of source.statements) {
    if (ts.isImportDeclaration(statement) && ts.isStringLiteral(statement.moduleSpecifier)) imports[statement.moduleSpecifier.text] = fallback;
  }
  imports['../types/platform'] = { ALL_PLATFORM_IDS };
  imports['../types/qoder'] = qoderTypes;
  imports['./qoderService'] = { listQoderAccounts: async () => qoder.accounts };
  imports['./platformGroupService'] = {
    async getPlatformGroups(platform: string) {
      groupReads.push(platform);
      return groups.get(qoderTypes.getQoderAccountRegion(platform)?.scope ?? platform) ?? [];
    },
    invalidatePlatformGroupCache() {},
  };
  imports['../utils/codexTopLayoutPreferences'] = preferences;
  imports['@tauri-apps/api/core'] = { invoke: async (command: string, args?: { platform?: string; data?: string }) => {
    calls.push(command);
    if (command === 'data_transfer_get_user_config') return {};
    if (command === 'data_transfer_get_instance_store') return { instances: [], defaultSettings: { extraArgs: '' } };
    if (command === 'data_transfer_apply_user_config') return false;
    if (command === 'save_platform_account_groups') {
      assert.equal(typeof args?.platform, 'string');
      assert.equal(typeof args?.data, 'string');
      const platform = args!.platform!;
      const restored: AccountGroup[] = JSON.parse(args!.data!);
      groupWrites.push({ platform, groups: restored });
      // 模拟持久化边界的地区别名：旧代码逐端写入会覆盖同一条记录。
      groups.set(qoderTypes.getQoderAccountRegion(platform)?.scope ?? platform, restored);
    }
    return [];
  } };
  const service = loadHookModule(moduleUrl, imports, globals).exports;
  const selection = { includeAccounts: false, includeConfig: true };
  return { items, calls, events, service, selection, groups, groupReads, groupWrites, qoder,
    failWrites() { failLayoutWrite = true; },
    async bundle() { return JSON.parse(await service.exportDataTransferJson(selection)); },
    async import(bundle: unknown) { return service.importDataTransferJson(JSON.stringify(bundle), selection); },
  };
}

test('config export includes normalized top order and import restores it with a same-window notification', async () => {
  const h = harness(); h.items.set(CODEX_TOP_LAYOUT_STORAGE_KEY, JSON.stringify({ order: ['sessions', 'sessions', 'old', 'proxy'] }));
  const bundle = await h.bundle();
  assert.deepEqual(bundle.config.codex_top_layout, normalizeCodexTopLayout({ order: ['sessions', 'proxy'] }));
  h.items.delete(CODEX_TOP_LAYOUT_STORAGE_KEY);
  const result = await h.import(bundle);
  assert.equal(result.config_result.applied, true);
  assert.deepEqual(JSON.parse(h.items.get(CODEX_TOP_LAYOUT_STORAGE_KEY)!), { order: bundle.config.codex_top_layout.order });
  assert.ok(h.events.includes('codex:top-layout-updated'));
});

test('old backups without a top layout preserve current local ordering', async () => {
  const h = harness(); const bundle = await h.bundle(); delete bundle.config.codex_top_layout;
  const existing = JSON.stringify({ order: ['proxy', 'sessions'] }); h.items.set(CODEX_TOP_LAYOUT_STORAGE_KEY, existing);
  await h.import(bundle);
  assert.equal(h.items.get(CODEX_TOP_LAYOUT_STORAGE_KEY), existing);
  assert.ok(!h.events.includes('codex:top-layout-updated'));
});

test('import normalizes duplicates and unknown tabs but rejects structurally invalid layout before config writes', async () => {
  const h = harness(); const bundle = await h.bundle();
  bundle.config.codex_top_layout = { order: ['proxy', 'old', 'proxy', 'top-layout'], placement: { proxy: 'more' } };
  await h.import(bundle);
  assert.deepEqual(JSON.parse(h.items.get(CODEX_TOP_LAYOUT_STORAGE_KEY)!).order, normalizeCodexTopLayout(bundle.config.codex_top_layout).order);
  h.calls.length = 0; bundle.config.codex_top_layout = { order: [42] };
  await assert.rejects(h.import(bundle), /codex_top_layout_invalid/);
  assert.ok(!h.calls.includes('data_transfer_apply_user_config'));
});

test('layout write failure reports partial import explicitly and preserves the previous saved order', async () => {
  const h = harness(); const bundle = await h.bundle();
  const old = JSON.stringify({ order: ['sessions'] }); h.items.set(CODEX_TOP_LAYOUT_STORAGE_KEY, old); h.failWrites();
  await assert.rejects(h.import(bundle), /codex_top_layout_import_failed/);
  assert.equal(h.items.get(CODEX_TOP_LAYOUT_STORAGE_KEY), old);
  assert.ok(h.calls.includes('data_transfer_apply_user_config'));
  assert.ok(!h.events.includes('codex:top-layout-updated'));
});

test('config export refuses a corrupt saved layout instead of silently backing up defaults', async () => {
  const h = harness(); h.items.set(CODEX_TOP_LAYOUT_STORAGE_KEY, '{broken');
  await assert.rejects(h.bundle(), /codex_top_layout_read_failed/);
  assert.equal(h.items.get(CODEX_TOP_LAYOUT_STORAGE_KEY), '{broken');
  assert.deepEqual(createDefaultCodexTopLayout().order.slice(0, 5), ['overview', 'providers', 'wakeup', 'instances', 'sessions']);
});

function qoderAccount(id: string, variant: QoderAccount['variant'], userId: string): QoderAccount {
  return { id, variant, user_id: userId, email: `${userId}@example.test`, created_at: 1, last_used: 1 };
}

function backupGroup(id: string, name: string, refs: DataTransferAccountRef[] = [], createdAt = 1) {
  return { id, name, accountRefs: refs, createdAt };
}

test('old Qoder backup restores both clients into each region without overwriting groups', async () => {
  const h = harness();
  h.qoder.accounts = [
    qoderAccount('intl-one', 'qoder_app', 'i1'), qoderAccount('intl-two', 'qoder_app', 'i2'),
    qoderAccount('cn-one', 'qoder_cn_app', 'c1'), qoderAccount('cn-two', 'qoder_cn_app', 'c2'),
  ];
  const bundle = await h.bundle();
  // App 在前，确保名称/设置的优先级不依赖 JSON 条目顺序；两个地区复用组 ID。
  bundle.config.platform_account_groups = {
    qoder_app: [
      backupGroup('shared', 'App name', [{ platform: 'qoder_app', userId: 'i2' }, { platform: 'qoder_app', userId: 'i1' }], 20),
      backupGroup('app-only', 'App only'),
    ],
    qoder_cn_app: [backupGroup('shared', 'CN App', [{ platform: 'qoder_cn_app', userId: 'c2' }])],
    qoder: [
      backupGroup('shared', 'IDE name', [{ platform: 'qoder', userId: 'i1' }], 10),
      backupGroup('ide-only', 'IDE only'),
    ],
    qoder_cn_ide: [backupGroup('shared', 'CN IDE', [{ platform: 'qoder_cn_ide', userId: 'c1' }])],
    cursor: [backupGroup('cursor-group', 'Cursor')],
  };
  const result = await h.import(bundle);
  assert.equal(result.config_result.applied, true);
  assert.deepEqual(h.groups.get('qoder_intl')?.map((group) => group.id), ['shared', 'ide-only', 'app-only']);
  const intl = h.groups.get('qoder_intl')![0];
  assert.equal(intl.name, 'IDE name');
  assert.equal(intl.createdAt, 10);
  assert.deepEqual(intl.accountIds, ['intl-one', 'intl-two']);
  const cn = h.groups.get('qoder_cn')![0];
  assert.equal(cn.name, 'CN IDE');
  assert.deepEqual(cn.accountIds, ['cn-one', 'cn-two']);
  assert.equal(h.groupWrites.filter((write) => write.platform === 'qoder_intl').length, 1);
  assert.equal(h.groupWrites.filter((write) => write.platform === 'qoder_cn').length, 1);
  assert.deepEqual(h.groups.get('cursor'), [{ id: 'cursor-group', name: 'Cursor', createdAt: 1, accountIds: [] }]);
});

test('empty App groups in old backups cannot erase IDE groups in either region', async () => {
  const h = harness();
  const bundle = await h.bundle();
  bundle.config.platform_account_groups = {
    qoder: [backupGroup('kept', 'International')], qoder_app: [],
    qoder_cn_ide: [backupGroup('kept', 'CN')], qoder_cn_app: [],
  };
  await h.import(bundle);
  assert.equal(h.groups.get('qoder_intl')?.[0].name, 'International');
  assert.equal(h.groups.get('qoder_cn')?.[0].name, 'CN');
  assert.equal(h.groupWrites.length, 2);
});

test('new Qoder backups export one group snapshot per region with portable account references', async () => {
  const h = harness();
  h.qoder.accounts = [qoderAccount('intl', 'qoder_app', 'i1'), qoderAccount('cn', 'qoder_cn_app', 'c1')];
  h.groups.set('qoder_intl', [{ id: 'same', name: 'Intl', createdAt: 1, accountIds: ['intl'] }]);
  h.groups.set('qoder_cn', [{ id: 'same', name: 'CN', createdAt: 2, accountIds: ['cn'] }]);
  const bundle = await h.bundle();
  assert.deepEqual(Object.keys(bundle.config.platform_account_groups), ['qoder', 'qoder_cn_ide']);
  assert.deepEqual(h.groupReads.filter((platform) => platform.startsWith('qoder')), ['qoder', 'qoder_cn_ide']);
  assert.deepEqual(bundle.config.platform_account_groups.qoder[0].accountRefs, [
    { platform: 'qoder', email: 'i1@example.test', userId: 'i1' },
  ]);
  h.groups.clear();
  await h.import(bundle);
  assert.deepEqual(h.groups.get('qoder_intl'), [{ id: 'same', name: 'Intl', createdAt: 1, accountIds: ['intl'] }]);
  assert.deepEqual(h.groups.get('qoder_cn'), [{ id: 'same', name: 'CN', createdAt: 2, accountIds: ['cn'] }]);
});
