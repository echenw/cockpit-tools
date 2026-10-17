/**
 * 全平台通用账号分组服务
 * - 支持任意平台（Antigravity、Codex、WorkBuddy、Cursor、Windsurf、Trae、Zed、GitHub Copilot 等）
 * - 磁盘原子持久化存储
 * - 本地 activeGroupTab 独立记忆（不纳入备份同步）
 */

import { invoke } from '@tauri-apps/api/core';
import { parseAccountGroups, type AccountGroup } from './accountGroupService';
import * as antigravityGroups from './accountGroupService';
import * as codexGroups from './codexAccountGroupService';
import { listQoderAccounts } from './qoderService';
import { isQoderVariantId, qoderAccountSupportsVariant } from '../types/qoder';

export type { AccountGroup };

// ─── 平台标识规范化 ──────────────────────────────────────────

export function normalizePlatform(platform: string): string {
  const trimmed = platform.trim().toLowerCase();
  if (trimmed === 'gemini' || trimmed === 'antigravity_ide') return 'antigravity';
  if (trimmed === 'codex_api_service') return 'codex';
  if (trimmed === 'claude') return 'claude_manager';
  return trimmed;
}

// ─── 内存缓存与任务串行队列 ─────────────────────────────────

const cacheByPlatform = new Map<string, AccountGroup[]>();
let queue = Promise.resolve();

function enqueue<T>(task: () => Promise<T>): Promise<T> {
  const result = queue.then(task, task);
  queue = result.then(
    () => {},
    () => {}
  );
  return result;
}

function cloneGroups(groups: AccountGroup[]): AccountGroup[] {
  return groups.map((g) => ({
    ...g,
    accountIds: [...g.accountIds],
  }));
}

function generateId(): string {
  return `grp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

// ─── 磁盘 I/O ───────────────────────────────────────────────

async function loadFromDisk(platform: string): Promise<AccountGroup[]> {
  try {
    const raw: string = await invoke('load_platform_account_groups', { platform });
    return parseAccountGroups(raw);
  } catch (error) {
    console.error(`[PlatformGroups] Failed to load groups for ${platform}:`, error);
    throw error;
  }
}

async function saveToDisk(platform: string, groups: AccountGroup[]): Promise<void> {
  try {
    await invoke('save_platform_account_groups', {
      platform,
      data: JSON.stringify(groups, null, 2),
    });
  } catch (error) {
    console.error(`[PlatformGroups] Failed to save groups for ${platform}:`, error);
    throw error;
  }
}

async function resolveQoderGroupAccountIds(platform: string, groups: AccountGroup[]): Promise<AccountGroup[]> {
  if (!isQoderVariantId(platform) || !groups.some((group) => group.accountIds.length > 0)) return groups;

  const accounts = await listQoderAccounts();
  // 现存 ID 优先；只解析同地区的旧 ID，未知引用保留。
  const accountIds = new Map(accounts.map((account) => [account.id, account.id]));
  for (const account of accounts) {
    if (!qoderAccountSupportsVariant(account, platform)) continue;
    for (const legacyId of account.legacy_ids ?? []) {
      if (!accountIds.has(legacyId)) accountIds.set(legacyId, account.id);
    }
  }
  return groups.map((group) => ({
    ...group,
    accountIds: Array.from(new Set(group.accountIds.map((id) => accountIds.get(id) ?? id))),
  }));
}

async function loadGroupsInternal(platform: string): Promise<AccountGroup[]> {
  const key = normalizePlatform(platform);
  const cached = cacheByPlatform.get(key);
  // 缓存分组也要按最新账号映射读取，覆盖后续发生的账号合并。
  const groups = await resolveQoderGroupAccountIds(key, cached ?? await loadFromDisk(key));
  cacheByPlatform.set(key, groups);
  return cloneGroups(groups);
}

async function saveGroupsInternal(platform: string, groups: AccountGroup[]): Promise<void> {
  const key = normalizePlatform(platform);
  const next = await resolveQoderGroupAccountIds(key, cloneGroups(groups));
  await saveToDisk(key, next);
  cacheByPlatform.set(key, next);
}

// Existing platforms share their original cache, queue and platform-specific fields.
// ─── 公开 API ────────────────────────────────────────────────

export function getPlatformGroups(platform: string): Promise<AccountGroup[]> {
  const key = normalizePlatform(platform);
  if (key === 'antigravity') return antigravityGroups.getAccountGroups();
  if (key === 'codex') return codexGroups.getCodexAccountGroups();
  return enqueue(() => loadGroupsInternal(platform));
}

export function createPlatformGroup(platform: string, name: string): Promise<AccountGroup> {
  const key = normalizePlatform(platform);
  if (key === 'antigravity') return antigravityGroups.createGroup(name);
  if (key === 'codex') return codexGroups.createCodexGroup(name);
  return enqueue(async () => {
    const groups = await loadGroupsInternal(key);
    const group: AccountGroup = {
      id: generateId(),
      name: name.trim(),
      accountIds: [],
      createdAt: Date.now(),
    };
    groups.push(group);
    await saveGroupsInternal(key, groups);
    return group;
  });
}

export function deletePlatformGroup(platform: string, groupId: string): Promise<void> {
  const key = normalizePlatform(platform);
  if (key === 'antigravity') return antigravityGroups.deleteGroup(groupId);
  if (key === 'codex') return codexGroups.deleteCodexGroup(groupId);
  return enqueue(async () => {
    const groups = (await loadGroupsInternal(key)).filter((g) => g.id !== groupId);
    await saveGroupsInternal(key, groups);
  });
}

export function renamePlatformGroup(
  platform: string,
  groupId: string,
  name: string
): Promise<AccountGroup | null> {
  const key = normalizePlatform(platform);
  if (key === 'antigravity') return antigravityGroups.renameGroup(groupId, name);
  if (key === 'codex') return codexGroups.renameCodexGroup(groupId, name);
  return enqueue(async () => {
    const groups = await loadGroupsInternal(key);
    const group = groups.find((g) => g.id === groupId);
    if (!group) return null;
    group.name = name.trim();
    await saveGroupsInternal(key, groups);
    return group;
  });
}

export function reorderPlatformGroups(
  platform: string,
  orderedGroupIds: string[]
): Promise<AccountGroup[]> {
  const key = normalizePlatform(platform);
  if (key === 'antigravity') return antigravityGroups.reorderGroups(orderedGroupIds);
  if (key === 'codex') return codexGroups.reorderCodexGroups(orderedGroupIds);
  return enqueue(async () => {
    const groups = await loadGroupsInternal(key);
    const groupMap = new Map(groups.map((g) => [g.id, g]));
    const reordered: AccountGroup[] = [];
    for (const id of orderedGroupIds) {
      const g = groupMap.get(id);
      if (g) {
        reordered.push(g);
        groupMap.delete(id);
      }
    }
    for (const remaining of groupMap.values()) {
      reordered.push(remaining);
    }
    await saveGroupsInternal(key, reordered);
    return cloneGroups(reordered);
  });
}

export function setPlatformGroupAccounts(
  platform: string,
  groupId: string,
  accountIds: string[]
): Promise<AccountGroup | null> {
  const key = normalizePlatform(platform);
  if (key === 'antigravity') return antigravityGroups.setGroupAccounts(groupId, accountIds);
  if (key === 'codex') return codexGroups.setCodexGroupAccounts(groupId, accountIds);
  return enqueue(async () => {
    const key = normalizePlatform(platform);
    const groups = await loadGroupsInternal(key);
    const group = groups.find((g) => g.id === groupId);
    if (!group) return null;
    group.accountIds = Array.from(new Set(accountIds));
    await saveGroupsInternal(key, groups);
    return group;
  });
}

export function assignAccountsToPlatformGroup(
  platform: string,
  groupId: string,
  accountIds: string[]
): Promise<AccountGroup | null> {
  const key = normalizePlatform(platform);
  if (key === 'antigravity') return antigravityGroups.addAccountsToGroup(groupId, accountIds);
  if (key === 'codex') return codexGroups.assignAccountsToCodexGroup(groupId, accountIds);
  return enqueue(async () => {
    const groups = await loadGroupsInternal(key);
    const group = groups.find((g) => g.id === groupId);
    if (!group) return null;

    const existing = new Set(group.accountIds);
    for (const id of accountIds) {
      if (!existing.has(id)) {
        group.accountIds.push(id);
        existing.add(id);
      }
    }
    await saveGroupsInternal(key, groups);
    return group;
  });
}

export function removeAccountsFromPlatformGroup(
  platform: string,
  groupId: string,
  accountIds: string[]
): Promise<AccountGroup | null> {
  const key = normalizePlatform(platform);
  if (key === 'antigravity') return antigravityGroups.removeAccountsFromGroup(groupId, accountIds);
  if (key === 'codex') return codexGroups.removeAccountsFromCodexGroup(groupId, accountIds);
  return enqueue(async () => {
    const groups = await loadGroupsInternal(key);
    const group = groups.find((g) => g.id === groupId);
    if (!group) return null;
    const toRemove = new Set(accountIds);
    group.accountIds = group.accountIds.filter((id) => !toRemove.has(id));
    await saveGroupsInternal(key, groups);
    return group;
  });
}

export function removeAccountIdsFromAllPlatformGroups(
  platform: string,
  accountIds: string[]
): Promise<void> {
  const key = normalizePlatform(platform);
  if (key === 'antigravity') return antigravityGroups.removeAccountIdsFromAllGroups(accountIds);
  if (key === 'codex') return codexGroups.removeAccountIdsFromAllCodexGroups(accountIds);
  return enqueue(async () => {
    const toRemove = new Set(accountIds.map((id) => id.trim()).filter(Boolean));
    if (toRemove.size === 0) return;
    const groups = await loadGroupsInternal(key);
    let changed = false;
    for (const group of groups) {
      const next = group.accountIds.filter((id) => !toRemove.has(id));
      if (next.length !== group.accountIds.length) {
        group.accountIds = next;
        changed = true;
      }
    }
    if (changed) await saveGroupsInternal(key, groups);
  });
}

export function invalidatePlatformGroupCache(platform?: string): void {
  if (platform) {
    const key = normalizePlatform(platform);
    if (key === 'antigravity') antigravityGroups.invalidateCache();
    if (key === 'codex') codexGroups.invalidateCodexGroupCache();
    cacheByPlatform.delete(key);
  } else {
    antigravityGroups.invalidateCache();
    codexGroups.invalidateCodexGroupCache();
    cacheByPlatform.clear();
  }
}

// ─── 本地 Active Tab 记忆持久化（不纳入云端同步与备份） ─────────

const ACTIVE_GROUP_TAB_STORAGE_PREFIX = 'agtools.group_tab_active.';

export function getActiveGroupTab(platform: string): string | null {
  try {
    const key = `${ACTIVE_GROUP_TAB_STORAGE_PREFIX}${normalizePlatform(platform)}`;
    const saved = localStorage.getItem(key);
    if (!saved || saved === '__all__') return null;
    return saved;
  } catch {
    return null;
  }
}

export function setActiveGroupTab(platform: string, groupId: string | null): void {
  try {
    const key = `${ACTIVE_GROUP_TAB_STORAGE_PREFIX}${normalizePlatform(platform)}`;
    if (!groupId) {
      localStorage.removeItem(key);
    } else {
      localStorage.setItem(key, groupId);
    }
  } catch {
    // ignore localStorage errors
  }
}
