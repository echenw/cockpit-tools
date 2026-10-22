import { getQoderAccountRegion } from '../types/qoder';

export const ACCOUNTS_OVERVIEW_FILTER_PERSISTENCE_CHANGED_EVENT =
  'agtools:accounts-overview-filter-persistence-changed';

export interface AccountsOverviewFilterPersistenceChangedDetail {
  scope: string;
  enabled: boolean;
}

const QUICK_SETTINGS_SCOPE_MAP: Record<string, string> = {
  antigravity: 'antigravity',
  codex: 'codex',
  claude: 'claude',
  github_copilot: 'githubcopilot',
  windsurf: 'windsurf',
  kiro: 'kiro',
  cursor: 'cursor',
  grok: 'grok',
  codebuddy: 'codebuddy',
  codebuddy_cn: 'codebuddy_cn',
  qoder: 'qoder',
  qoder_app: 'qoder_app',
  qoder_cn_ide: 'qoder_cn_ide',
  qoder_cn_app: 'qoder_cn_app',
  zcode: 'zcode',
  trae: 'trae',
  trae_solo: 'trae_solo',
  trae_cn: 'trae_cn',
  trae_solo_cn: 'trae_solo_cn',
  workbuddy: 'workbuddy',
  zed: 'zed',
};

function getScopeBase(scope: string): string {
  return `agtools.${scope}.accounts_overview_filters`;
}

function getEnabledStorageKey(scope: string): string {
  return `${getScopeBase(scope)}.persist_enabled`;
}

function getFieldStorageKey(scope: string, field: string): string {
  return `${getScopeBase(scope)}.${field}`;
}

export function normalizeAccountsOverviewScope(rawScope: string): string {
  const normalized = rawScope.trim().toLowerCase().replace(/[^a-z0-9]+/g, '_');
  return getQoderAccountRegion(normalized)?.scope ?? (normalized || 'default');
}

export function resolveAccountsOverviewScopeFromQuickSettingsType(type: string): string {
  return normalizeAccountsOverviewScope(QUICK_SETTINGS_SCOPE_MAP[type] ?? type);
}

function prepareQoderRegionFilters(scope: string): void {
  const region = getQoderAccountRegion(scope);
  if (!region || localStorage.getItem(getEnabledStorageKey(scope)) !== null) return;
  // 新地区命名空间首次读取时沿用 IDE 偏好，缺项再取 App；源配置保留。
  // persist_enabled 最后写入，既作为初始化完成标记，也避免清空筛选后恢复旧值。
  for (const field of ['view_mode', 'sort_by', 'sort_direction', 'filter_types', 'tag_filter', 'group_by_tag']) {
    const destination = getFieldStorageKey(scope, field);
    if (localStorage.getItem(destination) !== null) continue;
    for (const client of region.clients) {
      const value = localStorage.getItem(getFieldStorageKey(client, field));
      if (value !== null) {
        localStorage.setItem(destination, value);
        break;
      }
    }
  }
  const enabled = region.clients.map((client) => localStorage.getItem(getEnabledStorageKey(client)))
    .find((value) => value !== null) ?? '1';
  localStorage.setItem(getEnabledStorageKey(scope), enabled);
}

export function readAccountsOverviewFilterPersistenceEnabled(rawScope: string): boolean {
  const scope = normalizeAccountsOverviewScope(rawScope);
  try {
    prepareQoderRegionFilters(scope);
    return localStorage.getItem(getEnabledStorageKey(scope)) !== '0';
  } catch {
    return false;
  }
}

function emitAccountsOverviewFilterPersistenceChanged(
  scope: string,
  enabled: boolean,
): void {
  if (typeof window === 'undefined') {
    return;
  }
  const detail: AccountsOverviewFilterPersistenceChangedDetail = {
    scope,
    enabled,
  };
  window.dispatchEvent(
    new CustomEvent<AccountsOverviewFilterPersistenceChangedDetail>(
      ACCOUNTS_OVERVIEW_FILTER_PERSISTENCE_CHANGED_EVENT,
      { detail },
    ),
  );
}

export function setAccountsOverviewFilterPersistenceEnabled(
  rawScope: string,
  enabled: boolean,
): void {
  const scope = normalizeAccountsOverviewScope(rawScope);
  try {
    prepareQoderRegionFilters(scope);
    localStorage.setItem(getEnabledStorageKey(scope), enabled ? '1' : '0');
  } catch {
    // ignore persistence failures
  }
  emitAccountsOverviewFilterPersistenceChanged(scope, enabled);
}

export function readAccountsOverviewFilterField<T>(
  rawScope: string,
  field: string,
  fallback: T,
): T {
  const scope = normalizeAccountsOverviewScope(rawScope);
  try {
    prepareQoderRegionFilters(scope);
    const raw = localStorage.getItem(getFieldStorageKey(scope, field));
    if (raw == null) {
      return fallback;
    }
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export function readAccountsOverviewFilterStringArray(
  rawScope: string,
  field: string,
): string[] {
  const value = readAccountsOverviewFilterField<unknown>(rawScope, field, []);
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((item): item is string => typeof item === 'string')
    .map((item) => item.trim())
    .filter(Boolean);
}

export function writeAccountsOverviewFilterField<T>(
  rawScope: string,
  field: string,
  value: T,
): void {
  const scope = normalizeAccountsOverviewScope(rawScope);
  try {
    prepareQoderRegionFilters(scope);
    localStorage.setItem(getFieldStorageKey(scope, field), JSON.stringify(value));
  } catch {
    // ignore persistence failures
  }
}

export function removeAccountsOverviewFilterField(rawScope: string, field: string): void {
  const scope = normalizeAccountsOverviewScope(rawScope);
  try {
    prepareQoderRegionFilters(scope);
    localStorage.removeItem(getFieldStorageKey(scope, field));
  } catch {
    // ignore persistence failures
  }
}
