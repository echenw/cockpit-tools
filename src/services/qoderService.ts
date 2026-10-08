import { invoke } from '@tauri-apps/api/core';
import { QoderAccount, QoderVariantId, QODER_VARIANT_IDS } from '../types/qoder';

export type { QoderVariantId };
export { QODER_VARIANT_IDS };

export const DEFAULT_QODER_VARIANT: QoderVariantId = 'qoder';

function resolveVariantKey(variantKey?: QoderVariantId): QoderVariantId {
  return variantKey ?? DEFAULT_QODER_VARIANT;
}

export interface QoderOAuthStartResponse {
  loginId: string;
  verificationUri: string;
  expiresIn: number;
  intervalSeconds: number;
  callbackUrl?: string | null;
}

type QoderOAuthStartResponseRaw = Partial<QoderOAuthStartResponse> & {
  login_id?: string;
  verification_uri?: string;
  expires_in?: number;
  interval_seconds?: number;
  callback_url?: string | null;
};

function normalizeQoderOAuthStartResponse(raw: QoderOAuthStartResponseRaw): QoderOAuthStartResponse {
  const loginId = raw.loginId ?? raw.login_id ?? '';
  const verificationUri = raw.verificationUri ?? raw.verification_uri ?? '';
  const expiresIn = Number(raw.expiresIn ?? raw.expires_in ?? 0);
  const intervalSeconds = Number(raw.intervalSeconds ?? raw.interval_seconds ?? 0);
  const callbackUrl = raw.callbackUrl ?? raw.callback_url ?? null;

  if (!loginId || !verificationUri) {
    throw new Error('Qoder OAuth start 响应缺少关键字段');
  }

  return {
    loginId,
    verificationUri,
    expiresIn: Number.isFinite(expiresIn) && expiresIn > 0 ? expiresIn : 600,
    intervalSeconds: Number.isFinite(intervalSeconds) && intervalSeconds > 0 ? intervalSeconds : 1,
    callbackUrl,
  };
}

export async function listQoderAccounts(): Promise<QoderAccount[]> {
  return await invoke('list_qoder_accounts');
}

export async function deleteQoderAccount(accountId: string): Promise<void> {
  return await invoke('delete_qoder_account', { accountId });
}

export async function deleteQoderAccounts(accountIds: string[]): Promise<void> {
  return await invoke('delete_qoder_accounts', { accountIds });
}

export async function importQoderFromJson(
  jsonContent: string,
  variantKey?: QoderVariantId,
): Promise<QoderAccount[]> {
  return await invoke('import_qoder_from_json', {
    jsonContent,
    variantKey: resolveVariantKey(variantKey),
  });
}

export async function importQoderFromLocal(variantKey?: QoderVariantId): Promise<QoderAccount[]> {
  return await invoke('import_qoder_from_local', { variantKey: resolveVariantKey(variantKey) });
}

export type QoderOfficialLoginPhase =
  | 'preparing' | 'signing-out' | 'launching' | 'waiting-login' | 'importing' | 'cleaning'
  | 'cancelling' | 'completed' | 'failed' | 'cancelled';

export interface QoderOfficialLoginStatus {
  sessionId: string;
  variant: QoderVariantId;
  phase: QoderOfficialLoginPhase;
  accountId: string | null;
  error: string | null;
  cleanupWarning: string | null;
}

export function startQoderOfficialLogin(variantKey: QoderVariantId): Promise<QoderOfficialLoginStatus> {
  return invoke('start_qoder_official_login', { variantKey });
}

export function getQoderOfficialLoginStatus(sessionId: string): Promise<QoderOfficialLoginStatus> {
  return invoke('get_qoder_official_login_status', { sessionId });
}

export function cancelQoderOfficialLogin(sessionId: string): Promise<void> {
  return invoke('cancel_qoder_official_login', { sessionId });
}

export async function qoderOauthLoginStart(variantKey?: QoderVariantId): Promise<QoderOAuthStartResponse> {
  const raw = await invoke<QoderOAuthStartResponseRaw>('qoder_oauth_login_start', {
    variantKey: resolveVariantKey(variantKey),
  });
  return normalizeQoderOAuthStartResponse(raw);
}

export async function qoderOauthLoginPeek(variantKey?: QoderVariantId): Promise<QoderOAuthStartResponse | null> {
  const raw = await invoke<QoderOAuthStartResponseRaw | null>('qoder_oauth_login_peek', {
    variantKey: resolveVariantKey(variantKey),
  });
  if (!raw) return null;
  try {
    return normalizeQoderOAuthStartResponse(raw);
  } catch {
    return null;
  }
}

export async function qoderOauthLoginComplete(loginId: string, variantKey?: QoderVariantId): Promise<QoderAccount> {
  return await invoke('qoder_oauth_login_complete', { loginId, variantKey: resolveVariantKey(variantKey) });
}

export async function qoderOauthLoginCancel(loginId?: string, variantKey?: QoderVariantId): Promise<void> {
  return await invoke('qoder_oauth_login_cancel', {
    loginId: loginId ?? null,
    variantKey: resolveVariantKey(variantKey),
  });
}

export async function exportQoderAccounts(
  accountIds: string[],
  includeCredentials = true,
): Promise<string> {
  return await invoke('export_qoder_accounts', { accountIds, includeCredentials });
}

// 页面选择目标客户端；无上下文的后台刷新使用最近的凭据来源。
export function buildQoderAccountRefreshPayload(accountId: string, variantKey?: QoderVariantId): {
  accountId: string;
  variantKey: QoderVariantId | null;
} {
  return { accountId, variantKey: variantKey ?? null };
}

export async function refreshQoderToken(accountId: string, variantKey?: QoderVariantId): Promise<QoderAccount> {
  return await invoke('refresh_qoder_token', buildQoderAccountRefreshPayload(accountId, variantKey));
}

// undefined 保持默认 IDE；null 明确表示全部变体。
export function resolveQoderBatchRefreshVariant(
  variantKey?: QoderVariantId | null,
): QoderVariantId | null {
  return variantKey === undefined ? DEFAULT_QODER_VARIANT : variantKey;
}

export function buildQoderBatchRefreshPayload(
  variantKey?: QoderVariantId | null,
): { variantKey: QoderVariantId | null } {
  return { variantKey: resolveQoderBatchRefreshVariant(variantKey) };
}

export async function refreshAllQoderTokens(variantKey?: QoderVariantId | null): Promise<number> {
  return await invoke('refresh_all_qoder_tokens', buildQoderBatchRefreshPayload(variantKey));
}

/** 定时任务/托盘专用：全变体批量刷新（`variantKey=None`）。页面手动批量刷新仍按当前标签页变体。 */
export async function refreshAllQoderVariants(): Promise<number> {
  return await refreshAllQoderTokens(null);
}

export async function injectQoderAccount(accountId: string, variantKey?: QoderVariantId): Promise<string> {
  return await invoke<string>('inject_qoder_account', { accountId, variantKey: variantKey ?? null });
}

export async function updateQoderAccountTags(
  accountId: string,
  tags: string[],
): Promise<QoderAccount> {
  return await invoke('update_qoder_account_tags', { accountId, tags });
}

export async function getQoderAccountsIndexPath(): Promise<string> {
  return await invoke('get_qoder_accounts_index_path');
}
