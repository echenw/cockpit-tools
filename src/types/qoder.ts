import type { QuotaCategoryGroup, OfficialQuotaResource } from './codebuddy-suite';

export interface QoderAccount {
  id: string;
  /** 最近的授权/凭据来源；同地区账号同时适用于 App 和 IDE。 */
  variant?: string | null;
  legacy_ids?: string[];
  email: string;
  user_id?: string | null;
  display_name?: string | null;
  plan_type?: string | null;
  credits_used?: number | null;
  credits_total?: number | null;
  credits_remaining?: number | null;
  credits_usage_percent?: number | null;
  quota_query_last_error?: string | null;
  quota_query_last_error_at?: number | null;
  usage_updated_at?: number | null;
  tags?: string[] | null;
  reward_claim_status?: string | null;
  reward_window_end_at?: number | null;
  reward_status_updated_at?: number | null;
  auth_user_info_raw?: unknown;
  auth_user_plan_raw?: unknown;
  auth_credit_usage_raw?: unknown;
  web_quota_raw?: unknown;
  web_quota_updated_at?: number | null;
  created_at: number;
  last_used: number;
}

export type QoderRewardStatus = 'claimable' | 'claimed' | 'none' | 'unknown';

export function getQoderRewardWindowEndMs(account: QoderAccount): number | null {
  return normalizeTimestampMs(account.reward_window_end_at);
}

export function resolveQoderRewardStatus(account: QoderAccount, now = Date.now()): QoderRewardStatus {
  if (!account.reward_claim_status) {
    return 'unknown';
  }
  const windowEndMs = getQoderRewardWindowEndMs(account);
  if (windowEndMs != null && now >= windowEndMs) {
    return 'unknown';
  }
  const statusUpper = account.reward_claim_status.toUpperCase();
  if (statusUpper === 'CLAIMABLE') {
    return 'claimable';
  }
  if (statusUpper === 'CLAIMED') {
    return 'claimed';
  }
  if (statusUpper === 'NONE') {
    return 'none';
  }
  return 'unknown';
}

interface UnknownRecord {
  [key: string]: unknown;
}

export interface QoderUsage {
  inlineSuggestionsUsedPercent: number | null;
  chatMessagesUsedPercent: number | null;
  allowanceResetAt?: number | null;
  creditsUsed: number | null;
  creditsTotal: number | null;
  creditsRemaining: number | null;
}

export interface QoderQuotaBucket {
  used: number | null;
  total: number | null;
  remaining: number | null;
  percentage: number | null;
}

export interface QoderSubscriptionInfo {
  planTag: string;
  userType: string | null;
  isPersonalVersion: boolean | null;
  isHighestTier: boolean;
  userQuota: QoderQuotaBucket;
  addOnQuota: QoderQuotaBucket;
  sharedCreditPackageUsed: number | null;
  totalUsagePercentage: number | null;
  expiresAt: number | null;
  detailUrl: string | null;
  upgradeUrl: string | null;
  addCreditsUrl: string | null;
}

export function shouldShowQoderSubscriptionReset(
  subscription: Pick<QoderSubscriptionInfo, 'expiresAt' | 'userType'>,
): boolean {
  return (
    subscription.expiresAt != null &&
    subscription.userType?.trim().toLowerCase() !== 'personal_standard'
  );
}

export interface QoderUsageOverview {
  planTag: string;
  usagePercent: number | null;
  creditsUsed: number | null;
  creditsTotal: number | null;
  creditsRemaining: number | null;
  unit: string;
  detailUrl: string | null;
  upgradeUrl: string | null;
  isQuotaExceeded: boolean;
}

const QODER_SENTINEL_EXPIRES_AT_MS = Date.UTC(9999, 11, 31, 0, 0, 0);

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function getNestedValue(root: unknown, path: string[]): unknown {
  let current: unknown = root;
  for (const key of path) {
    if (!isRecord(current)) return undefined;
    current = current[key];
  }
  return current;
}

function toNonEmptyString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function toFiniteNumber(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function toBoolean(value: unknown): boolean {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    return normalized === '1' || normalized === 'true';
  }
  if (typeof value === 'number') return value === 1;
  return false;
}

function toBooleanOrNull(value: unknown): boolean | null {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (!normalized) return null;
    if (normalized === '1' || normalized === 'true') return true;
    if (normalized === '0' || normalized === 'false') return false;
    return null;
  }
  if (typeof value === 'number') {
    if (value === 1) return true;
    if (value === 0) return false;
  }
  return null;
}

function firstNonEmptyString(...values: unknown[]): string | null {
  for (const value of values) {
    const normalized = toNonEmptyString(value);
    if (normalized) return normalized;
  }
  return null;
}

function firstFiniteNumber(...values: unknown[]): number | null {
  for (const value of values) {
    const normalized = toFiniteNumber(value);
    if (normalized != null) return normalized;
  }
  return null;
}

function firstBoolean(...values: unknown[]): boolean | null {
  for (const value of values) {
    const normalized = toBooleanOrNull(value);
    if (normalized != null) return normalized;
  }
  return null;
}

function firstRecord(...values: unknown[]): UnknownRecord | null {
  for (const value of values) {
    if (isRecord(value)) return value;
  }
  return null;
}

function clampPercent(value: number | null): number | null {
  if (value == null) return null;
  const normalized = value <= 1 ? value * 100 : value;
  return Math.max(0, Math.min(100, normalized));
}

function normalizeTimestampMs(value: unknown): number | null {
  const normalized = toFiniteNumber(value);
  if (normalized == null || normalized <= 0) return null;
  const timestampMs =
    normalized >= 1_000_000_000_000 ? Math.round(normalized) : Math.round(normalized * 1000);
  if (timestampMs >= QODER_SENTINEL_EXPIRES_AT_MS) return null;
  return timestampMs;
}

function parseQuotaBucket(raw: unknown, fallback?: Partial<QoderQuotaBucket>): QoderQuotaBucket {
  const used = firstFiniteNumber(
    getNestedValue(raw, ['used']),
    getNestedValue(raw, ['usage']),
    getNestedValue(raw, ['consumed']),
    fallback?.used,
  );
  const total = firstFiniteNumber(
    getNestedValue(raw, ['total']),
    getNestedValue(raw, ['quota']),
    getNestedValue(raw, ['limit']),
    fallback?.total,
  );
  const remaining = firstFiniteNumber(
    getNestedValue(raw, ['remaining']),
    getNestedValue(raw, ['available']),
    getNestedValue(raw, ['left']),
    fallback?.remaining,
    total != null && used != null ? total - used : null,
  );
  const percentage = clampPercent(
    firstFiniteNumber(
      getNestedValue(raw, ['percentage']),
      getNestedValue(raw, ['usagePercent']),
      getNestedValue(raw, ['usage_percentage']),
      fallback?.percentage,
      total != null && used != null && total > 0 ? (used / total) * 100 : null,
    ),
  );

  return {
    used,
    total,
    remaining,
    percentage,
  };
}

function getRawPlanTag(account: QoderAccount): string | null {
  return firstNonEmptyString(
    getNestedValue(account.auth_user_plan_raw, ['plan_tier_name']),
    getNestedValue(account.auth_user_plan_raw, ['tier_name']),
    getNestedValue(account.auth_user_plan_raw, ['tierName']),
    getNestedValue(account.auth_user_plan_raw, ['planTierName']),
    getNestedValue(account.auth_user_plan_raw, ['plan_name']),
    getNestedValue(account.auth_user_plan_raw, ['planName']),
    getNestedValue(account.auth_user_plan_raw, ['plan']),
    getNestedValue(account.auth_credit_usage_raw, ['plan_tier_name']),
    getNestedValue(account.auth_credit_usage_raw, ['tier_name']),
    getNestedValue(account.auth_credit_usage_raw, ['tierName']),
    getNestedValue(account.auth_credit_usage_raw, ['planTierName']),
    account.plan_type,
    getNestedValue(account.auth_user_info_raw, ['userTag']),
    getNestedValue(account.auth_user_info_raw, ['user_tag']),
    getNestedValue(account.auth_credit_usage_raw, ['userType']),
    getNestedValue(account.auth_credit_usage_raw, ['user_type']),
    getNestedValue(account.auth_user_plan_raw, ['userType']),
    getNestedValue(account.auth_user_plan_raw, ['user_type']),
    getNestedValue(account.auth_user_info_raw, ['userType']),
    getNestedValue(account.auth_user_info_raw, ['user_type']),
  );
}

// 按 Qoder CN App/IDE 已确认的接口枚举显示用户可读套餐名。
const QODER_PLAN_LABELS: Record<string, string> = {
  personal_standard: 'Free',
  personal_professional_trial: 'Free',
  personal_professional: 'Pro',
  personal_professional_plus: 'Pro+',
  personal_ultra: 'Ultra',
  teams: 'Teams',
  enterprise: 'Enterprise',
  enterprise_standard: 'Enterprise Standard',
  enterprise_professional: 'Enterprise VPC',
  'enterprise standard': 'Enterprise Standard',
  'enterprise vpc': 'Enterprise VPC',
  '体验版': 'Free',
  '专业版': 'Pro',
  '高级版': 'Pro+',
  '旗舰版': 'Ultra',
  '团队版': 'Teams',
  '企业标准版': 'Enterprise Standard',
  '企业专属版': 'Enterprise VPC',
};

export function getQoderAccountDisplayEmail(account: QoderAccount): string {
  const email = account.email?.trim();
  if (email && email.toLowerCase() !== 'unknown@qoder.local') return email;
  const securityMobile = toNonEmptyString(
    getNestedValue(account.auth_user_info_raw, ['security_mobile']),
  );
  return securityMobile || account.display_name || account.user_id || account.id;
}

export function getQoderPlanBadge(account: QoderAccount): string {
  const raw = getRawPlanTag(account);
  if (raw) return QODER_PLAN_LABELS[raw.trim().toLowerCase()] ?? raw;
  return 'UNKNOWN';
}

export function getQoderSubscriptionInfo(account: QoderAccount): QoderSubscriptionInfo {
  const planTag = getQoderPlanBadge(account);
  const userQuota = parseQuotaBucket(
    firstRecord(
      getNestedValue(account.auth_credit_usage_raw, ['userQuota']),
      getNestedValue(account.auth_user_plan_raw, ['userQuota']),
      getNestedValue(account.auth_user_info_raw, ['userQuota']),
    ),
    {
      used: account.credits_used,
      total: account.credits_total,
      remaining: account.credits_remaining,
      percentage: account.credits_usage_percent,
    },
  );
  const addOnQuota = parseQuotaBucket(
    firstRecord(
      getNestedValue(account.auth_credit_usage_raw, ['addOnQuota']),
      getNestedValue(account.auth_credit_usage_raw, ['addonQuota']),
      getNestedValue(account.auth_credit_usage_raw, ['add_on_quota']),
      getNestedValue(account.auth_user_plan_raw, ['addOnQuota']),
      getNestedValue(account.auth_user_plan_raw, ['addonQuota']),
      getNestedValue(account.auth_user_plan_raw, ['add_on_quota']),
    ),
  );
  const sharedCreditPackageRaw = firstRecord(
    getNestedValue(account.auth_credit_usage_raw, ['orgResourcePackage']),
    getNestedValue(account.auth_credit_usage_raw, ['organizationResourcePackage']),
    getNestedValue(account.auth_credit_usage_raw, ['sharedCreditPackage']),
    getNestedValue(account.auth_credit_usage_raw, ['resourcePackage']),
    getNestedValue(account.auth_user_plan_raw, ['orgResourcePackage']),
    getNestedValue(account.auth_user_plan_raw, ['organizationResourcePackage']),
    getNestedValue(account.auth_user_plan_raw, ['sharedCreditPackage']),
    getNestedValue(account.auth_user_plan_raw, ['resourcePackage']),
  );
  const totalUsagePercentage = clampPercent(
    firstFiniteNumber(
      getNestedValue(account.auth_credit_usage_raw, ['totalUsagePercentage']),
      getNestedValue(account.auth_credit_usage_raw, ['total_usage_percentage']),
      getNestedValue(account.auth_user_plan_raw, ['totalUsagePercentage']),
      getNestedValue(account.auth_user_plan_raw, ['total_usage_percentage']),
    ),
  );
  const detailUrl = firstNonEmptyString(
    getNestedValue(account.auth_credit_usage_raw, ['creditBreakdownUrl']),
    getNestedValue(account.auth_user_plan_raw, ['creditBreakdownUrl']),
    getNestedValue(account.auth_credit_usage_raw, ['usageDetailUrl']),
    getNestedValue(account.auth_credit_usage_raw, ['usageDetailsUrl']),
    getNestedValue(account.auth_credit_usage_raw, ['detailUrl']),
    getNestedValue(account.auth_credit_usage_raw, ['overviewUrl']),
    getNestedValue(account.auth_credit_usage_raw, ['usageUrl']),
  );
  const upgradeUrl = firstNonEmptyString(
    getNestedValue(account.auth_credit_usage_raw, ['upgradeUrl']),
    getNestedValue(account.auth_user_plan_raw, ['upgradeUrl']),
    getNestedValue(account.auth_user_info_raw, ['upgradeUrl']),
  );
  const addCreditsUrl = firstNonEmptyString(
    getNestedValue(account.auth_credit_usage_raw, ['addCreditsUrl']),
    getNestedValue(account.auth_credit_usage_raw, ['add_credits_url']),
    getNestedValue(account.auth_credit_usage_raw, ['topUpUrl']),
    getNestedValue(account.auth_credit_usage_raw, ['top_up_url']),
    getNestedValue(account.auth_user_plan_raw, ['addCreditsUrl']),
    getNestedValue(account.auth_user_plan_raw, ['add_credits_url']),
    getNestedValue(account.auth_user_plan_raw, ['topUpUrl']),
    getNestedValue(account.auth_user_plan_raw, ['top_up_url']),
  );
  const expiresAt = normalizeTimestampMs(
    firstFiniteNumber(
      getNestedValue(account.auth_credit_usage_raw, ['expiresAt']),
      getNestedValue(account.auth_credit_usage_raw, ['expires_at']),
      getNestedValue(account.auth_credit_usage_raw, ['resetAt']),
      getNestedValue(account.auth_credit_usage_raw, ['reset_at']),
      getNestedValue(account.auth_user_plan_raw, ['expiresAt']),
      getNestedValue(account.auth_user_plan_raw, ['expires_at']),
      getNestedValue(account.auth_user_plan_raw, ['resetAt']),
      getNestedValue(account.auth_user_plan_raw, ['reset_at']),
      getNestedValue(account.auth_user_info_raw, ['expiresAt']),
      getNestedValue(account.auth_user_info_raw, ['expires_at']),
    ),
  );

  return {
    planTag,
    userType: firstNonEmptyString(
      getNestedValue(account.auth_credit_usage_raw, ['userType']),
      getNestedValue(account.auth_credit_usage_raw, ['user_type']),
      getNestedValue(account.auth_user_plan_raw, ['userType']),
      getNestedValue(account.auth_user_plan_raw, ['user_type']),
      getNestedValue(account.auth_user_info_raw, ['userType']),
      getNestedValue(account.auth_user_info_raw, ['user_type']),
    ),
    isPersonalVersion: firstBoolean(
      getNestedValue(account.auth_credit_usage_raw, ['isPersonalVersion']),
      getNestedValue(account.auth_credit_usage_raw, ['is_personal_version']),
      getNestedValue(account.auth_user_plan_raw, ['isPersonalVersion']),
      getNestedValue(account.auth_user_plan_raw, ['is_personal_version']),
      getNestedValue(account.auth_user_info_raw, ['isPersonalVersion']),
      getNestedValue(account.auth_user_info_raw, ['is_personal_version']),
    ),
    isHighestTier:
      firstBoolean(
        getNestedValue(account.auth_credit_usage_raw, ['isHighestTier']),
        getNestedValue(account.auth_credit_usage_raw, ['is_highest_tier']),
        getNestedValue(account.auth_user_plan_raw, ['isHighestTier']),
        getNestedValue(account.auth_user_plan_raw, ['is_highest_tier']),
        getNestedValue(account.auth_user_info_raw, ['isHighestTier']),
        getNestedValue(account.auth_user_info_raw, ['is_highest_tier']),
      ) ?? false,
    userQuota,
    addOnQuota,
    sharedCreditPackageUsed: firstFiniteNumber(
      getNestedValue(sharedCreditPackageRaw, ['used']),
      getNestedValue(sharedCreditPackageRaw, ['usage']),
      getNestedValue(sharedCreditPackageRaw, ['consumed']),
      getNestedValue(sharedCreditPackageRaw, ['count']),
    ),
    totalUsagePercentage,
    expiresAt,
    detailUrl,
    upgradeUrl,
    addCreditsUrl,
  };
}

export function getQoderUsage(account: QoderAccount): QoderUsage {
  const subscription = getQoderSubscriptionInfo(account);
  const percent = subscription.userQuota.percentage ?? subscription.totalUsagePercentage;

  return {
    inlineSuggestionsUsedPercent: percent,
    chatMessagesUsedPercent: percent,
    allowanceResetAt: subscription.expiresAt,
    creditsUsed: subscription.userQuota.used,
    creditsTotal: subscription.userQuota.total,
    creditsRemaining: subscription.userQuota.remaining,
  };
}

export function getQoderUsageOverview(account: QoderAccount): QoderUsageOverview {
  const subscription = getQoderSubscriptionInfo(account);
  const usage = getQoderUsage(account);

  return {
    planTag: subscription.planTag,
    usagePercent: usage.inlineSuggestionsUsedPercent,
    creditsUsed: usage.creditsUsed,
    creditsTotal: usage.creditsTotal,
    creditsRemaining: usage.creditsRemaining,
    unit:
      firstNonEmptyString(getNestedValue(account.auth_credit_usage_raw, ['userQuota', 'unit'])) ||
      'Credits',
    detailUrl: subscription.detailUrl || subscription.upgradeUrl,
    upgradeUrl: subscription.upgradeUrl,
    isQuotaExceeded:
      toBoolean(getNestedValue(account.auth_credit_usage_raw, ['isQuotaExceeded'])) ||
      toBoolean(getNestedValue(account.auth_user_info_raw, ['isQuotaExceeded'])),
  };
}

export function hasQoderQuotaData(account: QoderAccount): boolean {
  return getCurrentWebQuotaPayload(account) != null || account.auth_credit_usage_raw != null
    || getQoderSubscriptionInfo(account).sharedCreditPackageUsed != null;
}

interface QoderWebQuotaDetailItem {
  id?: string;
  package_id?: string;
  name?: string;
  package_name?: string;
  source?: string;
  limit_value?: number;
  used_value?: number;
  effective_at?: number;
  expires_at?: number;
}

interface QoderWebQuotaPayload {
  account_quota?: {
    limit_value?: number;
    used_value?: number;
    reset_time?: number;
  };
  plan_quota?: {
    quota_summary?: {
      limit_value?: number;
      used_value?: number;
      remaining_value?: number;
    };
    quota_detail?: QoderWebQuotaDetailItem[];
  };
  resource_package_quota?: {
    quota_summary?: {
      limit_value?: number;
      used_value?: number;
      remaining_value?: number;
    };
    limit_value?: number;
    used_value?: number;
    quota_detail?: QoderWebQuotaDetailItem[];
  };
  nextResetAt?: number;
  lastResetAt?: number;
}

function getCurrentWebQuotaPayload(account: QoderAccount): QoderWebQuotaPayload | null {
  if (!isRecord(account.web_quota_raw)) return null;
  const webUpdatedAt = normalizeTimestampMs(account.web_quota_updated_at);
  const usageUpdatedAt = normalizeTimestampMs(account.usage_updated_at);
  if (usageUpdatedAt != null && (webUpdatedAt == null || webUpdatedAt < usageUpdatedAt)) {
    return null;
  }
  const payload = isRecord(account.web_quota_raw.data) ? account.web_quota_raw.data : account.web_quota_raw;
  return payload as QoderWebQuotaPayload;
}

export function getQoderQuotaCategoryGroups(
  account: QoderAccount,
  t: (key: string, defaultValue?: string) => string,
): QuotaCategoryGroup[] {
  const webPayload = getCurrentWebQuotaPayload(account);

  const subscription = getQoderSubscriptionInfo(account);

  // 1. 基础体验包
  const rawAccountQuota = webPayload?.account_quota;
  const rawPlanQuota = webPayload?.plan_quota;
  const baseTotal = firstFiniteNumber(
    rawPlanQuota?.quota_summary?.limit_value,
    rawAccountQuota?.limit_value,
    subscription.userQuota.total,
  ) ?? 0;
  const baseUsed = firstFiniteNumber(
    rawPlanQuota?.quota_summary?.used_value,
    rawAccountQuota?.used_value,
    subscription.userQuota.used,
  ) ?? 0;
  const baseRemain = Math.max(0, baseTotal - baseUsed);
  const baseUsedPercent = baseTotal > 0 ? Math.max(0, Math.min(100, (baseUsed / baseTotal) * 100)) : 0;
  const baseRemainPercent = baseTotal > 0 ? Math.max(0, Math.min(100, (baseRemain / baseTotal) * 100)) : null;
  const baseResetTime = normalizeTimestampMs(
    firstFiniteNumber(
      webPayload?.nextResetAt,
      rawAccountQuota?.reset_time,
      subscription.expiresAt,
    ),
  ) ?? null;

  const baseItem: OfficialQuotaResource = {
    packageCode: 'base',
    packageName: t('codebuddy.quotaCategory.base', '基础体验包'),
    cycleStartTime: null,
    cycleEndTime: null,
    deductionEndTime: null,
    expiredTime: null,
    total: baseTotal,
    remain: baseRemain,
    used: baseUsed,
    usedPercent: baseUsedPercent,
    remainPercent: baseRemainPercent,
    refreshAt: baseResetTime,
    expireAt: null,
    isBasePackage: true,
    unlimited: false,
  };
  const baseItems: OfficialQuotaResource[] = [baseItem];

  // 2. 活动赠送包
  const rawPackageQuota = webPayload?.resource_package_quota;
  // 官方 App 用量接口也提供积分包明细，不要求账号已有网页 Cookie。
  const usageRaw = isRecord(account.auth_credit_usage_raw) ? account.auth_credit_usage_raw : null;
  const usage = isRecord(usageRaw?.qoderUsage) ? usageRaw.qoderUsage : usageRaw;
  const dedicatedPackages = usage?.dedicatedResourcePackages ?? usage?.dedicated_resource_packages;
  const nativeDetails: QoderWebQuotaDetailItem[] = Array.isArray(dedicatedPackages)
    ? dedicatedPackages.filter(isRecord).flatMap((pkg) => {
        const id = toNonEmptyString(pkg.id);
        const total = toFiniteNumber(pkg.total);
        const used = toFiniteNumber(pkg.used) ?? 0;
        if (!id || total == null || total <= 0 || used < 0) return [];
        return [{
          id,
          name: toNonEmptyString(pkg.name) ?? undefined,
          limit_value: total,
          used_value: used,
          expires_at: firstFiniteNumber(pkg.expiresAt, pkg.expires_at) ?? undefined,
        }];
      })
    : [];
  const rawDetails = Array.isArray(rawPackageQuota?.quota_detail) ? rawPackageQuota.quota_detail : [];
  const activityItems: OfficialQuotaResource[] = [];
  let activitySummary: { total: number; used: number } | null = null;
  const hasCompleteDetails = rawDetails.length > 0 && rawDetails.every((pkg) =>
    isRecord(pkg) && toFiniteNumber(pkg.limit_value) != null && toFiniteNumber(pkg.used_value) != null,
  );

  const resourcesFromDetails = (details: QoderWebQuotaDetailItem[]): OfficialQuotaResource[] =>
    details.map<OfficialQuotaResource>((pkg) => {
      const pkgTotal = toFiniteNumber(pkg.limit_value)!;
      const pkgUsed = toFiniteNumber(pkg.used_value)!;
      const pkgRemain = Math.max(0, pkgTotal - pkgUsed);
      const pkgUsedPercent = pkgTotal > 0 ? Math.max(0, Math.min(100, (pkgUsed / pkgTotal) * 100)) : 0;
      const pkgRemainPercent = pkgTotal > 0 ? Math.max(0, Math.min(100, (pkgRemain / pkgTotal) * 100)) : null;
      const pkgExpireAt = normalizeTimestampMs(pkg.expires_at);
      const pkgEffectiveAt = normalizeTimestampMs(pkg.effective_at);
      const pkgName =
        toNonEmptyString(pkg.package_name) ||
        toNonEmptyString(pkg.name) ||
        t('common.shared.columns.creditPackage', '附加 Credits');

      return {
        packageCode: 'activity',
        packageName: pkgName,
        cycleStartTime: pkgEffectiveAt != null ? String(pkgEffectiveAt) : null,
        cycleEndTime: null,
        deductionEndTime: null,
        expiredTime: null,
        total: pkgTotal,
        remain: pkgRemain,
        used: pkgUsed,
        usedPercent: pkgUsedPercent,
        remainPercent: pkgRemainPercent,
        refreshAt: null,
        expireAt: pkgExpireAt,
        isBasePackage: false,
        unlimited: false,
      };
    });

  if (hasCompleteDetails) {
    activityItems.push(...resourcesFromDetails(rawDetails));
  } else {
    // 只有汇总额度时只展示汇总，不能据此推断礼包数量、领取日或到期日。
    const actTotal = firstFiniteNumber(
      rawPackageQuota?.quota_summary?.limit_value,
      rawPackageQuota?.limit_value,
      subscription.addOnQuota.total,
    ) ?? 0;
    const actUsed = firstFiniteNumber(
      rawPackageQuota?.quota_summary?.used_value,
      rawPackageQuota?.used_value,
      subscription.addOnQuota.used,
    ) ?? 0;

    activitySummary = { total: actTotal, used: actUsed };
  }

  // 按到期时间由近及远排序
  activityItems.sort((a, b) => {
    if (a.expireAt == null && b.expireAt == null) return 0;
    if (a.expireAt == null) return 1;
    if (b.expireAt == null) return -1;
    return a.expireAt - b.expireAt;
  });

  const aggregate = (
    items: OfficialQuotaResource[],
    summary?: { total: number; used: number } | null,
  ): Omit<QuotaCategoryGroup, 'key' | 'label' | 'items' | 'visible'> => {
    const unlimited = items.some((item) => item.unlimited);
    const total = summary?.total ?? items.reduce((sum, r) => sum + r.total, 0);
    const used = summary?.used ?? items.reduce((sum, r) => sum + r.used, 0);
    const remain = summary ? Math.max(0, total - used) : items.reduce((sum, r) => sum + r.remain, 0);
    const usedPercent = unlimited ? 0 : total > 0 ? Math.max(0, Math.min(100, (used / total) * 100)) : 0;
    const remainPercent = unlimited ? null : total > 0 ? Math.max(0, Math.min(100, (remain / total) * 100)) : null;
    const quotaClass =
      remainPercent != null ? (remainPercent <= 10 ? 'critical' : remainPercent <= 30 ? 'low' : remainPercent <= 60 ? 'medium' : 'high') : 'high';
    return {
      total: unlimited ? -1 : total,
      remain: unlimited ? -1 : remain,
      used: unlimited ? 0 : used,
      usedPercent,
      remainPercent,
      quotaClass,
      unlimited,
    };
  };

  const baseAgg = aggregate(baseItems);
  const activityAgg = aggregate(activityItems, activitySummary);

  const groups: QuotaCategoryGroup[] = [
    {
      key: 'base',
      label: t('codebuddy.quotaCategory.base', '基础体验包'),
      ...baseAgg,
      items: baseItems,
      visible: true,
    },
    {
      key: 'activity',
      label: t('common.shared.columns.creditPackage', '附加 Credits'),
      ...activityAgg,
      items: activityItems,
      visible: activityAgg.total > 0 || activityItems.length > 0,
    },
  ];

  // The official App treats dedicated packages separately from addOnQuota.
  // Combining them would drop purchased/add-on credits or count them twice.
  if (nativeDetails.length > 0) {
    const dedicatedItems = resourcesFromDetails(nativeDetails);
    dedicatedItems.sort((a, b) => (a.expireAt ?? Infinity) - (b.expireAt ?? Infinity));
    groups.push({
      key: 'extra',
      label: t('qoder.quota.dedicatedPackages', '专属积分包'),
      ...aggregate(dedicatedItems),
      items: dedicatedItems,
      visible: true,
    });
  }

  if (subscription.sharedCreditPackageUsed != null) {
    groups.push({
      key: 'other',
      label: t('common.shared.columns.sharedCreditPackage', 'Shared Credit Package'),
      used: subscription.sharedCreditPackageUsed,
      total: 0,
      remain: 0,
      usedPercent: 0,
      remainPercent: null,
      quotaClass: 'high',
      items: [],
      visible: true,
      usageOnly: true,
    });
  }
  return groups;
}

// ---------------------------------------------------------------------------
// Qoder 套件变体：四个变体键与显示名（结构对齐 TraePlatformKind）。
//
// 显示名为固定品牌字面量，须逐字渲染、不做意译；经 `qoder.suite.variants.*`
// 本地化（品牌字面量，各语言一致）。
//
// variant 记录凭据来源；账号身份按地区共享，四个客户端入口保持独立。
// ---------------------------------------------------------------------------

export type QoderVariantId = 'qoder' | 'qoder_app' | 'qoder_cn_ide' | 'qoder_cn_app';

export const QODER_VARIANT_IDS: readonly QoderVariantId[] = [
  'qoder',
  'qoder_app',
  'qoder_cn_ide',
  'qoder_cn_app',
];

/** 支持应用多开的 Qoder 变体：仅 IDE 系。 */
export type QoderInstanceVariantId = Extract<QoderVariantId, 'qoder' | 'qoder_cn_ide'>;

export const QODER_INSTANCE_VARIANT_IDS: readonly QoderInstanceVariantId[] = [
  'qoder',
  'qoder_cn_ide',
];

export function isQoderVariantId(value: string): value is QoderVariantId {
  return QODER_VARIANT_IDS.some((variant) => variant === value);
}

/** 固定显示名（品牌字面量，逐字渲染）。 */
export const QODER_VARIANT_DISPLAY_NAMES: Record<QoderVariantId, string> = {
  qoder: 'Qoder IDE',
  qoder_app: 'Qoder',
  qoder_cn_ide: 'Qoder CN IDE',
  qoder_cn_app: 'Qoder CN',
};

function toNonEmptyVariantString(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export function normalizeQoderVariantId(raw: unknown): QoderVariantId | null {
  const value = toNonEmptyVariantString(raw);
  if (!value) return null;
  const normalized = value.toLowerCase().replace(/-/g, '_');
  switch (normalized) {
    case 'qoder':
      return 'qoder';
    case 'qoder_app':
      return 'qoder_app';
    case 'qoder_cn_ide':
      return 'qoder_cn_ide';
    case 'qoder_cn_app':
      return 'qoder_cn_app';
    default:
      return null;
  }
}

/**
 * 返回凭据来源变体；列表归属请使用 qoderAccountSupportsVariant。
 */
export function getQoderAccountVariantId(account: QoderAccount): QoderVariantId {
  return normalizeQoderVariantId(account.variant) ?? 'qoder';
}

/** Client navigation stays four-way; account membership is regional. */
export function qoderAccountSupportsVariant(account: Pick<QoderAccount, 'variant'>, variant: string): boolean {
  const source = account.variant == null ? 'qoder' : normalizeQoderVariantId(account.variant);
  const target = normalizeQoderVariantId(variant);
  if (!source || !target) return false;
  return source.startsWith('qoder_cn_') === target.startsWith('qoder_cn_');
}

export function getQoderAccountVariants(account: QoderAccount): QoderVariantId[] {
  return QODER_VARIANT_IDS.filter((variant) => qoderAccountSupportsVariant(account, variant));
}
