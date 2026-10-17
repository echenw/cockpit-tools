import assert from "node:assert/strict";
import test from "node:test";
import {
  getQoderAccountDisplayEmail,
  getQoderAccountVariantId,
  getQoderAccountVariants,
  qoderAccountSupportsVariant,
  getQoderPlanBadge,
  getQoderSubscriptionInfo,
  hasQoderQuotaData,
  resolveQoderRewardStatus,
  getQoderRewardStatusExpiryMs,
  type QoderAccount,
} from "./qoder.ts";

function makeAccount(overrides: Partial<QoderAccount>): QoderAccount {
  return {
    id: "account-id",
    email: "",
    created_at: 0,
    last_used: 0,
    ...overrides,
  };
}

test("all variants display the normalized IPC quota buckets and reset time", () => {
  for (const variant of ["qoder", "qoder_app", "qoder_cn_ide", "qoder_cn_app"]) {
    const account = makeAccount({
      variant,
      // Contract emitted by QoderAccount.for_ipc after unwrapping qoderUsage.
      auth_credit_usage_raw: {
        userQuota: { total: 200, used: 40, remaining: 160, percentage: 20 },
        addOnQuota: { total: 500, used: 100, remaining: 400, percentage: 20 },
        expiresAt: 1791041092084,
        totalUsagePercentage: 20,
        isQuotaExceeded: false,
      },
      // Explicit buckets must win over older summary fields.
      credits_used: 100,
      credits_total: 500,
      credits_remaining: 400,
    });
    assert.equal(hasQoderQuotaData(account), true);
    const subscription = getQoderSubscriptionInfo(account);
    assert.deepEqual(subscription.userQuota, {
      used: 40, total: 200, remaining: 160, percentage: 20,
    });
    assert.deepEqual(subscription.addOnQuota, {
      used: 100, total: 500, remaining: 400, percentage: 20,
    });
    assert.equal(subscription.expiresAt, 1791041092084);
    assert.equal(subscription.totalUsagePercentage, 20);
  }
});

test("uses the provider's usage userType only when no explicit plan exists", () => {
  const account = makeAccount({
    display_name: "Sample User",
    auth_user_info_raw: { user: { id: "user-a", name: "Sample User" } },
    auth_credit_usage_raw: { userType: "personal_standard" },
  });
  assert.equal(getQoderPlanBadge(account), "Free");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_credit_usage_raw: { userType: "personal_professional_trial" },
  }), "Free");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_credit_usage_raw: { userType: "personal_professional" },
  }), "Pro");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_credit_usage_raw: { userType: "personal_professional_plus" },
  }), "Pro+");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_credit_usage_raw: { userType: "personal_ultra" },
  }), "Ultra");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_user_plan_raw: { planTierName: "enterprise vpc" },
    auth_credit_usage_raw: { userType: "enterprise" },
  }), "Enterprise VPC");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_user_plan_raw: { planName: "Ultra" },
    auth_credit_usage_raw: { userType: "personal_ultra" },
  }), "Ultra");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_user_plan_raw: { planTierName: "企业专属版" },
    auth_credit_usage_raw: { userType: "enterprise" },
  }), "Enterprise VPC");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_credit_usage_raw: { userType: "enterprise" },
  }), "Enterprise");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_credit_usage_raw: { userType: "enterprise_professional" },
  }), "Enterprise VPC");
  assert.equal(getQoderPlanBadge({
    ...account,
    plan_type: "personal_standard",
    auth_credit_usage_raw: {},
  }), "Free");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_user_plan_raw: { plan: "PRO" },
  }), "PRO");
  assert.equal(getQoderPlanBadge({
    ...account,
    auth_credit_usage_raw: {},
  }), "UNKNOWN");
});

test("reward windows expire in either seconds or milliseconds", () => {
  const pastMs = Date.now() - 60_000;
  const futureMs = Date.now() + 60_000;
  for (const status of ["CLAIMED", "CLAIMABLE"]) {
    for (const endAt of [pastMs, Math.floor(pastMs / 1000)]) {
      assert.equal(resolveQoderRewardStatus(makeAccount({
        reward_claim_status: status,
        reward_window_end_at: endAt,
      })), "unknown");
    }
    for (const endAt of [futureMs, Math.floor(futureMs / 1000)]) {
      assert.equal(resolveQoderRewardStatus(makeAccount({
        reward_claim_status: status,
        reward_window_end_at: endAt,
      })), status === "CLAIMED" ? "claimed" : "claimable");
    }
  }
});

test("campaign query failure never presents a cached NONE as a confirmed result", () => {
  const now = Date.now();
  const account = makeAccount({
    reward_claim_status: "NONE",
    reward_status_updated_at: Math.floor(now / 1000),
    reward_query_last_error: "fixture network failure",
  });
  assert.equal(resolveQoderRewardStatus(account, now), "unknown");
  assert.equal(resolveQoderRewardStatus({ ...account, reward_query_last_error: null }, now), "none");
});

test("missing reward window ends expire at 10:00 UTC+8 regardless of system timezone", () => {
  // Use absolute instants, not local Date constructors, so non-UTC+8 systems
  // expose an accidental setHours/setDate implementation.
  const yesterdayAfterReset = Date.parse("2026-10-11T02:05:00Z");
  const beforeReset = Date.parse("2026-10-12T01:59:59Z");
  const atReset = Date.parse("2026-10-12T02:00:00Z");
  const afterReset = Date.parse("2026-10-12T02:05:00Z");
  const nextReset = Date.parse("2026-10-13T02:00:00Z");

  for (const status of ["NONE", "CLAIMED", "UNCLAIMED", "CLAIMABLE"]) {
    const account = makeAccount({
      reward_claim_status: status,
      reward_window_end_at: null,
      reward_status_updated_at: Math.floor(yesterdayAfterReset / 1000),
    });
    const expected = status === "NONE" ? "none" : status === "CLAIMED" ? "claimed" : "claimable";
    assert.equal(getQoderRewardStatusExpiryMs(account), atReset);
    assert.equal(resolveQoderRewardStatus(account, beforeReset), expected);
    assert.equal(resolveQoderRewardStatus(account, atReset), "unknown");

    const refreshed = { ...account, reward_status_updated_at: afterReset };
    assert.equal(getQoderRewardStatusExpiryMs(refreshed), nextReset);
    assert.equal(resolveQoderRewardStatus(refreshed, afterReset), expected);
    assert.equal(resolveQoderRewardStatus(refreshed, nextReset), "unknown");
  }
});

test("UTC+8 activity boundary stays fixed across foreign DST changes", () => {
  const checkedAt = Date.parse("2026-03-08T00:00:00Z"); // LA enters DST that day
  const account = makeAccount({
    reward_claim_status: "NONE",
    reward_status_updated_at: checkedAt / 1000,
  });
  assert.equal(
    getQoderRewardStatusExpiryMs(account),
    Date.parse("2026-03-08T02:00:00Z"),
  );
  assert.equal(resolveQoderRewardStatus(account, Date.parse("2026-03-08T02:00:00Z")), "unknown");
});

test("an undated reward status must be refreshed, but an explicit server end remains authoritative", () => {
  const now = new Date(2026, 9, 12, 15).getTime();
  for (const status of ["NONE", "CLAIMED", "UNCLAIMED"]) {
    assert.equal(resolveQoderRewardStatus(makeAccount({ reward_claim_status: status }), now), "unknown");
  }
  assert.equal(resolveQoderRewardStatus(makeAccount({
    reward_claim_status: "UNCLAIMED",
    reward_window_end_at: now + 60_000,
  }), now), "claimable");
});

test("returns the trimmed email when a real email exists", () => {
  const account = makeAccount({ email: "  nick@example.com  " });
  assert.equal(getQoderAccountDisplayEmail(account), "nick@example.com");
});

test("skips the sentinel email and prefers display_name", () => {
  const account = makeAccount({
    email: "unknown@qoder.local",
    display_name: "nick2428355985",
  });
  assert.equal(getQoderAccountDisplayEmail(account), "nick2428355985");
});

test("skips the sentinel email and falls back to user_id", () => {
  const account = makeAccount({
    email: "unknown@qoder.local",
    user_id: "01a0d20d-0000-0000-0000-000000000000",
  });
  assert.equal(
    getQoderAccountDisplayEmail(account),
    "01a0d20d-0000-0000-0000-000000000000",
  );
});

test("skips the sentinel email and falls back to id", () => {
  const account = makeAccount({ email: "unknown@qoder.local" });
  assert.equal(getQoderAccountDisplayEmail(account), "account-id");
});

test("falls back to display_name when the email is empty", () => {
  const account = makeAccount({ email: "", display_name: "nick2428355985" });
  assert.equal(getQoderAccountDisplayEmail(account), "nick2428355985");
});

test("prefers security_mobile over display_name for sentinel CN accounts", () => {
  const account = makeAccount({
    email: "unknown@qoder.local",
    display_name: "nick2428355985",
    auth_user_info_raw: { security_mobile: "13800001111" },
  });
  assert.equal(getQoderAccountDisplayEmail(account), "13800001111");
});

test("falls back to display_name when security_mobile is empty", () => {
  const account = makeAccount({
    email: "unknown@qoder.local",
    display_name: "nick2428355985",
    auth_user_info_raw: { security_mobile: "   " },
  });
  assert.equal(getQoderAccountDisplayEmail(account), "nick2428355985");
});

test("uses the stored variant instead of raw payload markers", () => {
  const account = makeAccount({
    email: "nick@example.com",
    auth_user_info_raw: { platform: "qoder_app" },
  });
  assert.equal(getQoderAccountVariantId(account), "qoder");
  assert.equal(
    getQoderAccountVariantId({ ...account, variant: "qoder_cn_app" }),
    "qoder_cn_app",
  );
});

test("hasQoderQuotaData recognizes official credits or organization packages", () => {
  assert.equal(hasQoderQuotaData(makeAccount({})), false);
  assert.equal(
    hasQoderQuotaData(
      makeAccount({
        auth_credit_usage_raw: { userQuota: { total: 300, used: 50 } },
      }),
    ),
    true,
  );
  assert.equal(
    hasQoderQuotaData(
      makeAccount({
        auth_user_plan_raw: { orgResourcePackage: { used: 42 } },
      }),
    ),
    true,
  );
});

test("the refreshed plan projection wins over a stale login userTag", () => {
  assert.equal(getQoderPlanBadge(makeAccount({
    variant: "qoder_app",
    plan_type: "personal_professional",
    auth_user_info_raw: { userTag: "FREE" },
    auth_credit_usage_raw: { userType: "personal_professional" },
  })), "Pro");
});

test('one authorized account appears in both clients of its region only', () => {
  for (const source of ['qoder', 'qoder_app', 'qoder_cn_ide', 'qoder_cn_app']) {
    const account = makeAccount({ variant: source });
    const expected = source.startsWith('qoder_cn_') ? ['qoder_cn_ide', 'qoder_cn_app'] : ['qoder', 'qoder_app'];
    assert.deepEqual(getQoderAccountVariants(account), expected);
    for (const target of ['qoder', 'qoder_app', 'qoder_cn_ide', 'qoder_cn_app']) {
      assert.equal(qoderAccountSupportsVariant(account, target), expected.includes(target));
    }
  }
  assert.equal(qoderAccountSupportsVariant(makeAccount({ variant: 'invalid' }), 'qoder'), false);
});
