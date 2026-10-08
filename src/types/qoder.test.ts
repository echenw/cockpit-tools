import assert from "node:assert/strict";
import test from "node:test";
import {
  getQoderAccountDisplayEmail,
  getQoderAccountVariantId,
  getQoderAccountVariants,
  qoderAccountSupportsVariant,
  getQoderPlanBadge,
  getQoderSubscriptionInfo,
  getQoderQuotaCategoryGroups,
  hasQoderQuotaData,
  resolveQoderRewardStatus,
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

test("getQoderQuotaCategoryGroups builds groups from web_quota_raw with multiple packages and sorts by expireAt", () => {
  const dummyT = (_key: string, def?: string) => def ?? _key;
  const account = makeAccount({
    email: "test@qoder.com",
    web_quota_raw: {
      code: "SUCCESS",
      data: {
        account_quota: {
          limit_value: 300,
          used_value: 50,
          reset_time: 1793289599000,
        },
        resource_package_quota: {
          limit_value: 200,
          used_value: 10,
          quota_detail: [
            {
              package_id: "pkg-later",
              limit_value: 100,
              used_value: 0,
              effective_at: 1790684488000,
              expires_at: 1793289599000,
            },
            {
              package_id: "pkg-earlier",
              limit_value: 100,
              used_value: 10,
              effective_at: 1790598088000,
              expires_at: 1793203199000,
            },
          ],
        },
      },
    },
  });

  const groups = getQoderQuotaCategoryGroups(account, dummyT);
  assert.equal(groups.length, 2);

  // 基础体验包
  const baseGroup = groups.find((g) => g.key === "base");
  assert.ok(baseGroup);
  assert.equal(baseGroup.label, "基础体验包");
  assert.equal(baseGroup.total, 300);
  assert.equal(baseGroup.used, 50);
  assert.equal(baseGroup.remain, 250);
  assert.equal(baseGroup.items.length, 1);
  assert.equal(baseGroup.items[0].refreshAt, 1793289599000);

  // 活动赠送包
  const activityGroup = groups.find((g) => g.key === "activity");
  assert.ok(activityGroup);
  assert.equal(activityGroup.label, "附加 Credits");
  assert.equal(activityGroup.total, 200);
  assert.equal(activityGroup.used, 10);
  assert.equal(activityGroup.remain, 190);
  assert.equal(activityGroup.items.length, 2);

  // 必须按到期时间升序排序（更早到期的在前）
  assert.equal(activityGroup.items[0].expireAt, 1793203199000);
  assert.equal(activityGroup.items[0].used, 10);
  assert.equal(activityGroup.items[0].remain, 90);
  assert.equal(activityGroup.items[1].expireAt, 1793289599000);
  assert.equal(activityGroup.items[1].used, 0);
  assert.equal(activityGroup.items[1].remain, 100);
});

test("native dedicated packages display without cookies and preserve separate add-on totals", () => {
  for (const variant of ["qoder", "qoder_app", "qoder_cn_ide", "qoder_cn_app"]) {
    const groups = getQoderQuotaCategoryGroups(makeAccount({
      variant,
      auth_credit_usage_raw: {
        userQuota: { total: 300, used: 20 },
        addOnQuota: { total: 250, used: 50 },
        dedicatedResourcePackages: [
          { id: "later", name: "Later credits", total: 80, used: 10, expiresAt: 1793289599000 },
          { id: "earlier", name: "Earlier credits", total: 60, used: 5, expiresAt: 1793203199000 },
        ],
      },
    }), (_key, def) => def ?? _key);
    const addOn = groups.find((group) => group.key === "activity");
    assert.equal(addOn?.total, 250);
    assert.equal(addOn?.items.length, 0);
    const dedicated = groups.find((group) => group.key === "extra");
    assert.ok(dedicated);
    assert.equal(dedicated.total, 140);
    assert.equal(dedicated.used, 15);
    assert.equal(dedicated.items[0].packageName, "Earlier credits");
    assert.equal(dedicated.items[0].expireAt, 1793203199000);
    assert.equal(dedicated.items[1].packageName, "Later credits");
    assert.equal(dedicated.items[0].cycleStartTime, null);
  }
});

test("invalid dedicated packages do not become guessed gift records", () => {
  const groups = getQoderQuotaCategoryGroups(makeAccount({
    auth_credit_usage_raw: {
      addOnQuota: { total: 250, used: 50 },
      dedicatedResourcePackages: [{ name: "Missing identity", total: 100 }, { id: "bad", total: -10 }],
    },
  }), (_key, def) => def ?? _key);
  assert.equal(groups.some((group) => group.key === "extra"), false);
  assert.equal(groups.find((group) => group.key === "activity")?.total, 250);
});

test("aggregate addOnQuota does not invent gift packages or expiry dates", () => {
  const dummyT = (_key: string, def?: string) => def ?? _key;
  const account = makeAccount({
    email: "test@qoder.com",
    auth_credit_usage_raw: {
      userQuota: { total: 0, used: 0, remaining: 0 },
      addOnQuota: { total: 700, used: 0, remaining: 700 },
      expiresAt: 1791041092084,
    },
  });

  const groups = getQoderQuotaCategoryGroups(account, dummyT);
  const baseGroup = groups.find((g) => g.key === "base");
  assert.ok(baseGroup);
  assert.equal(baseGroup.total, 0);
  assert.equal(baseGroup.used, 0);
  assert.equal(baseGroup.visible, true);

  const activityGroup = groups.find((g) => g.key === "activity");
  assert.ok(activityGroup);
  assert.equal(activityGroup.total, 700);
  assert.equal(activityGroup.used, 0);
  assert.equal(activityGroup.visible, true);
  assert.equal(activityGroup.remain, 700);
  assert.equal(activityGroup.items.length, 0);
});

test("shared organization credits keep their used amount without inventing a total", () => {
  for (const used of [0, 42]) {
    const account = makeAccount({
      auth_user_plan_raw: { orgResourcePackage: { used } },
    });
    assert.equal(hasQoderQuotaData(account), true);
    const groups = getQoderQuotaCategoryGroups(account, (_key, def) => def ?? _key);
    const shared = groups.find((group) => group.label === "Shared Credit Package");
    assert.ok(shared);
    assert.equal(shared.used, used);
    assert.equal(shared.visible, true);
    assert.equal(shared.usageOnly, true);
    assert.equal(shared.remainPercent, null);
    assert.equal(shared.items.length, 0);
  }
});

test("missing shared organization usage does not display a guessed zero", () => {
  const groups = getQoderQuotaCategoryGroups(makeAccount({
    auth_credit_usage_raw: { orgResourcePackage: {} },
  }), (_key, def) => def ?? _key);
  assert.equal(groups.some((group) => group.usageOnly), false);
});

test("a newer successful usage query takes precedence over an older web quota snapshot", () => {
  const account = makeAccount({
    usage_updated_at: 1790684490,
    web_quota_updated_at: 1790684488,
    web_quota_raw: {
      account_quota: { limit_value: 300, used_value: 10 },
      resource_package_quota: { limit_value: 700, used_value: 0 },
    },
    auth_credit_usage_raw: {
      userQuota: { total: 300, used: 50, remaining: 250 },
      addOnQuota: { total: 700, used: 100, remaining: 600 },
    },
  });
  const groups = getQoderQuotaCategoryGroups(account, (_key, def) => def ?? _key);
  assert.equal(groups[0].used, 50);
  assert.equal(groups[1].used, 100);
  const freshWeb = getQoderQuotaCategoryGroups({
    ...account,
    web_quota_updated_at: 1790684491,
  }, (_key, def) => def ?? _key);
  assert.equal(freshWeb[0].used, 10);
  assert.equal(freshWeb[1].used, 0);
});

test("incomplete website details use the official summary without making up 100 credits", () => {
  const groups = getQoderQuotaCategoryGroups(makeAccount({
    web_quota_raw: {
      resource_package_quota: {
        quota_summary: { limit_value: 250, used_value: 30 },
        quota_detail: [{ name: "Unspecified package" }],
      },
    },
  }), (_key, def) => def ?? _key);
  assert.equal(groups[1].total, 250);
  assert.equal(groups[1].used, 30);
  assert.equal(groups[1].items.length, 0);
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
