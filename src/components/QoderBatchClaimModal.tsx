import { useState, useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { Gift, X, Check, RotateCw, AlertCircle } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import {
  QoderAccount,
  getQoderAccountVariantId,
  getQoderAccountDisplayEmail,
  resolveQoderRewardStatus,
} from '../types/qoder';
import * as qoderService from '../services/qoderService';
import { useModalScrollLock } from '../hooks/useModalScrollLock';
import { useEscCloseTopmost } from '../hooks/useEscClose';
import { useQoderRewardClock } from '../hooks/useQoderRewardClock';
import './QoderBatchClaimModal.css';

interface QoderBatchClaimModalProps {
  accounts: QoderAccount[];
  onClose: () => void;
  onFinished: () => Promise<void>;
  maskAccountText: (text: string) => string;
}

type ClaimStatus = 'pending' | 'running' | 'success' | 'already' | 'failed';

interface AccountClaimState {
  status: ClaimStatus;
  amount?: number;
  message?: string;
}

export function QoderBatchClaimModal({
  accounts,
  onClose,
  onFinished,
  maskAccountText,
}: QoderBatchClaimModalProps) {
  const { t } = useTranslation();
  const rewardNow = useQoderRewardClock(accounts);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => {
    const unclaimeds = accounts.filter((a) => resolveQoderRewardStatus(a) !== 'claimed');
    const defaults = unclaimeds.length > 0 ? unclaimeds : accounts;
    return new Set(defaults.map((a) => a.id));
  });
  const [running, setRunning] = useState(false);
  const [currentClaimingId, setCurrentClaimingId] = useState<string | null>(null);
  const [claimStates, setClaimStates] = useState<Record<string, AccountClaimState>>({});
  const [summary, setSummary] = useState<{ success: number; already: number; failed: number; pending: number } | null>(null);
  const [stopRequested, setStopRequested] = useState(false);
  const [settings, setSettings] = useState<qoderService.QoderAutoCheckinSettings | null>(null);
  const [autoEnabled, setAutoEnabled] = useState(false);
  const [dailyTime, setDailyTime] = useState('10:05');
  const [intervalSeconds, setIntervalSeconds] = useState('3');
  const [savingSettings, setSavingSettings] = useState(false);
  const [settingsError, setSettingsError] = useState<string | null>(null);
  const [settingsSaved, setSettingsSaved] = useState(false);
  const [settingsLoadVersion, setSettingsLoadVersion] = useState(0);

  const mountedRef = useRef(true);
  const runningRef = useRef(false);
  const stopRequestedRef = useRef(false);
  const batchIdRef = useRef<string | null>(null);
  const accountsOnOpenRef = useRef(accounts);

  useModalScrollLock(true);
  useEscCloseTopmost(true, () => {
    if (!running && !savingSettings) {
      onClose();
    }
  });

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      stopRequestedRef.current = true;
      if (batchIdRef.current) {
        void qoderService.cancelQoderRewardBatch(batchIdRef.current).catch((error) => {
          console.error('取消签到任务失败:', error);
        });
      }
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    void qoderService.getQoderAutoCheckinSettings().then((saved) => {
      if (disposed) return;
      setSettings(saved);
      setAutoEnabled(saved.enabled);
      setDailyTime(saved.time);
      setIntervalSeconds(String(saved.requestIntervalSeconds));
      if (saved.enabled) {
        setSelectedIds(new Set(accountsOnOpenRef.current.filter((account) => saved.accountIds.includes(account.id)).map((account) => account.id)));
      }
    }).catch((error) => {
      if (!disposed) setSettingsError(String(error));
    });
    return () => { disposed = true; };
  }, [settingsLoadVersion]);

  const settingsValid = /^([01]\d|2[0-3]):[0-5]\d$/.test(dailyTime)
    && /^\d+$/.test(intervalSeconds) && Number(intervalSeconds) <= 300;

  const saveSettings = async () => {
    if (!settings || !settingsValid) return null;
    setSavingSettings(true);
    setSettingsSaved(false);
    setSettingsError(null);
    // Only replace selection in this dialog's visible scope; keep the other region/filter.
    const visibleIds = new Set(accounts.map((account) => account.id));
    const accountIds = [...settings.accountIds.filter((id) => !visibleIds.has(id)), ...selectedIds];
    try {
      const saved = await qoderService.saveQoderAutoCheckinSettings({
        enabled: autoEnabled, time: dailyTime,
        requestIntervalSeconds: Number(intervalSeconds), accountIds,
      });
      if (mountedRef.current) {
        setSettings(saved);
        setSettingsSaved(true);
      }
      return saved;
    } catch (error) {
      if (mountedRef.current) setSettingsError(String(error));
      return null;
    } finally {
      if (mountedRef.current) setSavingSettings(false);
    }
  };

  const allSelected = accounts.length > 0 && selectedIds.size === accounts.length;
  const isIndeterminate = selectedIds.size > 0 && selectedIds.size < accounts.length;

  const handleToggleSelectAll = () => {
    if (running || savingSettings || !settings) return;
    setSettingsSaved(false);
    if (allSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(accounts.map((a) => a.id)));
    }
  };

  const handleToggleAccount = (id: string) => {
    if (running || savingSettings || !settings) return;
    setSettingsSaved(false);
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const handleStartBatchClaim = async () => {
    if (runningRef.current || savingSettings || !settings || !settingsValid || selectedIds.size === 0) return;
    runningRef.current = true;
    stopRequestedRef.current = false;
    setStopRequested(false);
    setRunning(true);
    setSummary(null);

    // Saving and the backend queue share the authoritative interval. An unsaved field
    // must not appear to control a request that still uses an older backend setting.
    const saved = await saveSettings();
    if (!saved || !mountedRef.current || stopRequestedRef.current) {
      runningRef.current = false;
      if (mountedRef.current) setRunning(false);
      return;
    }

    const targetAccounts = accounts.filter((a) => selectedIds.has(a.id));
    const initStates: Record<string, AccountClaimState> = {};
    for (const a of targetAccounts) {
      initStates[a.id] = { status: 'pending' };
    }
    setClaimStates(initStates);

    let successCount = 0;
    let alreadyCount = 0;
    let failedCount = 0;
    let completedCount = 0;

    let batchId: string | null = null;
    try {
      batchId = await qoderService.startQoderRewardBatch();
      batchIdRef.current = batchId;
      for (const account of targetAccounts) {
        if (!mountedRef.current || stopRequestedRef.current) break;

        setCurrentClaimingId(account.id);
        setClaimStates((prev) => ({
          ...prev,
          [account.id]: { status: 'running' },
        }));

        try {
          const result = await qoderService.claimQoderBatchReward(account.id, batchId);
          if (!mountedRef.current) break;
          if (result === null) {
            setClaimStates((prev) => ({ ...prev, [account.id]: { status: 'pending' } }));
            break;
          }
          completedCount++;

          if (result.success && !result.replayed) {
            successCount++;
            setClaimStates((prev) => ({
              ...prev,
              [account.id]: {
                status: 'success',
                amount: result.amount,
                message: result.message,
              },
            }));
          } else if (result.success && result.replayed) {
            alreadyCount++;
            setClaimStates((prev) => ({
              ...prev,
              [account.id]: {
                status: 'already',
                amount: result.amount,
                message: result.message,
              },
            }));
          } else {
            failedCount++;
            setClaimStates((prev) => ({
              ...prev,
              [account.id]: {
                status: 'failed',
                message: result.message || t('qoder.claimReward.statusFailed', '失败'),
              },
            }));
          }
        } catch (err) {
          if (!mountedRef.current) break;
          completedCount++;
          failedCount++;
          setClaimStates((prev) => ({
            ...prev,
            [account.id]: {
              status: 'failed',
              message: String(err),
            },
          }));
        }
      }
    } catch (error) {
      if (mountedRef.current) setSettingsError(String(error));
    } finally {
      if (batchId) {
        try {
          await qoderService.cancelQoderRewardBatch(batchId);
        } catch (error) {
          if (mountedRef.current) setSettingsError(String(error));
        }
      }
      batchIdRef.current = null;
      runningRef.current = false;
    }

    if (mountedRef.current) {
      // 队列已结束，列表同步不应继续锁住关闭入口。
      setRunning(false);
      setCurrentClaimingId(null);
      setSummary({ success: successCount, already: alreadyCount, failed: failedCount, pending: targetAccounts.length - completedCount });
      try {
        await onFinished();
      } catch (err) {
        console.error('刷新账号列表失败:', err);
      }
    }
  };

  const handleStopBatchClaim = () => {
    stopRequestedRef.current = true;
    setStopRequested(true);
    if (batchIdRef.current) {
      void qoderService.cancelQoderRewardBatch(batchIdRef.current).catch((error) => {
        if (mountedRef.current) {
          setSettingsError(String(error));
          setStopRequested(false);
        }
      });
    }
  };

  return createPortal(
    <div className="qoder-batch-claim-overlay" onClick={running || savingSettings ? undefined : onClose}>
      <div className="qoder-batch-claim-modal" role="dialog" aria-modal="true" aria-labelledby="qoder-batch-claim-title" onClick={(e) => e.stopPropagation()}>
        <div className="qoder-batch-claim-header">
          <div className="qoder-batch-claim-heading">
            <div className="qoder-batch-claim-icon">
              <Gift size={20} />
            </div>
            <h2 id="qoder-batch-claim-title">{t('qoder.claimReward.modalTitle', '一键领取每日 100 积分')}</h2>
          </div>
          <button
            className="modal-close"
            onClick={onClose}
            disabled={running || savingSettings}
            aria-label={t('common.close', '关闭')}
          >
            <X size={16} />
          </button>
        </div>

        <div className="qoder-batch-claim-body">
          <p className="qoder-batch-claim-desc">
            {t(
              'qoder.claimReward.modalDesc',
              '可勾选需要领取的 Qoder 账号，一键领取每日 100 积分福利（活动每天 10:00 刷新）。领取完成后会自动同步最新配额。'
            )}
          </p>

          <fieldset className="qoder-batch-claim-settings" disabled={running || savingSettings || !settings}>
            <legend>{t('qoder.claimReward.scheduleTitle', '签到设置')}</legend>
            <label className="qoder-batch-claim-auto-toggle">
              <input type="checkbox" checked={autoEnabled} onChange={(event) => {
                setAutoEnabled(event.target.checked); setSettingsSaved(false);
              }} />
              {t('qoder.claimReward.autoEnabled', '每天自动签到')}
            </label>
            <div className="qoder-batch-claim-setting-fields">
              <label>
                <span>{t('qoder.claimReward.dailyTime', '每日签到时间（本机时间）')}</span>
                <input type="time" value={dailyTime} disabled={!autoEnabled} onChange={(event) => {
                  setDailyTime(event.target.value); setSettingsSaved(false);
                }} />
              </label>
              <label>
                <span>{t('qoder.claimReward.requestInterval', '账号请求间隔（秒）')}</span>
                <input type="number" min="0" max="300" step="1" value={intervalSeconds} onChange={(event) => {
                  setIntervalSeconds(event.target.value); setSettingsSaved(false);
                }} />
              </label>
            </div>
            <p className="qoder-batch-claim-settings-hint">
              {t('qoder.claimReward.runningRequired', '需保持 Cockpit 运行；关闭此弹窗不影响自动签到。错过时间后，当天再次启动会补执行。')}
            </p>
            <p className="qoder-batch-claim-settings-hint">
              {t('qoder.claimReward.intervalHint', '上一个账号请求结束后，再等待设定秒数处理下一个；手动和自动签到共用。每天每个账号自动尝试一次，失败可手动重试。')}
            </p>
            <div className="qoder-batch-claim-settings-actions">
              <span className="qoder-batch-claim-settings-hint">
                {t('qoder.claimReward.selectionHint', '保存当前勾选账号用于自动签到，保留其他地区及筛选外的已选账号。一键领取也会保存设置。')}
              </span>
              <button className="btn btn-secondary" type="button" disabled={!settingsValid}
                onClick={() => { void saveSettings(); }}>
                {savingSettings ? t('common.saving', '保存中...') : t('qoder.claimReward.saveSettings', '保存设置')}
              </button>
            </div>
          </fieldset>
          {!settingsValid && settings && <p className="qoder-batch-claim-settings-error" role="alert">
            {t('qoder.claimReward.invalidSettings', '请选择有效时间，间隔须为 0–300 的整数秒。')}
          </p>}
          {!settings && !settingsError && <p className="qoder-batch-claim-settings-hint" role="status">
            {t('qoder.claimReward.loadingSettings', '正在读取签到设置...')}
          </p>}
          {settingsError && <div className="qoder-batch-claim-settings-actions">
            <p className="qoder-batch-claim-settings-error" role="alert">{settingsError}</p>
            {!settings && <button className="btn btn-secondary" type="button" onClick={() => {
              setSettingsError(null); setSettingsLoadVersion((version) => version + 1);
            }}>{t('common.retry', '重试')}</button>}
          </div>}
          {settingsSaved && settings && <p className="qoder-batch-claim-settings-hint" role="status">
            {settings.enabled
              ? t('qoder.claimReward.scheduleSaved', '已保存：每天 {{time}} 为 {{count}} 个账号自动签到，间隔 {{seconds}} 秒。', {
                time: settings.time, count: settings.accountIds.length, seconds: settings.requestIntervalSeconds,
              })
              : t('qoder.claimReward.scheduleDisabled', '已保存请求间隔，自动签到已关闭。')}
          </p>}

          <div className="qoder-batch-claim-toolbar">
            <label className="qoder-batch-claim-select-all">
              <input
                type="checkbox"
                checked={allSelected}
                ref={(el) => {
                  if (el) el.indeterminate = isIndeterminate;
                }}
                onChange={handleToggleSelectAll}
                disabled={running || savingSettings || !settings || accounts.length === 0}
              />
              <span>
                {t('qoder.claimReward.selectAll', '全选')} (
                {t('qoder.claimReward.selectedCount', '已选 {{selected}} / {{total}} 个账号', {
                  selected: selectedIds.size,
                  total: accounts.length,
                })}
                )
              </span>
            </label>
            {running && currentClaimingId && (
              <span className="qoder-batch-claim-active-label">
                <RotateCw size={12} className="loading-spinner" />
                {t('qoder.claimReward.claiming', '领取中...')}
              </span>
            )}
          </div>

          <ul className="qoder-batch-claim-list">
            {accounts.map((account) => {
              const isSelected = selectedIds.has(account.id);
              const state = claimStates[account.id];
              const variantId = getQoderAccountVariantId(account);
              const variantLabel = variantId.startsWith('qoder_cn_') ? 'Qoder CN' : 'Qoder';
              const displayEmail = maskAccountText(getQoderAccountDisplayEmail(account));

              return (
                <li
                  key={account.id}
                  className="qoder-batch-claim-row"
                  onClick={() => handleToggleAccount(account.id)}
                  style={{ cursor: running ? 'default' : 'pointer' }}
                >
                  <div className="qoder-batch-claim-account-info">
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => handleToggleAccount(account.id)}
                      disabled={running || savingSettings || !settings}
                      aria-label={displayEmail}
                      onClick={(e) => e.stopPropagation()}
                    />
                    <div className="qoder-batch-claim-meta">
                      <div className="qoder-batch-claim-email-line">
                        <span className="qoder-batch-claim-email" title={displayEmail}>
                          {displayEmail}
                        </span>
                        <span className="qoder-batch-claim-badge">{variantLabel}</span>
                      </div>
                      <span className="qoder-batch-claim-quota">
                        {t('qoder.usageOverview.includedCredits', '额度')}:{' '}
                        {account.credits_remaining !== undefined && account.credits_remaining !== null
                          ? `${account.credits_remaining} / ${account.credits_total ?? '--'}`
                          : '-- / --'}
                      </span>
                    </div>
                  </div>

                  <div className="qoder-batch-claim-status-area">
                    {state?.status === 'running' && (
                      <span className="qoder-batch-claim-status running">
                        <RotateCw size={12} className="loading-spinner" />
                        {t('qoder.claimReward.claiming', '领取中...')}
                      </span>
                    )}
                    {state?.status === 'success' && (
                      <span className="qoder-batch-claim-status success">
                        <Check size={13} />
                        {state.amount == null ? t('common.success', '成功') : `+${state.amount}`}
                      </span>
                    )}
                    {state?.status === 'already' && (
                      <span className="qoder-batch-claim-status already">
                        <Check size={13} />
                        {t('qoder.claimReward.statusAlreadyClaimed', '今日已领')}
                      </span>
                    )}
                    {state?.status === 'failed' && (
                      <span className="qoder-batch-claim-status failed" title={state.message}>
                        <AlertCircle size={13} />
                        {t('qoder.claimReward.statusFailed', '失败')}
                      </span>
                    )}
                    {(!state || state.status === 'pending') && (() => {
                      const rewardStatus = resolveQoderRewardStatus(account, rewardNow);
                      if (rewardStatus === 'claimed') {
                        return (
                          <span className="qoder-batch-claim-status already">
                            <Gift size={12} />
                            {t('qoder.claimReward.statusAlreadyClaimed', '今日已领')}
                          </span>
                        );
                      }
                      if (rewardStatus === 'claimable') {
                        return (
                          <span className="qoder-batch-claim-status claimable">
                            <Gift size={12} />
                            {t('qoder.claimReward.badgeClaimable', '可领100')}
                          </span>
                        );
                      }
                      if (rewardStatus === 'none') {
                        return (
                          <span className="qoder-batch-claim-status none">
                            <Gift size={12} />
                            {t('qoder.claimReward.statusNone', '无活动')}
                          </span>
                        );
                      }
                      return (
                        <span className="qoder-batch-claim-status pending">
                          {t('qoder.claimReward.statusPending', '待领取')}
                        </span>
                      );
                    })()}
                  </div>
                </li>
              );
            })}
          </ul>
        </div>

        <div className="qoder-batch-claim-footer">
          <div className="qoder-batch-claim-summary">
            {summary && (
              <span>
                {t('qoder.claimReward.batchFinishedSummary', '完成：{{success}} 成功，{{already}} 已领，{{failed}} 失败', {
                  success: summary.success,
                  already: summary.already,
                  failed: summary.failed,
                })}
                {summary.pending > 0 && ` · ${summary.pending} ${t('qoder.claimReward.statusPending', '待领取')}`}
              </span>
            )}
          </div>
          <div className="qoder-batch-claim-footer-btns">
            <button
              className="btn btn-secondary"
              onClick={running ? handleStopBatchClaim : onClose}
              disabled={savingSettings || (running && stopRequested)}
            >
              {running ? t('common.stop', '停止') : summary ? t('common.close', '关闭') : t('common.cancel', '取消')}
            </button>
            <button
              className="btn btn-primary"
              onClick={handleStartBatchClaim}
              disabled={running || savingSettings || !settings || !settingsValid || selectedIds.size === 0}
            >
              {running ? (
                <>
                  <RotateCw size={14} className="loading-spinner" />
                  {t('qoder.claimReward.claiming', '领取中...')}
                </>
              ) : (
                <>
                  <Gift size={14} />
                  {summary
                    ? t('qoder.claimReward.reclaim', '重新领取')
                    : `${t('qoder.claimReward.startClaim', '一键领取')} (${selectedIds.size})`}
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body
  );
}
