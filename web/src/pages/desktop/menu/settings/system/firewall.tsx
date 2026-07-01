import { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Divider, Modal, Segmented, Spin, Tag, message } from 'antd';
import { LockKeyholeIcon, RefreshCwIcon, ShieldIcon, ShieldOffIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as api from '@/api/system-firewall.ts';
import type { FirewallMode, FirewallStatus } from '@/api/system-firewall.ts';

type RulesTab = 'ipv4' | 'ipv6' | 'nft';

export const FirewallSettings = () => {
  const { t } = useTranslation();

  const [status, setStatus] = useState<FirewallStatus | null>(null);
  const [rulesTab, setRulesTab] = useState<RulesTab>('ipv4');
  const [isLoading, setIsLoading] = useState(false);
  const [isApplying, setIsApplying] = useState(false);

  const selectedRules = useMemo(() => {
    if (!status) return '';
    return status.rules[rulesTab] || t('settings.system.firewall.rules.empty');
  }, [status, rulesTab, t]);
  const isParanoidMode =
    status?.paranoidActive || status?.effectiveMode === 'paranoid' || status?.config.mode === 'paranoid';

  useEffect(() => {
    load();
  }, []);

  async function load() {
    setIsLoading(true);
    try {
      const rsp = await api.getStatus();
      if (rsp.code !== 0 || !rsp.data) {
        message.error(rsp.msg || t('settings.system.firewall.loadFailed'));
        return;
      }
      setStatus(rsp.data);
    } catch (err) {
      console.log(err);
      message.error(t('settings.system.firewall.loadFailed'));
    } finally {
      setIsLoading(false);
    }
  }

  function requestMode(mode: FirewallMode) {
    if (mode === 'paranoid') {
      if (!status?.httpsEnabled) {
        message.warning(t('settings.system.firewall.enableHttpsFirst'));
        return;
      }

      Modal.confirm({
        title: t('settings.system.firewall.paranoid.confirmTitle'),
        content: t('settings.system.firewall.paranoid.confirmDesc'),
        okText: t('settings.system.firewall.paranoid.enable'),
        cancelText: t('settings.system.firewall.cancel'),
        onOk: () => applyMode(mode)
      });
      return;
    }

    Modal.confirm({
      title: t('settings.system.firewall.baseline.confirmTitle'),
      content: t('settings.system.firewall.baseline.confirmDesc'),
      okText: t('settings.system.firewall.baseline.apply'),
      cancelText: t('settings.system.firewall.cancel'),
      onOk: () => applyMode(mode)
    });
  }

  async function applyMode(mode: FirewallMode) {
    setIsApplying(true);
    try {
      const rsp = await api.setMode(mode);
      if (rsp.code !== 0 || !rsp.data) {
        message.error(rsp.msg || t('settings.system.firewall.saveFailed'));
        return;
      }

      let nextStatus: FirewallStatus = rsp.data;
      if (nextStatus.confirmationRequired) {
        const confirmRsp = await api.confirmPending();
        if (confirmRsp.code === 0 && confirmRsp.data) {
          nextStatus = confirmRsp.data;
        }
      }

      setStatus(nextStatus);
      message.success(t('settings.system.firewall.saved'));
    } catch (err) {
      console.log(err);
      message.error(t('settings.system.firewall.saveFailed'));
    } finally {
      setIsApplying(false);
      load();
    }
  }

  if (isLoading && !status) {
    return (
      <div className="flex justify-center py-12">
        <Spin />
      </div>
    );
  }

  return (
    <div className="flex flex-col space-y-6">
      {!status?.httpsEnabled && (
        <Alert
          type="warning"
          showIcon
          message={t('settings.system.firewall.httpsRequired')}
        />
      )}

      {isParanoidMode && (
        <Alert
          type="error"
          showIcon
          message={t('settings.system.firewall.paranoid.active')}
          description={t('settings.system.firewall.paranoid.blocks')}
          action={
            <Button
              danger
              size="small"
              loading={isApplying}
              icon={<ShieldOffIcon size={14} />}
              onClick={() => requestMode('baseline')}
            >
              {t('settings.system.firewall.baseline.apply')}
            </Button>
          }
        />
      )}

      <div className="space-y-3 rounded-lg bg-neutral-800/50 p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="font-semibold text-neutral-100">
              {t('settings.system.firewall.mode.title')}
            </div>
            <div className="text-xs leading-snug text-neutral-500">
              {t('settings.system.firewall.mode.description')}
            </div>
          </div>
          <Tag color={isParanoidMode ? 'red' : 'blue'}>
            {isParanoidMode
              ? t('settings.system.firewall.mode.paranoid')
              : t('settings.system.firewall.mode.baseline')}
          </Tag>
        </div>

        <div className="grid grid-cols-2 gap-3 text-xs text-neutral-400">
          <StatusLine
            label={t('settings.system.firewall.backend')}
            value={status?.backend.preferred || '-'}
          />
          <StatusLine
            label="HTTPS"
            value={
              status?.httpsEnabled
                ? t('settings.system.firewall.enabledPort', { port: status.httpsPort })
                : t('settings.system.firewall.disabled')
            }
          />
          <StatusLine
            label="iptables"
            value={toolText(status?.backend.iptables)}
          />
          <StatusLine
            label="ip6tables"
            value={toolText(status?.backend.ip6tables)}
          />
          <StatusLine label="nft" value={toolText(status?.backend.nft)} />
          <StatusLine
            label={t('settings.system.firewall.effectiveMode')}
            value={status?.effectiveMode || '-'}
          />
        </div>

        <div className="flex flex-wrap justify-end gap-2 pt-2">
          <Button icon={<RefreshCwIcon size={16} />} loading={isLoading} onClick={load}>
            {t('settings.system.firewall.refresh')}
          </Button>
          <Button
            type={isParanoidMode ? 'primary' : 'default'}
            danger={isParanoidMode}
            icon={<ShieldOffIcon size={16} />}
            disabled={!isParanoidMode}
            loading={isApplying}
            onClick={() => requestMode('baseline')}
          >
            {t('settings.system.firewall.baseline.apply')}
          </Button>
          <Button
            type={!isParanoidMode ? 'primary' : 'default'}
            danger
            icon={<LockKeyholeIcon size={16} />}
            disabled={isParanoidMode || !status?.httpsEnabled}
            loading={isApplying}
            onClick={() => requestMode('paranoid')}
          >
            {t('settings.system.firewall.paranoid.enable')}
          </Button>
        </div>
      </div>

      <Divider className="opacity-50" />

      <div className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-base">
            <ShieldIcon size={16} />
            <span>{t('settings.system.firewall.rules.title')}</span>
          </div>
          <Segmented
            size="small"
            value={rulesTab}
            options={[
              { value: 'ipv4', label: 'IPv4' },
              { value: 'ipv6', label: 'IPv6' },
              { value: 'nft', label: 'nft' }
            ]}
            onChange={(value) => setRulesTab(value as RulesTab)}
          />
        </div>
        <pre className="min-h-[260px] max-h-[360px] overflow-auto rounded bg-black/50 p-3 font-mono text-xs leading-relaxed text-neutral-200">
          {selectedRules}
        </pre>
      </div>
    </div>
  );
};

function StatusLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex min-w-0 justify-between gap-3">
      <span>{label}</span>
      <span className="truncate text-right text-neutral-200">{value}</span>
    </div>
  );
}

function toolText(tool?: { installed: boolean; detail: string }) {
  if (!tool) return '-';
  return tool.installed ? tool.detail : 'missing';
}
