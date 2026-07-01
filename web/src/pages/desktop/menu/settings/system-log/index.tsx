import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Alert, Button, Divider, Input, InputNumber, Select, Switch, message } from 'antd';
import { RefreshCwIcon, SaveIcon, SendIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as api from '@/api/system-log.ts';
import type { SystemLogConfig } from '@/api/system-log.ts';

const defaultConfig: SystemLogConfig = {
  remoteEnabled: false,
  remoteHost: '',
  remotePort: 514,
  priority: 8,
  bufferKb: 200,
  rotations: 1,
  smallOutput: false,
  stripTimestamps: false,
  kernelEnabled: true,
  kernelConsoleLevel: 7
};

export const SystemLog = ({ showTitle = true }: { showTitle?: boolean }) => {
  const { t } = useTranslation();

  const [config, setConfig] = useState<SystemLogConfig>(defaultConfig);
  const [localLogFile, setLocalLogFile] = useState('/tmp/hardened-syslog/messages');
  const [lineCount, setLineCount] = useState(200);
  const [content, setContent] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [isLogLoading, setIsLogLoading] = useState(false);
  const [isTesting, setIsTesting] = useState(false);
  const [logTruncated, setLogTruncated] = useState(false);

  const priorityOptions = useMemo(
    () =>
      [8, 7, 6, 5, 4, 3, 2, 1].map((level) => ({
        value: level,
        label: t(`settings.systemLog.level.${level}`)
      })),
    [t]
  );

  useEffect(() => {
    loadConfig();
    refreshLog(200);
  }, []);

  function patchConfig(patch: Partial<SystemLogConfig>) {
    setConfig((current) => ({ ...current, ...patch }));
  }

  async function loadConfig() {
    setIsLoading(true);
    try {
      const rsp = await api.getConfig();
      if (rsp.code !== 0 || !rsp.data) {
        message.error(rsp.msg || t('settings.systemLog.loadFailed'));
        return;
      }

      setConfig({ ...defaultConfig, ...rsp.data.config });
      setLocalLogFile(rsp.data.localLogFile || defaultConfigPath());
    } catch (err) {
      console.log(err);
      message.error(t('settings.systemLog.loadFailed'));
    } finally {
      setIsLoading(false);
    }
  }

  async function save() {
    if (isSaving) return;
    if (config.remoteEnabled && !config.remoteHost.trim()) {
      message.error(t('settings.systemLog.invalidHost'));
      return;
    }

    setIsSaving(true);
    try {
      const rsp = await api.setConfig({
        ...config,
        remoteHost: config.remoteHost.trim()
      });
      if (rsp.code !== 0) {
        message.error(rsp.msg || t('settings.systemLog.saveFailed'));
        return;
      }

      message.success(t('settings.systemLog.saved'));
      if (rsp.data?.config) setConfig({ ...defaultConfig, ...rsp.data.config });
      refreshLog(lineCount);
    } catch (err) {
      console.log(err);
      message.error(t('settings.systemLog.saveFailed'));
    } finally {
      setIsSaving(false);
    }
  }

  async function refreshLog(lines = lineCount) {
    setIsLogLoading(true);
    try {
      const rsp = await api.getMessages('system', lines);
      if (rsp.code !== 0 || !rsp.data) {
        message.error(rsp.msg || t('settings.systemLog.logLoadFailed'));
        return;
      }

      setContent(rsp.data.content || '');
      setLogTruncated(Boolean(rsp.data.truncated));
    } catch (err) {
      console.log(err);
      message.error(t('settings.systemLog.logLoadFailed'));
    } finally {
      setIsLogLoading(false);
    }
  }

  async function sendTestMessage() {
    if (isTesting) return;

    setIsTesting(true);
    try {
      const rsp = await api.sendTestMessage();
      if (rsp.code !== 0) {
        message.error(rsp.msg || t('settings.systemLog.testFailed'));
        return;
      }

      message.success(t('settings.systemLog.testSent'));
      refreshLog(lineCount);
    } catch (err) {
      console.log(err);
      message.error(t('settings.systemLog.testFailed'));
    } finally {
      setIsTesting(false);
    }
  }

  function changeLineCount(value: number) {
    setLineCount(value);
    refreshLog(value);
  }

  return (
    <>
      {showTitle && (
        <>
          <div className="text-base">{t('settings.systemLog.title')}</div>
          <Divider className="opacity-50" />
        </>
      )}

      <div className="flex flex-col space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div className="flex flex-col space-y-1">
            <span>{t('settings.systemLog.remote.title')}</span>
            <span className="text-xs text-neutral-500">
              {t('settings.systemLog.remote.description')}
            </span>
          </div>
          <Switch
            checked={config.remoteEnabled}
            loading={isLoading}
            onChange={(remoteEnabled) => patchConfig({ remoteEnabled })}
          />
        </div>

        {config.remoteEnabled && (
          <div className="space-y-3 rounded-xl bg-neutral-800/50 p-4">
            <SettingRow label={t('settings.systemLog.remote.host')}>
              <Input
                value={config.remoteHost}
                placeholder="10.0.87.5"
                onChange={(event) => patchConfig({ remoteHost: event.target.value })}
              />
            </SettingRow>
            <SettingRow label={t('settings.systemLog.remote.port')}>
              <InputNumber<number>
                min={1}
                max={65535}
                value={config.remotePort}
                onChange={(value) => patchConfig({ remotePort: value || 514 })}
                className="w-full"
              />
            </SettingRow>
            <div className="text-xs text-neutral-500">
              {t('settings.systemLog.remote.protocol')}
            </div>
          </div>
        )}

        <div className="space-y-3 rounded-xl bg-neutral-800/50 p-4">
          <div>
            <div className="font-semibold text-neutral-100">
              {t('settings.systemLog.local.title')}
            </div>
            <div className="mt-0.5 text-xs leading-snug text-neutral-500">
              {t('settings.systemLog.local.description', { path: localLogFile })}
            </div>
          </div>
          <SettingRow label={t('settings.systemLog.local.priority')}>
            <Select
              value={config.priority}
              options={priorityOptions}
              onChange={(priority) => patchConfig({ priority })}
              className="w-full"
            />
          </SettingRow>
          <SettingRow label={t('settings.systemLog.local.buffer')}>
            <InputNumber<number>
              min={16}
              max={1024}
              value={config.bufferKb}
              addonAfter="KiB"
              onChange={(value) => patchConfig({ bufferKb: value || 200 })}
              className="w-full"
            />
          </SettingRow>
          <SettingRow label={t('settings.systemLog.local.rotations')}>
            <InputNumber<number>
              min={0}
              max={4}
              value={config.rotations}
              onChange={(value) => patchConfig({ rotations: value || 0 })}
              className="w-full"
            />
          </SettingRow>
          <SettingRow label={t('settings.systemLog.local.compact')}>
            <Switch
              checked={config.smallOutput}
              onChange={(smallOutput) => patchConfig({ smallOutput })}
            />
          </SettingRow>
          <SettingRow label={t('settings.systemLog.local.stripTimestamps')} isLast>
            <Switch
              checked={config.stripTimestamps}
              onChange={(stripTimestamps) => patchConfig({ stripTimestamps })}
            />
          </SettingRow>
        </div>

        <div className="space-y-3 rounded-xl bg-neutral-800/50 p-4">
          <div>
            <div className="font-semibold text-neutral-100">
              {t('settings.systemLog.kernel.title')}
            </div>
            <div className="mt-0.5 text-xs leading-snug text-neutral-500">
              {t('settings.systemLog.kernel.description')}
            </div>
          </div>
          <SettingRow label={t('settings.systemLog.kernel.enabled')}>
            <Switch
              checked={config.kernelEnabled}
              onChange={(kernelEnabled) => patchConfig({ kernelEnabled })}
            />
          </SettingRow>
          <SettingRow label={t('settings.systemLog.kernel.consoleLevel')} isLast>
            <Select
              value={config.kernelConsoleLevel}
              options={priorityOptions}
              onChange={(kernelConsoleLevel) => patchConfig({ kernelConsoleLevel })}
              className="w-full"
            />
          </SettingRow>
        </div>

        <div className="flex justify-end gap-2">
          <Button icon={<SendIcon size={16} />} loading={isTesting} onClick={sendTestMessage}>
            {t('settings.systemLog.test')}
          </Button>
          <Button type="primary" icon={<SaveIcon size={16} />} loading={isSaving} onClick={save}>
            {t('settings.systemLog.save')}
          </Button>
        </div>

        <Divider className="opacity-50" />

        <div className="space-y-3">
          <div className="flex items-center justify-between gap-3">
            <div className="text-base">{t('settings.systemLog.viewer.title')}</div>
            <div className="flex items-center gap-2">
              <Select
                value={lineCount}
                options={[100, 200, 500, 1000].map((value) => ({
                  value,
                  label: t('settings.systemLog.viewer.lines', { count: value })
                }))}
                onChange={changeLineCount}
                className="w-[120px]"
              />
              <Button
                icon={<RefreshCwIcon size={16} />}
                loading={isLogLoading}
                onClick={() => refreshLog()}
              >
                {t('settings.systemLog.viewer.refresh')}
              </Button>
            </div>
          </div>

          {logTruncated && (
            <Alert type="info" showIcon message={t('settings.systemLog.viewer.truncated')} />
          )}

          <pre className="min-h-[260px] max-h-[360px] overflow-auto rounded bg-black/50 p-3 font-mono text-xs leading-relaxed text-neutral-200">
            {content || t('settings.systemLog.viewer.empty')}
          </pre>
        </div>
      </div>
    </>
  );
};

function defaultConfigPath() {
  return '/tmp/hardened-syslog/messages';
}

const SettingRow = ({
  label,
  children,
  isLast = false
}: {
  label: string;
  children: ReactNode;
  isLast?: boolean;
}) => {
  return (
    <div
      className={`flex min-h-[44px] items-center justify-between gap-4 ${
        isLast ? '' : 'border-b border-neutral-700/50 pb-3'
      }`}
    >
      <span className="shrink-0 text-sm text-neutral-300">{label}</span>
      <div className="w-[260px]">{children}</div>
    </div>
  );
};
