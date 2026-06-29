import { useEffect, useState } from 'react';
import {
  CloudSyncOutlined,
  LoadingOutlined,
  RocketOutlined,
  SmileOutlined
} from '@ant-design/icons';
import { Alert, Button, Divider, Modal, Result, Spin } from 'antd';
import { useTranslation } from 'react-i18next';
import semver from 'semver';

import * as api from '@/api/application.ts';
import type {
  SystemBootHealth,
  SystemLatest,
  SystemPendingUpdate,
  SystemRollbackInfo,
  SystemStagedUpdate,
  SystemUpdateProgress,
  SystemVersion
} from '@/api/application.ts';

import { Offline } from './offline.tsx';
import { Preview } from './preview.tsx';

type UpdateProps = {
  setIsLocked: (isClosable: boolean) => void;
};

export const Update = ({ setIsLocked }: UpdateProps) => {
  const { t } = useTranslation();

  const [status, setStatus] = useState('');
  const [currentVersion, setCurrentVersion] = useState('');
  const [latestVersion, setLatestVersion] = useState('');
  const [errMsg, setErrMsg] = useState('');
  const [systemStatus, setSystemStatus] = useState('');
  const [systemCurrent, setSystemCurrent] = useState<SystemVersion | null>(null);
  const [systemLatest, setSystemLatest] = useState<SystemLatest | null>(null);
  const [systemStaged, setSystemStaged] = useState<SystemStagedUpdate | null>(null);
  const [systemPending, setSystemPending] = useState<SystemPendingUpdate | null>(null);
  const [systemBootHealth, setSystemBootHealth] = useState<SystemBootHealth | null>(null);
  const [systemRollback, setSystemRollback] = useState<SystemRollbackInfo | null>(null);
  const [systemProgress, setSystemProgress] = useState<SystemUpdateProgress | null>(null);
  const [systemErrMsg, setSystemErrMsg] = useState('');

  useEffect(() => {
    checkForUpdates();
    checkSystemUpdates();
  }, []);

  function isVersionAtLeast(current: string, latest: string) {
    if (semver.valid(current) && semver.valid(latest)) {
      return semver.gte(current, latest);
    }

    return current === latest;
  }

  function checkForUpdates() {
    if (status === 'loading') return;
    setStatus('loading');

    api
      .getVersion()
      .then((rsp: any) => {
        if (rsp.code !== 0 || !rsp.data) {
          setStatus('failed');
          setErrMsg(t('settings.update.queryFailed'));
          return;
        }

        setCurrentVersion(rsp.data.current);

        if (rsp.data?.latest) {
          setLatestVersion(rsp.data.latest);
          const isLatest = isVersionAtLeast(rsp.data.current, rsp.data.latest);
          setStatus(isLatest ? 'latest' : 'outdated');
        } else {
          setStatus('latest');
        }
      })
      .catch(() => {
        setStatus('failed');
        setErrMsg(t('settings.update.queryFailed'));
      });
  }

  function checkSystemUpdates() {
    if (systemStatus === 'loading') return;
    setSystemStatus('loading');
    setSystemErrMsg('');

    api
      .checkSystemUpdate()
      .then((rsp: any) => {
        if (rsp.code !== 0 || !rsp.data) {
          setSystemStatus('failed');
          setSystemErrMsg(t('settings.update.system.queryFailed'));
          return;
        }

        setSystemCurrent(rsp.data.current);
        setSystemLatest(rsp.data.latest || null);

        if (rsp.data.error) {
          setSystemStatus('failed');
          setSystemErrMsg(t('settings.update.system.queryFailed'));
          return;
        }

        if (rsp.data.latest?.version) {
          const isLatest = isVersionAtLeast(rsp.data.current.version, rsp.data.latest.version);
          setSystemStatus(isLatest ? 'latest' : 'outdated');
        } else {
          setSystemStatus('latest');
        }
      })
      .catch(() => {
        setSystemStatus('failed');
        setSystemErrMsg(t('settings.update.system.queryFailed'));
      })
      .finally(() => {
        refreshSystemUpdateStatus();
      });
  }

  function refreshSystemUpdateStatus() {
    api
      .getSystemUpdateStatus()
      .then((rsp: any) => {
        if (rsp.code !== 0 || !rsp.data) return;
        const progress = rsp.data.progress || null;
        const staged = rsp.data.staged || null;
        const pending = rsp.data.pending || null;

        setSystemCurrent(rsp.data.current);
        setSystemStaged(staged);
        setSystemPending(pending);
        setSystemBootHealth(rsp.data.bootHealth || null);
        setSystemRollback(rsp.data.rollback || null);
        setSystemProgress(progress);

        if (progress?.phase === 'failed') {
          setSystemStatus('failed');
          setSystemErrMsg(progress.message || t('settings.update.system.queryFailed'));
          return;
        }

        if (progress?.operation && progress.phase !== 'done') {
          if (progress.operation === 'download') setSystemStatus('downloading');
          else if (progress.operation === 'install') setSystemStatus('installing');
          else if (progress.operation === 'rollback') setSystemStatus('rollingBack');
          else if (progress.operation === 'confirm') setSystemStatus('confirming');
          return;
        }

        if (pending) {
          setSystemStatus('installed');
          return;
        }

        if (staged) {
          setSystemStatus('staged');
        }
      })
      .catch(() => {
        setSystemStaged(null);
        setSystemPending(null);
        setSystemBootHealth(null);
        setSystemRollback(null);
        setSystemProgress(null);
      });
  }

  function downloadSystemUpdate() {
    if (!systemLatest || systemStatus === 'downloading') return;

    setIsLocked(true);
    setSystemStatus('downloading');
    setSystemErrMsg('');

    api
      .downloadSystemUpdate()
      .then((rsp: any) => {
        if (rsp.code !== 0 || !rsp.data) {
          setSystemStatus('failed');
          setSystemErrMsg(t('settings.update.system.downloadFailed'));
          return;
        }

        setSystemCurrent(rsp.data.current);
        setSystemLatest(rsp.data.latest);
        setSystemStaged(rsp.data.staged);
        setSystemStatus('staged');
      })
      .catch(() => {
        setSystemStatus('failed');
        setSystemErrMsg(t('settings.update.system.downloadFailed'));
      })
      .finally(() => {
        refreshSystemUpdateStatus();
        setIsLocked(false);
      });
  }

  function confirmInstallSystemUpdate() {
    if (!systemStaged || systemStatus === 'installing') return;

    Modal.confirm({
      title: t('settings.update.system.installConfirmTitle'),
      content: systemStaged.destructive ? (
        <div className="space-y-3">
          <div>{t('settings.update.system.rawInstallConfirmDesc')}</div>
          <Alert
            type="error"
            showIcon
            message={t('settings.update.system.rawInstallWarning')}
          />
        </div>
      ) : (
        t('settings.update.system.installConfirmDesc')
      ),
      okText: t('settings.update.system.install'),
      cancelText: t('settings.update.cancel'),
      onOk: installSystemUpdate
    });
  }

  function installSystemUpdate() {
    setIsLocked(true);
    setSystemStatus('installing');
    setSystemErrMsg('');

    return api
      .installSystemUpdate()
      .then((rsp: any) => {
        if (rsp.code !== 0 || !rsp.data) {
          setSystemStatus('failed');
          setSystemErrMsg(t('settings.update.system.installFailed'));
          return;
        }

        setSystemPending(rsp.data.installed);
        setSystemStatus('installed');
        refreshSystemUpdateStatus();
      })
      .catch(() => {
        setSystemStatus('failed');
        setSystemErrMsg(t('settings.update.system.installFailed'));
      })
      .finally(() => {
        refreshSystemUpdateStatus();
        setIsLocked(false);
      });
  }

  function confirmSystemUpdate() {
    if (!systemPending || systemStatus === 'confirming') return;

    setIsLocked(true);
    setSystemStatus('confirming');
    setSystemErrMsg('');

    api
      .confirmSystemUpdate()
      .then((rsp: any) => {
        if (rsp.code !== 0 || !rsp.data) {
          setSystemStatus('failed');
          setSystemErrMsg(t('settings.update.system.confirmFailed'));
          return;
        }

        setSystemPending(null);
        setSystemBootHealth(null);
        setSystemStatus('confirmed');
        refreshSystemUpdateStatus();
      })
      .catch(() => {
        setSystemStatus('failed');
        setSystemErrMsg(t('settings.update.system.confirmFailed'));
      })
      .finally(() => {
        setIsLocked(false);
      });
  }

  function confirmRollbackSystemUpdate() {
    if (!systemRollback || systemStatus === 'rollingBack') return;

    Modal.confirm({
      title: t('settings.update.system.rollbackConfirmTitle'),
      content: t('settings.update.system.rollbackConfirmDesc'),
      okText: t('settings.update.system.rollback'),
      cancelText: t('settings.update.cancel'),
      onOk: rollbackSystemUpdate
    });
  }

  function rollbackSystemUpdate() {
    setIsLocked(true);
    setSystemStatus('rollingBack');
    setSystemErrMsg('');

    return api
      .rollbackSystemUpdate()
      .then((rsp: any) => {
        if (rsp.code !== 0 || !rsp.data) {
          setSystemStatus('failed');
          setSystemErrMsg(t('settings.update.system.rollbackFailed'));
          return;
        }

        setSystemRollback(rsp.data.restored);
        setSystemPending(null);
        setSystemStatus('rolledBack');
        refreshSystemUpdateStatus();
      })
      .catch(() => {
        setSystemStatus('failed');
        setSystemErrMsg(t('settings.update.system.rollbackFailed'));
      })
      .finally(() => {
        refreshSystemUpdateStatus();
        setIsLocked(false);
      });
  }

  function update() {
    if (status !== 'outdated') return;

    setIsLocked(true);
    setStatus('updating');

    api
      .update()
      .then((rsp: any) => {
        if (rsp.code !== 0) {
          setStatus('failed');
          setErrMsg(t('settings.update.updateFailed'));
        }
      })
      .finally(() => {
        setTimeout(() => {
          setIsLocked(false);
          setErrMsg('');

          window.location.reload();
        }, 12000);
      });
  }

  function versionLine(label: string, value?: string) {
    if (!value) return null;

    return (
      <div className="flex justify-between gap-6 text-xs text-neutral-500">
        <span>{label}</span>
        <span className="max-w-[60%] break-words text-right text-neutral-300">{value}</span>
      </div>
    );
  }

  function formatBytes(value?: number) {
    if (!value) return '';
    if (value >= 1024 * 1024) return `${(value / 1024 / 1024).toFixed(1)} MiB`;
    if (value >= 1024) return `${(value / 1024).toFixed(1)} KiB`;
    return `${value} B`;
  }

  return (
    <>
      <div className="text-base">{t('settings.update.title')}</div>
      <Divider className="opacity-50" />

      <Preview checkForUpdates={checkForUpdates} />
      <Offline
        status={status}
        setStatus={setStatus}
        setIsLocked={setIsLocked}
        setErrMsg={setErrMsg}
      />
      <Divider className="opacity-50" />

      <div className="flex min-h-[320px] flex-col justify-between">
        <div className="text-sm text-neutral-300">{t('settings.update.application.title')}</div>
        {status === 'loading' && (
          <div className="flex justify-center pt-24">
            <Spin indicator={<LoadingOutlined spin />} size="large" />
          </div>
        )}

        {status === 'updating' && (
          <div className="flex flex-col items-center justify-center space-y-10 pb-10 pt-24">
            <Spin size="large" />
            <span className="text-neutral-500">{t('settings.update.updating')}</span>
          </div>
        )}

        {status === 'latest' && (
          <Result
            status="success"
            icon={<SmileOutlined />}
            title={currentVersion}
            subTitle={t('settings.update.isLatest')}
            extra={[
              <Button key="confirm" onClick={checkForUpdates}>
                {t('settings.update.title')}
              </Button>
            ]}
          />
        )}

        {status === 'outdated' && (
          <Result
            status="warning"
            icon={<RocketOutlined />}
            title={`${currentVersion} -> ${latestVersion}`}
            subTitle={t('settings.update.available')}
            extra={[
              <Button key="confirm" type="primary" onClick={update}>
                {t('settings.update.confirm')}
              </Button>
            ]}
          />
        )}

        {status === 'failed' && <Result subTitle={errMsg} />}

        <Divider className="opacity-50" />
        <div className="space-y-4">
          <div className="text-sm text-neutral-300">{t('settings.update.system.title')}</div>

          {systemStatus === 'loading' && (
            <div className="flex justify-center py-10">
              <Spin indicator={<LoadingOutlined spin />} />
            </div>
          )}

          {systemStatus === 'downloading' && (
            <div className="flex flex-col items-center justify-center space-y-6 py-10">
              <Spin indicator={<LoadingOutlined spin />} />
              <span className="text-neutral-500">
                {systemProgress?.message || t('settings.update.system.downloading')}
              </span>
            </div>
          )}

          {(systemStatus === 'installing' ||
            systemStatus === 'rollingBack' ||
            systemStatus === 'confirming') && (
            <div className="flex flex-col items-center justify-center space-y-6 py-10">
              <Spin indicator={<LoadingOutlined spin />} />
              <span className="text-neutral-500">
                {systemStatus === 'confirming'
                  ? t('settings.update.system.confirming')
                  : systemStatus === 'installing'
                    ? systemProgress?.message || t('settings.update.system.installing')
                    : t('settings.update.system.rollingBack')}
              </span>
            </div>
          )}

          {systemStatus === 'latest' && systemCurrent && (
            <Result
              status="success"
              icon={<SmileOutlined />}
              title={systemCurrent.version}
              subTitle={t('settings.update.system.isLatest')}
              extra={[
                <Button key="refresh" onClick={checkSystemUpdates}>
                  {t('settings.update.system.refresh')}
                </Button>,
                systemRollback ? (
                  <Button key="rollback" danger onClick={confirmRollbackSystemUpdate}>
                    {t('settings.update.system.rollback')}
                  </Button>
                ) : null
              ]}
            />
          )}

          {systemStatus === 'staged' && systemStaged && (
            <Result
              status="success"
              icon={<CloudSyncOutlined />}
              title={`${systemStaged.version} ${t('settings.update.system.staged')}`}
              subTitle={t('settings.update.system.stagedDesc')}
              extra={[
                systemLatest?.releaseNotesUrl ? (
                  <Button
                    key="release"
                    href={systemLatest.releaseNotesUrl}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {t('settings.update.system.releaseNotes')}
                  </Button>
                ) : null,
                <Button key="refresh" onClick={checkSystemUpdates}>
                  {t('settings.update.system.refresh')}
                </Button>,
                <Button key="install" type="primary" danger onClick={confirmInstallSystemUpdate}>
                  {t('settings.update.system.install')}
                </Button>
              ]}
            />
          )}

          {systemStatus === 'installed' && systemPending && (
            <Result
              status="warning"
              icon={<CloudSyncOutlined />}
              title={`${systemPending.version} ${t('settings.update.system.installed')}`}
              subTitle={t('settings.update.system.rebootRequired')}
              extra={[
                <Button key="refresh" onClick={checkSystemUpdates}>
                  {t('settings.update.system.refresh')}
                </Button>
              ]}
            />
          )}

          {systemStatus === 'rolledBack' && systemRollback && (
            <Result
              status="success"
              icon={<CloudSyncOutlined />}
              title={t('settings.update.system.rollbackDone')}
              subTitle={t('settings.update.system.rebootRequired')}
              extra={[
                <Button key="refresh" onClick={checkSystemUpdates}>
                  {t('settings.update.system.refresh')}
                </Button>
              ]}
            />
          )}

          {systemStatus === 'confirmed' && (
            <Result
              status="success"
              icon={<CloudSyncOutlined />}
              title={t('settings.update.system.confirmed')}
              subTitle={t('settings.update.system.bootGood')}
              extra={[
                <Button key="refresh" onClick={checkSystemUpdates}>
                  {t('settings.update.system.refresh')}
                </Button>
              ]}
            />
          )}

          {systemStatus === 'outdated' && systemCurrent && systemLatest && (
            <Result
              status="warning"
              icon={<CloudSyncOutlined />}
              title={`${systemCurrent.version} -> ${systemLatest.version}`}
              subTitle={t('settings.update.system.available')}
              extra={[
                <Button
                  key="release"
                  href={systemLatest.releaseNotesUrl}
                  target="_blank"
                  rel="noreferrer"
                >
                  {t('settings.update.system.releaseNotes')}
                </Button>,
                <Button key="download" type="primary" onClick={downloadSystemUpdate}>
                  {t('settings.update.system.downloadVerify')}
                </Button>,
                <Button key="refresh" onClick={checkSystemUpdates}>
                  {t('settings.update.system.refresh')}
                </Button>,
                systemRollback ? (
                  <Button key="rollback" danger onClick={confirmRollbackSystemUpdate}>
                    {t('settings.update.system.rollback')}
                  </Button>
                ) : null
              ]}
            />
          )}

          {systemStatus === 'failed' && (
            <Result
              status="warning"
              icon={<CloudSyncOutlined />}
              title={systemCurrent?.version || t('settings.update.system.title')}
              subTitle={systemErrMsg}
              extra={[
                <Button key="refresh" onClick={checkSystemUpdates}>
                  {t('settings.update.system.refresh')}
                </Button>,
                systemStaged ? (
                  <Button key="install" type="primary" danger onClick={confirmInstallSystemUpdate}>
                    {t('settings.update.system.install')}
                  </Button>
                ) : null,
                systemRollback ? (
                  <Button key="rollback" danger onClick={confirmRollbackSystemUpdate}>
                    {t('settings.update.system.rollback')}
                  </Button>
                ) : null
              ]}
            />
          )}

          {systemCurrent && (
            <div className="space-y-2 px-2 pb-2">
              {versionLine(t('settings.update.system.base'), systemCurrent.baseVersion)}
              {versionLine(t('settings.update.system.kernel'), systemCurrent.kernelVersion)}
              {versionLine(t('settings.update.system.rootfs'), systemCurrent.rootfsVersion)}
              {versionLine(t('settings.update.system.target'), systemCurrent.target)}
              {systemLatest &&
                versionLine(t('settings.update.system.latestTarget'), systemLatest.target)}
              {systemStaged &&
                versionLine(t('settings.update.system.stagedVersion'), systemStaged.version)}
              {systemStaged &&
                versionLine(t('settings.update.system.archive'), systemStaged.archiveName)}
              {systemStaged &&
                versionLine(
                  t('settings.update.system.requiredFree'),
                  formatBytes(systemStaged.requiredFreeBytes)
                )}
              {systemStaged &&
                versionLine(
                  t('settings.update.system.fileCount'),
                  systemStaged.fileCount.toString()
                )}
              {systemStaged?.destructive &&
                versionLine(
                  t('settings.update.system.rawImages'),
                  systemStaged.imageCount.toString()
                )}
              {systemProgress &&
                versionLine(
                  t('settings.update.system.progress'),
                  `${systemProgress.operation}/${systemProgress.phase}`
                )}
              {systemProgress?.message &&
                versionLine(t('settings.update.system.progressMessage'), systemProgress.message)}
              {systemPending &&
                versionLine(t('settings.update.system.pendingVersion'), systemPending.version)}
              {systemBootHealth &&
                versionLine(
                  t('settings.update.system.bootHealth'),
                  systemBootHealth.healthy
                    ? t('settings.update.system.healthy')
                    : t('settings.update.system.unhealthy')
                )}
              {systemPending && systemBootHealth?.healthy && (
                <div className="flex justify-end pt-2">
                  <Button size="small" type="primary" onClick={confirmSystemUpdate}>
                    {t('settings.update.system.confirmBoot')}
                  </Button>
                </div>
              )}
              {systemRollback &&
                versionLine(t('settings.update.system.rollbackBackup'), systemRollback.backupId)}
            </div>
          )}
        </div>

        <div className="flex justify-center">
          <Button
            type="link"
            size="small"
            href="https://github.com/woffko/Hardened_NanoKVM/blob/main/CHANGELOG.md"
            target="_blank"
          >
            CHANGELOG
          </Button>
        </div>
      </div>
    </>
  );
};
