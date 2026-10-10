import { useEffect, useRef, useState, type RefObject } from 'react';
import { Alert, Button, Input, message, Modal, Spin, Switch, Tag, type InputRef } from 'antd';
import { QRCodeSVG } from 'qrcode.react';
import { useTranslation } from 'react-i18next';

import * as api from '@/api/auth-totp.ts';
import type { TotpStatus } from '@/api/auth-totp.ts';
import { encrypt } from '@/lib/encrypt.ts';

/** Copy text, falling back to execCommand where the Clipboard API is missing (plain HTTP). */
async function copyText(text: string, container: HTMLElement): Promise<boolean> {
  if (window.isSecureContext && navigator.clipboard) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through to the legacy path.
    }
  }
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.opacity = '0';
  container.appendChild(area);
  area.focus();
  area.select();
  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch {
    copied = false;
  }
  area.remove();
  return copied;
}

type Props = {
  /** Blocks navigation away while an enrolment is half-finished. */
  setIsLocked?: (locked: boolean) => void;
  /** Called once enrolment completes, for the forced-enrolment page. */
  onEnrolled?: () => void;
};

export const TotpEnrollment = ({ setIsLocked, onEnrolled }: Props) => {
  const { t } = useTranslation();

  const [status, setStatus] = useState<TotpStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isBusy, setIsBusy] = useState(false);

  const [secret, setSecret] = useState('');
  const [otpauthUri, setOtpauthUri] = useState('');
  const [code, setCode] = useState('');

  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [password, setPassword] = useState('');
  const [isDisabling, setIsDisabling] = useState(false);
  const [isStartingEnrolment, setIsStartingEnrolment] = useState(false);
  const [isRegenerating, setIsRegenerating] = useState(false);
  const [isSavingRequired, setIsSavingRequired] = useState(false);
  // Codes from a fresh enrolment: onEnrolled must wait until they are acknowledged.
  const [enrolmentNeedsAck, setEnrolmentNeedsAck] = useState(false);
  const codesRef = useRef<HTMLDivElement>(null);
  const enrolPasswordRef = useRef<InputRef>(null);
  const regeneratePasswordRef = useRef<InputRef>(null);
  const disablePasswordRef = useRef<InputRef>(null);

  // antd focuses the dialog itself once it has opened, which overrides autoFocus.
  const focusWhenOpen = (ref: RefObject<InputRef>) => (open: boolean) => {
    if (open) ref.current?.focus();
  };

  const isEnrolling = Boolean(otpauthUri);

  useEffect(() => {
    refresh();
  }, []);

  // An abandoned enrolment leaves a secret the user may already have scanned,
  // so keep them on the tab until they either confirm it or back out.
  useEffect(() => {
    setIsLocked?.(isEnrolling || backupCodes.length > 0);
  }, [isEnrolling, backupCodes.length, setIsLocked]);

  function refresh() {
    setIsLoading(true);
    api
      .getStatus()
      .then((rsp) => {
        if (rsp.code === 0) {
          setStatus(rsp.data as TotpStatus);
        }
      })
      .catch((err) => console.log(err))
      .finally(() => setIsLoading(false));
  }

  function startEnrollment() {
    if (isBusy || !password) return;
    setIsBusy(true);

    api
      .enroll(encrypt(password))
      .then((rsp) => {
        if (rsp.code !== 0) {
          message.error(rsp.msg || t('settings.account.totp.enrollFailed'));
          return;
        }
        setIsStartingEnrolment(false);
        setPassword('');
        setSecret(rsp.data.secret);
        setOtpauthUri(rsp.data.otpauthUri);
        setCode('');
      })
      .catch((err) => message.error(errorText(err, t('settings.account.totp.enrollFailed'))))
      .finally(() => setIsBusy(false));
  }

  function confirmEnrollment() {
    if (isBusy || !code.trim()) return;
    setIsBusy(true);

    api
      .confirm(code.trim())
      .then((rsp) => {
        if (rsp.code !== 0) {
          message.error(rsp.msg || t('settings.account.totp.invalidCode'));
          return;
        }
        setBackupCodes(rsp.data.backupCodes || []);
        setOtpauthUri('');
        setSecret('');
        setCode('');
        setEnrolmentNeedsAck(true);
        refresh();
      })
      .catch((err) => message.error(errorText(err, t('settings.account.totp.invalidCode'))))
      .finally(() => setIsBusy(false));
  }

  function cancelEnrollment() {
    setOtpauthUri('');
    setSecret('');
    setCode('');
  }

  function disable() {
    if (isBusy || !password) return;
    setIsBusy(true);

    api
      .disable(encrypt(password))
      .then((rsp) => {
        if (rsp.code !== 0) {
          message.error(rsp.msg || t('settings.account.totp.disableFailed'));
          return;
        }
        setIsDisabling(false);
        setPassword('');
        refresh();
      })
      .catch((err) => message.error(errorText(err, t('settings.account.totp.disableFailed'))))
      .finally(() => setIsBusy(false));
  }

  function regenerate() {
    if (isBusy || !password) return;
    setIsBusy(true);

    api
      .regenerateBackupCodes(encrypt(password))
      .then((rsp) => {
        if (rsp.code !== 0) {
          message.error(rsp.msg || t('settings.account.totp.regenerateFailed'));
          return;
        }
        setIsRegenerating(false);
        setPassword('');
        setBackupCodes(rsp.data.backupCodes || []);
        refresh();
      })
      .catch((err) => message.error(errorText(err, t('settings.account.totp.regenerateFailed'))))
      .finally(() => setIsBusy(false));
  }

  function changeRequired(required: boolean) {
    setIsSavingRequired(true);

    api
      .setRequired(required)
      .then((rsp) => {
        if (rsp.code !== 0) {
          message.error(rsp.msg || t('settings.account.totp.requireFailed'));
          return;
        }
        setStatus((current) => current && { ...current, required });
      })
      .catch((err) => message.error(errorText(err, t('settings.account.totp.requireFailed'))))
      .finally(() => setIsSavingRequired(false));
  }

  function copyBackupCodes() {
    copyText(backupCodes.join('\n'), codesRef.current ?? document.body).then((copied) =>
      copied
        ? message.success(t('settings.account.totp.copied'))
        : message.error(t('settings.account.totp.copyFailed'))
    );
  }

  function downloadBackupCodes() {
    const url = URL.createObjectURL(
      new Blob([backupCodes.join('\n') + '\n'], { type: 'text/plain' })
    );
    const link = document.createElement('a');
    link.href = url;
    link.download = 'nanokvm-backup-codes.txt';
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function acknowledgeBackupCodes() {
    setBackupCodes([]);
    if (enrolmentNeedsAck) {
      setEnrolmentNeedsAck(false);
      onEnrolled?.();
    }
  }

  function errorText(err: any, fallback: string) {
    const detail = err?.response?.data?.msg;
    return typeof detail === 'string' && detail ? detail : fallback;
  }

  // Backup codes are shown exactly once; only hashes are kept server-side.
  if (backupCodes.length > 0) {
    return (
      <div ref={codesRef} className="flex flex-col space-y-3">
        <Alert
          type="warning"
          showIcon
          message={
            <div>
              <div className="font-medium">{t('settings.account.totp.backupTitle')}</div>
              <div>{t('settings.account.totp.backupDescription')}</div>
            </div>
          }
        />
        <div className="grid grid-cols-3 gap-2 rounded bg-neutral-800 p-3 text-center font-mono text-sm">
          {backupCodes.map((backupCode) => (
            <span key={backupCode}>{backupCode}</span>
          ))}
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={copyBackupCodes}>{t('settings.account.totp.copy')}</Button>
          <Button onClick={downloadBackupCodes}>{t('settings.account.totp.download')}</Button>
          <Button type="primary" onClick={acknowledgeBackupCodes}>
            {t('settings.account.totp.savedThem')}
          </Button>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex justify-center py-4">
        <Spin />
      </div>
    );
  }

  if (isEnrolling) {
    return (
      <div className="flex flex-col space-y-3">
        <span className="text-sm text-neutral-400">{t('settings.account.totp.scan')}</span>
        <div className="flex justify-center rounded bg-white p-3">
          <QRCodeSVG value={otpauthUri} size={180} />
        </div>
        <span className="text-xs text-neutral-500">{t('settings.account.totp.manualEntry')}</span>
        <code className="break-all rounded bg-neutral-800 p-2 text-xs">{secret}</code>

        <Input
          value={code}
          onChange={(e) => setCode(e.target.value)}
          onPressEnter={confirmEnrollment}
          placeholder={t('settings.account.totp.codePlaceholder')}
          inputMode="numeric"
          autoComplete="one-time-code"
        />
        <div className="flex space-x-2">
          <Button type="primary" loading={isBusy} onClick={confirmEnrollment}>
            {t('settings.account.totp.confirm')}
          </Button>
          <Button onClick={cancelEnrollment}>{t('settings.account.totp.cancel')}</Button>
        </div>
      </div>
    );
  }

  return (
    <>
      <div className="flex items-center justify-between gap-4">
        <div className="flex min-w-0 flex-col space-y-1">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>{t('settings.account.totp.title')}</span>
            {status?.enabled ? (
              <Tag color="green" className="!me-0">
                {t('settings.account.totp.enabled')}
              </Tag>
            ) : (
              <Tag className="!me-0">{t('settings.account.totp.disabled')}</Tag>
            )}
            {status?.required && !status.enabled && (
              <Tag color="blue" className="!me-0">
                {t('settings.account.totp.required')}
              </Tag>
            )}
          </div>
          <span className="text-xs text-neutral-500">
            {status?.enabled
              ? // Not named `count`: that would make i18next look for plural
                // key variants that the fork's extras mechanism does not add.
                t('settings.account.totp.remaining', {
                  remaining: status.backupCodesRemaining
                })
              : t('settings.account.totp.description')}
          </span>
        </div>

        {status?.enabled ? (
          <div className="flex shrink-0 gap-2">
            <Button onClick={() => setIsRegenerating(true)}>
              {t('settings.account.totp.regenerate')}
            </Button>
            <Button danger disabled={status.required} onClick={() => setIsDisabling(true)}>
              {t('settings.account.totp.disable')}
            </Button>
          </div>
        ) : (
          <Button
            type="primary"
            disabled={!status?.clockSynced}
            onClick={() => setIsStartingEnrolment(true)}
          >
            {t('settings.account.totp.enable')}
          </Button>
        )}
      </div>

      {/* Codes are derived from the clock, so enrolling before NTP succeeds
          would produce a secret whose codes could never be confirmed. */}
      {!status?.clockSynced && !status?.enabled && (
        <Alert
          className="mt-3"
          type="warning"
          showIcon
          message={t('settings.account.totp.clockUnsynced')}
        />
      )}

      {status?.enabled && (
        <div className="mt-6 flex items-center justify-between gap-4">
          <div className="flex min-w-0 flex-col space-y-1">
            <span>{t('settings.account.totp.requireTitle')}</span>
            <span className="text-xs text-neutral-500">
              {t('settings.account.totp.requireDescription')}
            </span>
          </div>
          <Switch checked={status.required} loading={isSavingRequired} onChange={changeRequired} />
        </div>
      )}

      {status?.enabled && status.backupCodesRemaining === 0 && (
        <Alert
          className="mt-3"
          type="warning"
          showIcon
          message={t('settings.account.totp.noBackupCodes')}
        />
      )}

      <Modal
        open={isStartingEnrolment}
        afterOpenChange={focusWhenOpen(enrolPasswordRef)}
        title={t('settings.account.totp.enableTitle')}
        okText={t('settings.account.totp.continue')}
        okButtonProps={{ loading: isBusy, disabled: !password }}
        onOk={startEnrollment}
        onCancel={() => {
          setIsStartingEnrolment(false);
          setPassword('');
        }}
      >
        <div className="flex flex-col space-y-3 py-2">
          <span className="text-sm text-neutral-400">
            {t('settings.account.totp.enableDescription')}
          </span>
          <Input.Password
            ref={enrolPasswordRef}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onPressEnter={startEnrollment}
            placeholder={t('settings.account.totp.passwordPlaceholder')}
          />
        </div>
      </Modal>

      <Modal
        open={isRegenerating}
        afterOpenChange={focusWhenOpen(regeneratePasswordRef)}
        title={t('settings.account.totp.regenerateTitle')}
        okText={t('settings.account.totp.regenerate')}
        okButtonProps={{ loading: isBusy, disabled: !password }}
        onOk={regenerate}
        onCancel={() => {
          setIsRegenerating(false);
          setPassword('');
        }}
      >
        <div className="flex flex-col space-y-3 py-2">
          <span className="text-sm text-neutral-400">
            {t('settings.account.totp.regenerateDescription')}
          </span>
          <Input.Password
            ref={regeneratePasswordRef}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onPressEnter={regenerate}
            placeholder={t('settings.account.totp.passwordPlaceholder')}
          />
        </div>
      </Modal>

      <Modal
        open={isDisabling}
        afterOpenChange={focusWhenOpen(disablePasswordRef)}
        title={t('settings.account.totp.disableTitle')}
        okText={t('settings.account.totp.disable')}
        okButtonProps={{ danger: true, loading: isBusy, disabled: !password }}
        onOk={disable}
        onCancel={() => {
          setIsDisabling(false);
          setPassword('');
        }}
      >
        <div className="flex flex-col space-y-3 py-2">
          <span className="text-sm text-neutral-400">
            {t('settings.account.totp.disableDescription')}
          </span>
          <Input.Password
            ref={disablePasswordRef}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t('settings.account.totp.passwordPlaceholder')}
          />
        </div>
      </Modal>
    </>
  );
};
