import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Button, Input, Segmented } from 'antd';
import { CheckIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as api from '@/api/network.ts';
import type { IPv6Mode } from '@/api/network.ts';

type IPv6Address = {
  interface: string;
  address: string;
  prefix: number;
  scope: string;
};

type IPv6Config = {
  interface?: string;
  address?: string;
  prefix?: number;
  gateway?: string;
};

type IPv6State = {
  mode: IPv6Mode;
  enabled: boolean;
  active: boolean;
  clientAvailable: boolean;
  clientPath: string;
  addresses: IPv6Address[];
  gateway: string;
  config?: IPv6Config;
  status: string;
  message: string;
};

function normalizeIPv6(value: string) {
  return value.trim().split('/')[0].trim();
}

function isValidIPv6(value: string) {
  if (!value.includes(':')) return false;

  try {
    new URL(`http://[${value}]/`);
    return true;
  } catch {
    return false;
  }
}

function isValidPrefix(value: string) {
  if (!/^\d+$/.test(value.trim())) return false;
  const prefix = Number(value);
  return prefix >= 1 && prefix <= 128;
}

function formatAddress(address: IPv6Address) {
  return `${address.address}/${address.prefix} (${address.scope})`;
}

const Panel = ({
  title,
  description,
  children
}: {
  title: string;
  description?: string;
  children: ReactNode;
}) => {
  return (
    <div className="overflow-hidden rounded-xl bg-neutral-800/50">
      <div className="px-4 pb-1.5 pt-3">
        <div className="font-semibold text-neutral-100">{title}</div>
        {description && (
          <div className="mt-0.5 text-xs leading-snug text-neutral-500">{description}</div>
        )}
      </div>
      <div>{children}</div>
    </div>
  );
};

const InfoRow = ({
  label,
  value,
  isLast = false
}: {
  label: string;
  value?: string;
  isLast?: boolean;
}) => {
  return (
    <div className="px-4">
      <div
        className={`flex min-h-[44px] items-center justify-between gap-4 ${
          isLast ? '' : 'border-b border-neutral-700/50'
        }`}
      >
        <span className="shrink-0 text-sm text-neutral-300">{label}</span>
        <span className="max-w-[420px] break-all text-right text-sm text-neutral-500">
          {value || '-'}
        </span>
      </div>
    </div>
  );
};

const EditableInfoRow = ({
  label,
  value,
  placeholder,
  status,
  isLast = false,
  onChange
}: {
  label: string;
  value: string;
  placeholder: string;
  status?: 'error';
  isLast?: boolean;
  onChange: (value: string) => void;
}) => {
  return (
    <div className="px-4">
      <div
        className={`flex min-h-[52px] items-center justify-between gap-4 ${
          isLast ? '' : 'border-b border-neutral-700/50'
        }`}
      >
        <span className="shrink-0 text-sm text-neutral-300">{label}</span>
        <Input
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          status={status}
          className="max-w-[300px]"
        />
      </div>
    </div>
  );
};

export const IPv6 = () => {
  const { t } = useTranslation();

  const [mode, setMode] = useState<IPv6Mode>('disabled');
  const [originalMode, setOriginalMode] = useState<IPv6Mode>('disabled');
  const [addresses, setAddresses] = useState<IPv6Address[]>([]);
  const [gateway, setGateway] = useState('');
  const [clientAvailable, setClientAvailable] = useState(false);
  const [clientPath, setClientPath] = useState('');
  const [status, setStatus] = useState('');
  const [statusMessage, setStatusMessage] = useState('');
  const [address, setAddress] = useState('');
  const [prefix, setPrefix] = useState('64');
  const [router, setRouter] = useState('');
  const [originalAddress, setOriginalAddress] = useState('');
  const [originalPrefix, setOriginalPrefix] = useState('64');
  const [originalRouter, setOriginalRouter] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    getIPv6();
  }, []);

  async function getIPv6(showLoading = true) {
    if (showLoading) setIsLoading(true);

    try {
      const rsp = await api.getIPv6();
      if (rsp.code !== 0) {
        setError(rsp.msg);
        return;
      }

      const data = rsp.data as IPv6State;
      const fetchedMode = data.mode || 'disabled';
      const config = data.config || {};
      const fetchedAddress = normalizeIPv6(config.address || '');
      const fetchedPrefix = String(config.prefix || 64);
      const fetchedRouter = normalizeIPv6(config.gateway || '');

      setMode(fetchedMode);
      setOriginalMode(fetchedMode);
      setAddresses(data.addresses || []);
      setGateway(data.gateway || '');
      setClientAvailable(Boolean(data.clientAvailable));
      setClientPath(data.clientPath || '');
      setStatus(data.status || '');
      setStatusMessage(data.message || '');
      setAddress(fetchedAddress);
      setPrefix(fetchedPrefix);
      setRouter(fetchedRouter);
      setOriginalAddress(fetchedAddress);
      setOriginalPrefix(fetchedPrefix);
      setOriginalRouter(fetchedRouter);
    } catch (err) {
      console.log(err);
      setError(t('settings.network.ipv6.loadFailed'));
    } finally {
      if (showLoading) setIsLoading(false);
    }
  }

  async function save() {
    if (isSaving) return;

    setMessage('');
    setError('');

    const normalizedAddress = normalizeIPv6(address);
    const normalizedRouter = normalizeIPv6(router);
    const trimmedPrefix = prefix.trim();

    if (mode === 'dhcpv6' && !clientAvailable) {
      setError(t('settings.network.ipv6.clientMissing'));
      return;
    }

    if (
      mode === 'manual' &&
      (!isValidIPv6(normalizedAddress) ||
        !isValidPrefix(trimmedPrefix) ||
        !isValidIPv6(normalizedRouter))
    ) {
      setError(t('settings.network.ipv6.invalidManual'));
      return;
    }

    setIsSaving(true);
    try {
      const rsp = await api.setIPv6(
        mode,
        mode === 'manual'
          ? {
              interface: 'eth0',
              address: normalizedAddress,
              prefix: Number(trimmedPrefix),
              gateway: normalizedRouter
            }
          : undefined
      );
      if (rsp.code !== 0) {
        setError(rsp.msg || t('settings.network.ipv6.saveFailed'));
        return;
      }

      setOriginalMode(mode);
      setOriginalAddress(normalizedAddress);
      setOriginalPrefix(trimmedPrefix);
      setOriginalRouter(normalizedRouter);
      await getIPv6(false);
      setMessage(t('settings.network.ipv6.saved'));
    } catch (err) {
      console.log(err);
      setError(t('settings.network.ipv6.saveFailed'));
    } finally {
      setIsSaving(false);
    }
  }

  const normalizedAddress = normalizeIPv6(address);
  const normalizedRouter = normalizeIPv6(router);
  const trimmedPrefix = prefix.trim();
  const hasInvalidManual =
    mode === 'manual' &&
    ((!isValidIPv6(normalizedAddress) && normalizedAddress !== '') ||
      (!isValidPrefix(trimmedPrefix) && trimmedPrefix !== '') ||
      (!isValidIPv6(normalizedRouter) && normalizedRouter !== ''));
  const hasChanges =
    mode !== originalMode ||
    (mode === 'manual' &&
      (normalizedAddress !== originalAddress ||
        trimmedPrefix !== originalPrefix ||
        normalizedRouter !== originalRouter));
  const needsApply = status === 'needs-apply';
  const canSave =
    (hasChanges || needsApply) &&
    !isLoading &&
    !isSaving &&
    !hasInvalidManual &&
    !(mode === 'dhcpv6' && !clientAvailable);
  const statusText =
    error ||
    message ||
    (needsApply ? statusMessage : hasChanges ? t('settings.network.ipv6.unsaved') : '');
  const statusColor = error ? 'text-red-400' : message ? 'text-green-400' : 'text-yellow-400/80';
  const addressList = addresses.map(formatAddress).join(', ');

  return (
    <div className="flex flex-col space-y-5">
      <div className="flex items-center justify-between gap-6">
        <div className="flex flex-col space-y-1">
          <span>{t('settings.network.ipv6.title')}</span>
          <span className="text-xs text-neutral-500">
            {t('settings.network.ipv6.description')}
          </span>
        </div>

        <Segmented
          disabled={isLoading || isSaving}
          value={mode}
          onChange={(val) => {
            setMode(val as IPv6Mode);
            setStatus('');
            setMessage('');
            setError('');
          }}
          options={[
            { label: t('settings.network.ipv6.disabled'), value: 'disabled' },
            { label: t('settings.network.ipv6.slaac'), value: 'slaac' },
            { label: t('settings.network.ipv6.dhcpv6'), value: 'dhcpv6' },
            { label: t('settings.network.ipv6.manual'), value: 'manual' }
          ]}
        />
      </div>

      <Panel title={t('settings.network.ipv6.status')}>
        <InfoRow label={t('settings.network.ipv6.interface')} value="eth0" />
        <InfoRow label={t('settings.network.ipv6.state')} value={statusMessage} />
        <InfoRow label={t('settings.network.ipv6.router')} value={gateway} />
        <InfoRow
          label={t('settings.network.ipv6.dhcpv6Client')}
          value={clientAvailable ? clientPath : t('settings.network.ipv6.notInstalled')}
        />
        <InfoRow
          label={t('settings.network.ipv6.addresses')}
          value={addressList}
          isLast
        />
      </Panel>

      {mode === 'manual' && (
        <Panel title={t('settings.network.ipv6.manualSettings')}>
          <EditableInfoRow
            label={t('settings.network.ipv6.ipAddress')}
            value={address}
            placeholder="fd00:1234:abcd:2::132"
            status={address.trim() && !isValidIPv6(normalizedAddress) ? 'error' : undefined}
            onChange={(value) => {
              setAddress(value);
              setMessage('');
              setError('');
            }}
          />
          <EditableInfoRow
            label={t('settings.network.ipv6.prefix')}
            value={prefix}
            placeholder="64"
            status={prefix.trim() && !isValidPrefix(trimmedPrefix) ? 'error' : undefined}
            onChange={(value) => {
              setPrefix(value);
              setMessage('');
              setError('');
            }}
          />
          <EditableInfoRow
            label={t('settings.network.ipv6.router')}
            value={router}
            placeholder="fe80::1"
            status={router.trim() && !isValidIPv6(normalizedRouter) ? 'error' : undefined}
            isLast
            onChange={(value) => {
              setRouter(value);
              setMessage('');
              setError('');
            }}
          />
        </Panel>
      )}

      {(hasChanges || statusText) && (
        <div className="flex items-center justify-between">
          <span className={`text-xs ${statusColor}`}>{statusText}</span>

          <Button
            type={hasChanges ? 'primary' : 'default'}
            icon={message ? <CheckIcon size={14} /> : undefined}
            loading={isSaving}
            disabled={!canSave}
            onClick={save}
          >
            {t('settings.network.ipv6.apply')}
          </Button>
        </div>
      )}
    </div>
  );
};
