import { useEffect, useState } from 'react';
import { Modal, Switch, Tooltip } from 'antd';
import { CircleAlertIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as api from '@/api/vm.ts';

const REDIRECT_DELAY_SECONDS = 30;

export const Tls = () => {
  const { t } = useTranslation();

  const [isEnabled, setIsEnabled] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    setIsEnabled(window.location.protocol === 'https:');
  }, []);

  function requestUpdate() {
    if (isLoading) return;

    const enable = !isEnabled;
    const target = protocolRedirectUrl(enable);

    Modal.confirm({
      title: t('settings.network.tls.rebootTitle'),
      content: (
        <div className="space-y-2">
          <p>
            {t('settings.network.tls.rebootDesc', { seconds: REDIRECT_DELAY_SECONDS })}
          </p>
          <p className="break-all font-mono text-xs text-neutral-400">{target}</p>
        </div>
      ),
      okText: t('settings.network.tls.rebootOk'),
      cancelText: t('settings.network.tls.rebootCancel'),
      onOk: () => update(enable, target)
    });
  }

  async function update(enable: boolean, target: string) {
    setIsLoading(true);
    const timer = window.setTimeout(() => {
      window.location.assign(target);
    }, REDIRECT_DELAY_SECONDS * 1000);

    try {
      const rsp = await api.setTLS(enable);
      if (rsp.code === 0) {
        setIsEnabled(enable);
        return;
      }
    } catch (err) {
      console.log(err);
    }

    window.clearTimeout(timer);
    setIsLoading(false);
  }

  function protocolRedirectUrl(enable: boolean) {
    const target = new URL(window.location.href);
    target.protocol = enable ? 'https:' : 'http:';

    if (enable && target.port === '80') {
      target.port = '';
    }
    if (!enable && target.port === '443') {
      target.port = '';
    }

    return target.toString();
  }

  return (
    <div className="flex items-center justify-between">
      <div className="flex flex-col space-y-1">
        <div className="flex items-center space-x-2">
          <span>HTTPS</span>

          <Tooltip
            title={t('settings.network.tls.tip')}
            className="cursor-pointer"
            placement="right"
            styles={{ root: { maxWidth: '400px' } }}
          >
            <CircleAlertIcon className="text-neutral-500" size={14} />
          </Tooltip>
        </div>
        <span className="text-xs text-neutral-500">{t('settings.network.tls.description')}</span>
      </div>

      <Switch checked={isEnabled} loading={isLoading} onChange={requestUpdate} />
    </div>
  );
};
