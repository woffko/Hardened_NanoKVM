import { useEffect, useState } from 'react';
import { Select } from 'antd';
import { useTranslation } from 'react-i18next';

import * as api from '@/api/vm.ts';
import { getCsrfToken, setCsrfToken } from '@/lib/cookie.ts';

const DEFAULT_DURATION = '900';

export const SessionLock = () => {
  const { t } = useTranslation();

  const [isLoading, setIsLoading] = useState(false);
  const [duration, setDuration] = useState(DEFAULT_DURATION);

  const options = [
    { value: '300', label: t('settings.device.sessionLock.5') },
    { value: '900', label: t('settings.device.sessionLock.15') },
    { value: '1800', label: t('settings.device.sessionLock.30') },
    { value: '3600', label: t('settings.device.sessionLock.60') }
  ];

  useEffect(() => {
    getSessionLock();
  }, []);

  function getSessionLock() {
    setIsLoading(true);

    api
      .getSessionLock()
      .then((rsp) => {
        const value = rsp.data?.duration?.toString();
        if (value) {
          setDuration(value);
        }
      })
      .catch((err) => {
        console.log(err);
      })
      .finally(() => {
        setIsLoading(false);
      });
  }

  function update(value: string) {
    if (isLoading) return;
    setIsLoading(true);

    api
      .setSessionLock(parseInt(value))
      .then((rsp) => {
        if (rsp.code !== 0) {
          console.log(rsp.msg);
          return;
        }

        setDuration(value);
        const expiresAt = rsp.data?.expiresAt;
        const csrfToken = getCsrfToken();
        if (expiresAt && csrfToken) {
          setCsrfToken(csrfToken, expiresAt);
        }
      })
      .catch((err) => {
        console.log(err);
      })
      .finally(() => {
        setIsLoading(false);
      });
  }

  return (
    <div className="flex items-center justify-between">
      <div className="flex flex-col space-y-1">
        <span>{t('settings.device.sessionLock.title')}</span>
        <span className="text-xs text-neutral-500">
          {t('settings.device.sessionLock.description')}
        </span>
      </div>

      <Select
        style={{ width: 150 }}
        value={duration}
        options={options}
        loading={isLoading}
        onChange={update}
      />
    </div>
  );
};
