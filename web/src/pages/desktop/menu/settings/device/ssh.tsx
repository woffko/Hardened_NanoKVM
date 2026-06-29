import { useEffect, useState } from 'react';
import { Switch, Tooltip } from 'antd';
import { CircleAlertIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as api from '@/api/vm.ts';

export const Ssh = () => {
  const { t } = useTranslation();

  const [isEnabled, setIsEnabled] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    void refresh();
  }, []);

  async function refresh() {
    setIsLoading(true);

    try {
      const rsp = await api.getSSHState();
      if (rsp.code === 0) {
        setIsEnabled(Boolean(rsp.data?.enabled));
      }
    } catch (err) {
      console.log(err);
    } finally {
      setIsLoading(false);
    }
  }

  async function update(checked: boolean) {
    if (isLoading) return;
    setIsLoading(true);

    try {
      const rsp = checked ? await api.enableSSH() : await api.disableSSH();
      if (rsp.code !== 0) {
        console.log(rsp.msg);
        return;
      }

      if (typeof rsp.data?.enabled === 'boolean') {
        setIsEnabled(rsp.data.enabled);
      } else {
        setIsEnabled(checked);
      }
    } catch (err) {
      console.log(err);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="flex items-center justify-between">
      <div className="flex flex-col space-y-1">
        <div className="flex items-center space-x-2">
          <span>SSH</span>

          <Tooltip
            title={t('settings.device.ssh.tip')}
            className="cursor-pointer"
            placement="right"
            styles={{ root: { maxWidth: '400px' } }}
          >
            <CircleAlertIcon className="text-neutral-500" size={14} />
          </Tooltip>
        </div>
        <span className="text-xs text-neutral-500">{t('settings.device.ssh.description')}</span>
      </div>

      <Switch checked={isEnabled} loading={isLoading} onChange={update} />
    </div>
  );
};
