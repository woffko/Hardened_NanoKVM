import { useState } from 'react';
import { Divider, Segmented } from 'antd';
import { useTranslation } from 'react-i18next';

import { Network } from '../network';
import { SystemLog } from '../system-log';

import { FirewallSettings } from './firewall';
import { TimeSettings } from './time';

type SystemSection = 'network' | 'time' | 'firewall' | 'systemLog';

export const System = () => {
  const { t } = useTranslation();
  const [section, setSection] = useState<SystemSection>('network');

  return (
    <>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="text-base">{t('settings.system.title')}</div>
        <Segmented
          size="small"
          className="max-w-full overflow-x-auto"
          value={section}
          options={[
            { value: 'network', label: t('settings.network.title') },
            { value: 'time', label: t('settings.system.sections.time') },
            { value: 'firewall', label: t('settings.system.sections.firewall') },
            { value: 'systemLog', label: t('settings.system.sections.systemLog') }
          ]}
          onChange={(value) => setSection(value as SystemSection)}
        />
      </div>
      <Divider className="opacity-50" />

      {section === 'network' && <Network showTitle={false} />}
      {section === 'time' && <TimeSettings />}
      {section === 'firewall' && <FirewallSettings />}
      {section === 'systemLog' && <SystemLog showTitle={false} />}
    </>
  );
};
