import { useState } from 'react';
import { Divider, Segmented } from 'antd';
import { useTranslation } from 'react-i18next';

import { SystemLog } from '../system-log';

import { FirewallSettings } from './firewall';
import { TimeSettings } from './time';

export const System = () => {
  const { t } = useTranslation();
  const [section, setSection] = useState<'time' | 'firewall' | 'systemLog'>('time');

  return (
    <>
      <div className="flex items-center justify-between gap-3">
        <div className="text-base">{t('settings.system.title')}</div>
        <Segmented
          size="small"
          value={section}
          options={[
            { value: 'time', label: t('settings.system.sections.time') },
            { value: 'firewall', label: t('settings.system.sections.firewall') },
            { value: 'systemLog', label: t('settings.system.sections.systemLog') }
          ]}
          onChange={(value) => setSection(value as 'time' | 'firewall' | 'systemLog')}
        />
      </div>
      <Divider className="opacity-50" />

      {section === 'time' && <TimeSettings />}
      {section === 'firewall' && <FirewallSettings />}
      {section === 'systemLog' && <SystemLog showTitle={false} />}
    </>
  );
};
