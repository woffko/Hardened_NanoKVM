import { useState } from 'react';
import { Divider, Segmented } from 'antd';
import { useTranslation } from 'react-i18next';

import { SystemLog } from '../system-log';

import { TimeSettings } from './time';

export const System = () => {
  const { t } = useTranslation();
  const [section, setSection] = useState<'time' | 'systemLog'>('time');

  return (
    <>
      <div className="flex items-center justify-between gap-3">
        <div className="text-base">{t('settings.system.title')}</div>
        <Segmented
          size="small"
          value={section}
          options={[
            { value: 'time', label: t('settings.system.sections.time') },
            { value: 'systemLog', label: t('settings.system.sections.systemLog') }
          ]}
          onChange={(value) => setSection(value as 'time' | 'systemLog')}
        />
      </div>
      <Divider className="opacity-50" />

      {section === 'time' ? <TimeSettings /> : <SystemLog showTitle={false} />}
    </>
  );
};
