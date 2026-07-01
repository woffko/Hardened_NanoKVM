import { Divider } from 'antd';
import { useTranslation } from 'react-i18next';

import { DNS } from './dns.tsx';
import { Tls } from './tls.tsx';
import { Wifi } from './wifi.tsx';

type NetworkProps = {
  showTitle?: boolean;
};

export const Network = ({ showTitle = true }: NetworkProps) => {
  const { t } = useTranslation();

  return (
    <>
      {showTitle && (
        <>
          <div className="text-base">{t('settings.network.title')}</div>
          <Divider className="opacity-50" />
        </>
      )}

      <div className="flex flex-col space-y-8">
        <Tls />
        <Wifi />
      </div>

      <Divider className="opacity-50" style={{ margin: '32px 0' }} />

      <div className="flex flex-col space-y-8">
        <DNS />
      </div>
    </>
  );
};
