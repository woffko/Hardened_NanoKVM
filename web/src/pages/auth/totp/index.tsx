import { Card, Typography } from 'antd';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import { Head } from '@/components/head.tsx';
import { TotpEnrollment } from '@/components/totp-enrollment.tsx';

/**
 * Standalone enrolment page for the forced case.
 *
 * Reached when `security.require_totp` is set but the account has no
 * enrolment. Login deliberately succeeds in that state -- refusing would leave
 * a headless device unreachable -- so this is where the user is sent to make
 * the policy true.
 */
export const Totp = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();

  return (
    <>
      <Head title={t('settings.account.totp.title')} />

      <div className="flex h-screen w-screen flex-col items-center justify-center space-y-5">
        <Typography.Title level={4} className="!mb-0 text-center">
          {t('settings.account.totp.requiredTitle')}
        </Typography.Title>
        <Typography.Paragraph type="secondary" className="!mb-0 max-w-md text-center">
          {t('settings.account.totp.requiredDescription')}
        </Typography.Paragraph>

        <Card style={{ minWidth: 340, maxWidth: 480 }}>
          <TotpEnrollment onEnrolled={() => navigate('/', { replace: true })} />
        </Card>
      </div>
    </>
  );
};
