import { useState } from 'react';
import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { Button, Form, Input, Modal } from 'antd';
import { useTranslation } from 'react-i18next';

import * as vmApi from '@/api/vm.ts';
import { encrypt } from '@/lib/encrypt.ts';

type UnlockProps = {
  onUnlock: (ticket: string) => void;
  onCancel: () => void;
};

// Scripts run as root: each upload or run needs a fresh terminal unlock.
export const Unlock = ({ onUnlock, onCancel }: UnlockProps) => {
  const { t } = useTranslation();
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [msg, setMsg] = useState('');

  function unlock(values: { username: string; password: string }) {
    if (isUnlocking) return;
    setMsg('');
    setIsUnlocking(true);

    vmApi
      .unlockTerminal(values.username, encrypt(values.password))
      .then((rsp) => {
        if (rsp.code !== 0) {
          if (rsp.code === -2) setMsg(t('terminal.invalidCredentials'));
          else if (rsp.code === -5) setMsg(t('terminal.locked'));
          else setMsg(rsp.msg || t('terminal.unlockFailed'));
          return;
        }

        onUnlock(rsp.data.ticket);
      })
      .catch((err) => {
        if (err?.response?.status === 403) setMsg(t('script.terminalRequired'));
        else setMsg(err?.response?.data?.msg || t('terminal.unlockFailed'));
      })
      .finally(() => {
        setIsUnlocking(false);
      });
  }

  return (
    <Modal
      title={t('terminal.unlockTitle')}
      width={400}
      footer={null}
      style={{ top: 60 }}
      open={true}
      onCancel={onCancel}
      destroyOnClose
    >
      <Form initialValues={{ username: 'admin' }} onFinish={unlock}>
        <p className="mb-4 text-sm text-neutral-400">{t('script.unlockDesc')}</p>

        <Form.Item
          name="username"
          rules={[{ required: true, message: t('auth.noEmptyUsername'), min: 1 }]}
        >
          <Input prefix={<UserOutlined />} placeholder={t('auth.placeholderUsername')} />
        </Form.Item>

        <Form.Item
          name="password"
          rules={[{ required: true, message: t('auth.noEmptyPassword'), min: 1 }]}
        >
          <Input.Password prefix={<LockOutlined />} placeholder={t('auth.placeholderPassword')} />
        </Form.Item>

        <div className="min-h-6 pb-1 text-sm text-red-500">{msg}</div>

        <Button type="primary" htmlType="submit" className="w-full" loading={isUnlocking}>
          {t('terminal.unlock')}
        </Button>
      </Form>
    </Modal>
  );
};
