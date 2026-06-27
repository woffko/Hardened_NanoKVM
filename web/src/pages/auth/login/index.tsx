import { ReactElement, useEffect, useState } from 'react';
import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { Button, Form, Input } from 'antd';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import * as api from '@/api/auth.ts';
import { existToken, setCsrfToken, setToken } from '@/lib/cookie.ts';
import { encrypt } from '@/lib/encrypt.ts';
import { HARDENED_LOGO_SRC, HARDENED_NAME, HARDENED_VERSION } from '@/lib/hardened.ts';
import { Head } from '@/components/head.tsx';

import { Tips } from './tips.tsx';

export const Login = (): ReactElement => {
  const navigate = useNavigate();
  const { t } = useTranslation();

  const [isLoading, setIsloading] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    if (existToken()) {
      navigate('/', { replace: true });
    }
  }, []);

  useEffect(() => {
    if (msg) {
      setTimeout(() => setMsg(''), 3000);
    }
  }, [msg]);

  function login(values: any) {
    if (isLoading) return;
    setIsloading(true);

    const username = values.username;
    const password = encrypt(values.password);

    api
      .login(username, password)
      .then((rsp: any) => {
        if (rsp.code !== 0) {
          let errorMsg = t('auth.error');
          if (rsp.code === -2) errorMsg = t('auth.invalidUser');
          else if (rsp.code === -5) errorMsg = t('auth.locked');
          else if (rsp.code === -4) errorMsg = t('auth.globalLocked');

          setMsg(errorMsg);
          return;
        }

        setMsg('');
        setToken(rsp.data.token, rsp.data.expiresAt);
        if (rsp.data.csrfToken) {
          setCsrfToken(rsp.data.csrfToken, rsp.data.expiresAt);
        }

        navigate('/', { replace: true });
        window.location.reload();
      })
      .catch(() => {
        setMsg(t('auth.error'));
      })
      .finally(() => {
        setIsloading(false);
      });
  }

  return (
    <>
      <Head title={t('head.login')} />

      <div className="flex h-screen w-screen flex-col items-center justify-center">
        <Form
          style={{ minWidth: 300, maxWidth: 500 }}
          initialValues={{ remember: true }}
          onFinish={login}
        >
          <div className="flex flex-col items-center justify-center pb-5">
            <div
              className="flex size-16 cursor-pointer items-center justify-center rounded-lg bg-neutral-100 shadow-lg"
              onClick={(evt) => {
                evt.preventDefault();
                (evt.currentTarget as HTMLDivElement).classList.add('animate-spin');
                setTimeout(() => {
                  (evt.currentTarget as HTMLDivElement).classList.remove('animate-spin');
                }, 1000);
              }}
            >
              <img
                id="logo"
                src={HARDENED_LOGO_SRC}
                alt={HARDENED_NAME}
                className="size-12 object-contain"
              />
            </div>
            <div className="mt-3 text-lg font-semibold text-neutral-100">{HARDENED_NAME}</div>
            <div className="mt-1 text-xs text-neutral-500">{HARDENED_VERSION}</div>
          </div>
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
            <Input
              prefix={<LockOutlined />}
              type="password"
              placeholder={t('auth.placeholderPassword')}
            />
          </Form.Item>

          <div className="pb-1 text-red-500">{msg}</div>

          <Form.Item>
            <Button type="primary" htmlType="submit" className="w-full" loading={isLoading}>
              {t('auth.loginButtonText')}
            </Button>
          </Form.Item>

          <div className="flex justify-end pb-4 text-sm">
            <Tips />
          </div>
        </Form>
      </div>
    </>
  );
};
