import { ReactElement, useEffect, useState } from 'react';
import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { Button, Form, Input } from 'antd';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import * as api from '@/api/auth.ts';
import { getCurrentVersion } from '@/api/application.ts';
import { existToken, setCsrfToken } from '@/lib/cookie.ts';
import { encrypt } from '@/lib/encrypt.ts';
import {
  formatHardenedVersion,
  HARDENED_LOGO_SRC,
  HARDENED_NAME,
  HARDENED_VERSION
} from '@/lib/hardened.ts';
import { Head } from '@/components/head.tsx';

import { Tips } from './tips.tsx';

export const Login = (): ReactElement => {
  const navigate = useNavigate();
  const { t } = useTranslation();

  const [isLoading, setIsloading] = useState(false);
  const [msg, setMsg] = useState('');
  const [setupRequired, setSetupRequired] = useState<boolean | null>(null);
  const [displayVersion, setDisplayVersion] = useState(HARDENED_VERSION);

  useEffect(() => {
    if (existToken()) {
      navigate('/', { replace: true });
      return;
    }

    api
      .getSetupState()
      .then((rsp: any) => {
        if (rsp.code === 0) {
          setSetupRequired(Boolean(rsp.data?.required));
          return;
        }
        setSetupRequired(false);
      })
      .catch(() => {
        setSetupRequired(false);
      });

    getCurrentVersion()
      .then((rsp: any) => {
        if (rsp.code === 0) {
          setDisplayVersion(formatHardenedVersion(rsp.data?.current));
        }
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    if (msg) {
      setTimeout(() => setMsg(''), 3000);
    }
  }, [msg]);

  function finishLoginResponse(rsp: any) {
    if (rsp.code !== 0) {
      let errorMsg = t('auth.error');
      if (rsp.code === -2) errorMsg = t('auth.invalidUser');
      else if (rsp.code === -5) errorMsg = t('auth.locked');
      else if (rsp.code === -4) errorMsg = t('auth.globalLocked');

      setMsg(errorMsg);
      return false;
    }

    setMsg('');
    if (rsp.data.csrfToken) {
      setCsrfToken(rsp.data.csrfToken, rsp.data.expiresAt);
    }

    navigate('/', { replace: true });
    window.location.reload();
    return true;
  }

  function login(values: any) {
    if (isLoading) return;
    setIsloading(true);

    const username = values.username;
    const password = encrypt(values.password);

    api
      .login(username, password)
      .then((rsp: any) => {
        finishLoginResponse(rsp);
      })
      .catch(() => {
        setMsg(t('auth.error'));
      })
      .finally(() => {
        setIsloading(false);
      });
  }

  function setup(values: any) {
    if (isLoading) return;
    if (values.password !== values.password2) {
      setMsg(t('auth.differentPassword'));
      return;
    }
    if (!validateString(values.username)) {
      setMsg(t('auth.illegalUsername'));
      return;
    }
    if (values.password.length < 8 || !validateString(values.password)) {
      setMsg(t('auth.illegalPassword'));
      return;
    }

    setIsloading(true);

    const username = values.username;
    const password = encrypt(values.password);

    api
      .setupFirstAccount(username, password)
      .then((rsp: any) => {
        if (rsp.code !== 0) {
          setMsg(rsp.msg || t('auth.error'));
          return undefined;
        }
        return api.login(username, password);
      })
      .then((rsp: any) => {
        if (!rsp) return;
        finishLoginResponse(rsp);
      })
      .catch(() => {
        setMsg(t('auth.error'));
      })
      .finally(() => {
        setIsloading(false);
      });
  }

  function validateString(str: string) {
    const regex = /['"\\/]/;
    return !regex.test(str);
  }

  const isSetup = setupRequired === true;
  const isCheckingSetup = setupRequired === null;

  return (
    <>
      <Head title={isSetup ? t('head.firstSetup') : t('head.login')} />

      <div className="flex h-screen w-screen flex-col items-center justify-center">
        <Form
          key={isSetup ? 'setup' : 'login'}
          style={{ minWidth: 300, maxWidth: 500 }}
          initialValues={isSetup ? { username: 'admin' } : { remember: true }}
          onFinish={isSetup ? setup : login}
        >
          <div className="flex flex-col items-center justify-center pb-5">
            <div
              className="flex h-[96px] w-[260px] cursor-pointer items-center justify-center overflow-hidden rounded bg-white shadow-lg"
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
                className="h-full w-full object-contain"
              />
            </div>
            <div className="mt-3 text-lg font-semibold text-neutral-100">{HARDENED_NAME}</div>
            <div className="mt-1 text-xs text-neutral-500">{displayVersion}</div>
          </div>
          {isSetup && (
            <div className="mb-5 flex flex-col gap-2 text-center">
              <h1 className="text-lg font-semibold text-neutral-100">{t('auth.setupTitle')}</h1>
              <p className="m-0 text-sm text-neutral-400">{t('auth.setupDescription')}</p>
              <p className="m-0 text-xs text-red-400">{t('auth.setupRecovery')}</p>
            </div>
          )}
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
          {isSetup && (
            <Form.Item
              name="password2"
              rules={[{ required: true, message: t('auth.noEmptyPassword'), min: 1 }]}
            >
              <Input
                prefix={<LockOutlined />}
                type="password"
                placeholder={t('auth.placeholderPassword2')}
              />
            </Form.Item>
          )}

          <div className="pb-1 text-red-500">{msg}</div>

          <Form.Item>
            <Button
              type="primary"
              htmlType="submit"
              className="w-full"
              loading={isLoading || isCheckingSetup}
              disabled={isCheckingSetup}
            >
              {isSetup ? t('auth.setupButtonText') : t('auth.loginButtonText')}
            </Button>
          </Form.Item>

          {!isSetup && (
            <div className="flex justify-end pb-4 text-sm">
              <Tips />
            </div>
          )}
        </Form>
      </div>
    </>
  );
};
