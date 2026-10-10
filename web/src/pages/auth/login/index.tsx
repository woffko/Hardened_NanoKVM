import { ReactElement, useEffect, useRef, useState, type MouseEvent } from 'react';
import { KeyOutlined, LockOutlined, UserOutlined } from '@ant-design/icons';
import { Button, Form, Input } from 'antd';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import { getCurrentVersion } from '@/api/application.ts';
import * as totpApi from '@/api/auth-totp.ts';
import * as api from '@/api/auth.ts';
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
  const [totpRequired, setTotpRequired] = useState(false);
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [displayVersion, setDisplayVersion] = useState(HARDENED_VERSION);
  const [logoPressed, setLogoPressed] = useState(false);
  const logoTimerRef = useRef<number | null>(null);

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

  useEffect(() => {
    return () => {
      if (logoTimerRef.current) {
        window.clearTimeout(logoTimerRef.current);
      }
    };
  }, []);

  function finishLoginResponse(rsp: any) {
    if (rsp.code !== 0) {
      let errorMsg = t('auth.error');
      if (rsp.code === -2) errorMsg = t('auth.invalidUser');
      else if (rsp.code === -5) errorMsg = t('auth.locked');
      else if (rsp.code === -4) errorMsg = t('auth.globalLocked');

      setMsg(errorMsg);
      return false;
    }

    // The password was accepted but no session was issued: a second factor
    // is still needed. The pending ticket travels in an HttpOnly cookie, so
    // there is nothing to keep here beyond switching the form over.
    if (rsp.data?.totpRequired) {
      setMsg('');
      setTotpRequired(true);
      return false;
    }

    setMsg('');
    if (rsp.data.csrfToken) {
      setCsrfToken(rsp.data.csrfToken, rsp.data.expiresAt);
    }

    // Policy requires a second factor this account has not enrolled. Login is
    // allowed through so the device cannot lock itself out, and enrolment is
    // the first thing the user sees.
    const target = rsp.data?.totpEnrollmentRequired ? '/auth/totp' : '/';
    navigate(target, { replace: true });
    window.location.reload();
    return true;
  }

  function submitTotp(values: any) {
    if (isLoading) return;
    setIsloading(true);

    totpApi
      .loginTotp(values.code)
      .then((rsp: any) => {
        // -2 is a wrong or spent code, not a wrong password. -1 carries the
        // backend's reason, e.g. that the device clock is not synchronized.
        if (rsp.code === -2) {
          setMsg(t('auth.totp.invalidCode'));
          return;
        }
        if (rsp.code === -1 && typeof rsp.msg === 'string' && rsp.msg) {
          setMsg(rsp.msg);
          return;
        }
        finishLoginResponse(rsp);
      })
      .catch((err) => {
        const detail = err?.response?.data?.msg;
        setMsg(typeof detail === 'string' && detail ? detail : t('auth.totp.invalidCode'));
      })
      .finally(() => {
        setIsloading(false);
      });
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

  function restartLogin() {
    setTotpRequired(false);
    setUseBackupCode(false);
    setMsg('');
  }

  function validateString(str: string) {
    const regex = /['"\\/]/;
    return !regex.test(str);
  }

  function pressLogo(evt: MouseEvent<HTMLDivElement>) {
    evt.preventDefault();
    if (logoTimerRef.current) {
      window.clearTimeout(logoTimerRef.current);
    }

    setLogoPressed(false);
    window.requestAnimationFrame(() => {
      setLogoPressed(true);
      logoTimerRef.current = window.setTimeout(() => {
        setLogoPressed(false);
        logoTimerRef.current = null;
      }, 700);
    });
  }

  // Three mutually exclusive modes: first-run setup, password, second factor.
  const isSetup = setupRequired === true && !totpRequired;
  const isCheckingSetup = setupRequired === null;
  const formMode = totpRequired ? 'totp' : isSetup ? 'setup' : 'login';

  return (
    <>
      <Head title={isSetup ? t('head.firstSetup') : t('head.login')} />

      <div className="flex h-screen w-screen flex-col items-center justify-center">
        <Form
          key={formMode}
          style={{ minWidth: 300, maxWidth: 500 }}
          initialValues={isSetup ? { username: 'admin' } : { remember: true }}
          onFinish={totpRequired ? submitTotp : isSetup ? setup : login}
        >
          <div className="flex flex-col items-center justify-center pb-5">
            <div
              className={`hardened-login-logo flex h-[96px] w-[260px] cursor-pointer items-center justify-center overflow-hidden rounded bg-white shadow-lg ${
                logoPressed ? 'hardened-login-logo--active' : ''
              }`}
              onClick={pressLogo}
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
          {totpRequired && (
            <div className="mb-5 flex flex-col gap-2 text-center">
              <h1 className="text-lg font-semibold text-neutral-100">
                {t('auth.totp.title', { defaultValue: 'Two-factor authentication' })}
              </h1>
              <p className="m-0 text-sm text-neutral-400">
                {useBackupCode
                  ? t('auth.totp.backupPrompt', {
                      defaultValue: 'Enter one of your backup codes.'
                    })
                  : t('auth.totp.prompt', {
                      defaultValue: 'Enter the 6-digit code from your authenticator app.'
                    })}
              </p>
            </div>
          )}

          {!totpRequired && (
            <>
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
            </>
          )}

          {totpRequired && (
            <Form.Item
              name="code"
              rules={[
                {
                  required: true,
                  message: t('auth.totp.noEmptyCode', { defaultValue: 'Enter a code' }),
                  min: 1
                }
              ]}
            >
              <Input
                prefix={<KeyOutlined />}
                autoFocus
                autoComplete="one-time-code"
                inputMode={useBackupCode ? 'text' : 'numeric'}
                placeholder={
                  useBackupCode
                    ? t('auth.totp.placeholderBackup', { defaultValue: 'Backup code' })
                    : t('auth.totp.placeholderCode', { defaultValue: '6-digit code' })
                }
              />
            </Form.Item>
          )}
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

          {msg && <div className="mb-3 text-red-500">{msg}</div>}

          <Form.Item>
            <Button
              type="primary"
              htmlType="submit"
              className="w-full"
              loading={isLoading || isCheckingSetup}
              disabled={isCheckingSetup}
            >
              {totpRequired
                ? t('auth.totp.verifyButtonText', { defaultValue: 'Verify' })
                : isSetup
                  ? t('auth.setupButtonText')
                  : t('auth.loginButtonText')}
            </Button>
          </Form.Item>

          {totpRequired && (
            <div className="flex justify-between pb-4 text-sm">
              <Button type="link" className="px-0" onClick={() => setUseBackupCode(!useBackupCode)}>
                {useBackupCode
                  ? t('auth.totp.useAuthenticator', { defaultValue: 'Use authenticator code' })
                  : t('auth.totp.useBackupCode', { defaultValue: 'Use a backup code' })}
              </Button>
              <Button type="link" className="px-0" onClick={restartLogin}>
                {t('auth.totp.cancel', { defaultValue: 'Back' })}
              </Button>
            </div>
          )}

          {!isSetup && !totpRequired && (
            <div className="flex justify-end pb-4 text-sm">
              <Tips />
            </div>
          )}
        </Form>
      </div>
    </>
  );
};
