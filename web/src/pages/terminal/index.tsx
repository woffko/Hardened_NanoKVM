import { useEffect, useRef, useState } from 'react';
import { LockOutlined, UserOutlined } from '@ant-design/icons';
import { AttachAddon } from '@xterm/addon-attach';
import { FitAddon } from '@xterm/addon-fit';
import { Terminal as XtermTerminal } from '@xterm/xterm';
import { Button, Form, Input } from 'antd';
import { useTranslation } from 'react-i18next';

import '@xterm/xterm/css/xterm.css';

import * as authApi from '@/api/auth.ts';
import * as vmApi from '@/api/vm.ts';
import { encrypt } from '@/lib/encrypt.ts';
import { getBaseUrl } from '@/lib/service.ts';
import { Head } from '@/components/head.tsx';

import { buildPicocomCommand } from './validater.ts';

export const Terminal = () => {
  const { t } = useTranslation();
  const [form] = Form.useForm();
  const [ticket, setTicket] = useState('');
  const [isUnlocking, setIsUnlocking] = useState(false);
  const [msg, setMsg] = useState('');
  const [pendingCommand, setPendingCommand] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const picocomRunningRef = useRef(false);

  useEffect(() => {
    authApi.getAccount().then((rsp) => {
      if (rsp.code === 0 && rsp.data?.username) {
        form.setFieldsValue({ username: rsp.data.username });
      }
    });
  }, [form]);

  useEffect(() => {
    if (!ticket) return;

    const terminalEle = document.getElementById('terminal');
    if (!terminalEle) return;

    const terminal = new XtermTerminal({
      cursorBlink: true
    });

    const fitAddon = new FitAddon();
    terminal.loadAddon(fitAddon);
    terminal.open(terminalEle);
    fitAddon.fit();

    const url = `${getBaseUrl('ws')}/api/vm/terminal?ticket=${encodeURIComponent(ticket)}`;
    const ws = new WebSocket(url);
    wsRef.current = ws;
    let isDisposed = false;

    ws.onopen = () => {
      const attachAddon = new AttachAddon(ws);
      terminal.loadAddon(attachAddon);

      sendSize();
      setTimeout(runPicocom, 300);
    };

    ws.onclose = () => {
      if (isDisposed) return;
      setMsg(t('terminal.sessionClosed'));
      setTicket('');
      setPendingCommand(null);
      picocomRunningRef.current = false;
      wsRef.current = null;
    };

    ws.onerror = () => {
      if (isDisposed) return;
      setMsg(t('terminal.sessionError'));
      setTicket('');
      setPendingCommand(null);
      picocomRunningRef.current = false;
      wsRef.current = null;
    };

    const sendSize = () => {
      if (ws.readyState !== WebSocket.OPEN) return;
      const windowSize = { rows: terminal.rows, cols: terminal.cols };
      const blob = new Blob([JSON.stringify(windowSize)], { type: 'application/json' });
      ws.send(blob);
    };

    const runPicocom = () => {
      const urls = window.location.href.split('?');
      if (urls.length < 2) return;

      const searchParams = new URLSearchParams(urls[1]);
      const port = searchParams.get('port');
      const baud = searchParams.get('baud');
      const parity = searchParams.get('parity');
      const flowControl = searchParams.get('flowControl');
      const dataBits = searchParams.get('dataBits');
      const stopBits = searchParams.get('stopBits');
      if (!port || !baud) return;

      const command = buildPicocomCommand({ port, baud, parity, flowControl, dataBits, stopBits });
      if (!command) {
        return;
      }

      setPendingCommand(command);
    };

    const exitPicocom = () => {
      if (ws.readyState === WebSocket.OPEN && picocomRunningRef.current) {
        ws.send('\x01\x18');
        picocomRunningRef.current = false;
      }
    };

    const resizeScreen = () => {
      fitAddon.fit();
      sendSize();
    };

    const cleanupConnection = () => {
      exitPicocom();
      setTimeout(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.close();
        }
      }, 100);
    };

    const handleBeforeUnload = () => {
      cleanupConnection();
    };

    window.addEventListener('resize', resizeScreen, false);
    window.addEventListener('beforeunload', handleBeforeUnload);

    return () => {
      isDisposed = true;
      wsRef.current = null;
      picocomRunningRef.current = false;
      setPendingCommand(null);
      terminal.dispose();
      cleanupConnection();

      window.removeEventListener('resize', resizeScreen, false);
      window.removeEventListener('beforeunload', handleBeforeUnload);
    };
  }, [ticket, t]);

  const confirmPicocom = () => {
    const ws = wsRef.current;
    const command = pendingCommand;
    if (!ws || ws.readyState !== WebSocket.OPEN || !command) return;
    ws.send(`${command}\r`);
    picocomRunningRef.current = true;
    setPendingCommand(null);
  };

  const cancelPicocom = () => {
    setPendingCommand(null);
  };

  function unlock(values: any) {
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

        setTicket(rsp.data.ticket);
      })
      .catch((err) => {
        setMsg(err?.response?.data?.msg || t('terminal.unlockFailed'));
      })
      .finally(() => {
        setIsUnlocking(false);
      });
  }

  return (
    <>
      <Head title={t('head.terminal')} />

      <div className="h-full w-full overflow-hidden">
        {ticket ? (
          <div className="relative h-full w-full overflow-hidden">
            <div id="terminal" className="h-full p-2"></div>
            {pendingCommand && (
              <div className="absolute inset-0 z-10 flex items-center justify-center bg-black/70 px-4">
                <div className="w-full max-w-[560px] rounded border border-neutral-700 bg-neutral-900 p-4">
                  <div className="mb-2 text-sm text-neutral-200">Run serial command?</div>
                  <pre className="mb-4 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-black/40 p-3 text-xs text-neutral-200">{pendingCommand}</pre>
                  <div className="flex justify-end gap-2">
                    <Button onClick={cancelPicocom}>Cancel</Button>
                    <Button type="primary" onClick={confirmPicocom}>
                      {t('terminal.confirm')}
                    </Button>
                  </div>
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="flex h-full w-full items-center justify-center px-4">
            <Form
              form={form}
              className="w-full max-w-[360px]"
              initialValues={{ username: 'admin' }}
              onFinish={unlock}
            >
              <div className="mb-5 text-center">
                <h1 className="mb-2 text-lg font-semibold text-neutral-100">
                  {t('terminal.unlockTitle')}
                </h1>
                <p className="m-0 text-sm text-neutral-400">{t('terminal.unlockDesc')}</p>
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
                <Input.Password
                  prefix={<LockOutlined />}
                  placeholder={t('auth.placeholderPassword')}
                />
              </Form.Item>

              <div className="min-h-6 pb-1 text-sm text-red-500">{msg}</div>

              <Button type="primary" htmlType="submit" className="w-full" loading={isUnlocking}>
                {t('terminal.unlock')}
              </Button>
            </Form>
          </div>
        )}
      </div>
    </>
  );
};
