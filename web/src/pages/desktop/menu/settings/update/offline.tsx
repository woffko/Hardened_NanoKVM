import { useRef } from 'react';
import { Button } from 'antd';
import { ExternalLinkIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as api from '@/api/application.ts';
import { removeToken } from '@/lib/cookie.ts';
import { DEFAULT_RECONNECT, probeHealth, waitForBackendRestart } from '@/lib/reconnect.ts';

import { appUpdateMessage, followAppUpdate } from './job.ts';
import { pickOfflinePackage } from './package.ts';
import type { OfflinePackage } from './package.ts';

interface UpdateProps {
  status: string;
  setStatus: (status: string) => void;
  setIsLocked: (isClosable: boolean) => void;
  setErrMsg: (msg: string) => void;
}

export const Offline = ({ status, setStatus, setIsLocked, setErrMsg }: UpdateProps) => {
  const { t } = useTranslation();

  const inputRef = useRef<HTMLInputElement | null>(null);

  function handleClick() {
    inputRef.current?.click();
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const selected = pickOfflinePackage(Array.from(e.target.files ?? []));
    // Choosing the same files again after a refusal must fire this again.
    e.target.value = '';
    if (status === 'loading' || status === 'updating' || status === 'restarting') {
      return;
    }
    if (!selected) {
      setStatus('failed');
      setErrMsg(t('settings.update.offline.invalidPackage'));
      return;
    }

    upload(selected);
  }

  function upload(selected: OfflinePackage) {
    setIsLocked(true);
    setStatus('updating');
    setErrMsg('');

    const formData = new FormData();
    formData.append('metadata', selected.metadata);
    formData.append('signature', selected.signature);
    formData.append('file', selected.file);

    api
      .offlineUpdate(formData)
      .then(async (rsp: Response) => {
        if (rsp.ok) {
          return rsp.json();
        }
        // An answer means the device did not restart for this upload.
        const answer = await rsp.json().catch(() => null);
        const csrf = rsp.status === 403 && /csrf/i.test(String(answer?.msg));
        if (rsp.status === 401 || csrf) {
          removeToken();
          window.location.reload();
        }
        return { code: rsp.status, msg: answer?.msg };
      })
      .then((rspj: any) => {
        if (rspj.code !== 0 || !rspj.data?.transactionId) {
          setStatus('failed');
          setErrMsg(rspj.msg || t('settings.update.offline.updateFailed'));
          setIsLocked(false);
          return;
        }
        return followAppUpdate(rspj.data.transactionId).then((outcome) => {
          setIsLocked(false);
          const message = appUpdateMessage(outcome, 'settings.update.offline.updateFailed');
          if (message) {
            setStatus('failed');
            setErrMsg(t(message));
            return;
          }
          window.location.reload();
        });
      })
      .catch(async () => {
        // No reply: the device may already be restarting for the update, and
        // without its transaction nothing here can say how that ended.
        setStatus('restarting');
        const outcome = await waitForBackendRestart(() => probeHealth(), DEFAULT_RECONNECT);
        setStatus('failed');
        setErrMsg(
          t(outcome === 'back' ? 'settings.update.outcomeUnknown' : 'settings.update.unreachable')
        );
        setIsLocked(false);
      });
  }

  return (
    <>
      <div className="mt-8 flex items-center justify-between">
        <div className="flex flex-col space-y-1">
          <div className="flex items-center space-x-2">
            <span>{t('settings.update.offline.title')}</span>

            <a
              className="flex items-center text-neutral-500 hover:text-blue-500"
              href="https://github.com/woffko/Hardened_NanoKVM/releases"
              target="_blank"
            >
              <ExternalLinkIcon size={15} />
            </a>
          </div>

          <span className="text-xs text-neutral-500">
            {t('settings.update.offline.signedDesc')}
          </span>
        </div>

        <input
          id="file-upload"
          ref={inputRef}
          type="file"
          multiple
          onChange={handleFileChange}
          className="hidden"
        />
        <Button onClick={handleClick}>{t('settings.update.offline.upload')}</Button>
      </div>
    </>
  );
};
