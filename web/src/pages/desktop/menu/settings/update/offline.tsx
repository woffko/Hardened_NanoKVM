import { useRef } from 'react';
import { Button } from 'antd';
import { ExternalLinkIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as api from '@/api/application.ts';
import { DEFAULT_RECONNECT, probeHealth, waitForBackendRestart } from '@/lib/reconnect.ts';

import { followAppUpdate } from './job.ts';

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
    const file = e.target.files?.[0];
    if (!file) {
      return;
    }

    if (!validateFilename(file.name)) {
      setStatus('failed');
      setErrMsg(t('settings.update.offline.invalidName'));
      return;
    }

    upload(file);
  }

  function upload(file: File | null) {
    if (!file) return;

    if (!validateFilename(file.name)) {
      setStatus('failed');
      setErrMsg(t('settings.update.offline.invalidName'));
      return;
    }

    if (status === 'loading' || status === 'updating' || status === 'restarting') {
      return;
    }

    setIsLocked(true);
    setStatus('updating');
    setErrMsg('');

    const formData = new FormData();
    formData.append('file', file);

    api
      .offlineUpdate(formData)
      .then((rsp: Response) => {
        if (!rsp.ok) throw new Error(`HTTP error ${rsp.status}`);
        return rsp.json();
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
          if (outcome === 'rolled-back') {
            setStatus('failed');
            setErrMsg(t('settings.update.offline.updateFailed'));
            return;
          }
          window.location.reload();
        });
      })
      .catch(async () => {
        // No reply: the device may already be restarting for the update.
        setStatus('restarting');
        const outcome = await waitForBackendRestart(() => probeHealth(), DEFAULT_RECONNECT);
        if (outcome === 'back') {
          window.location.reload();
          return;
        }
        setStatus('failed');
        setErrMsg(t('settings.update.unreachable'));
        setIsLocked(false);
      });
  }

  function validateFilename(filename: string) {
    const regex: RegExp =
      /^(nanokvm_\d+\.\d+\.\d+|hardened-nanokvm-kvmapp-\d+\.\d+\.\d+)\.tar\.gz$/;
    return regex.test(filename);
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

          <span className="text-xs text-neutral-500">{t('settings.update.offline.desc')}</span>
        </div>

        <input
          id="file-upload"
          ref={inputRef}
          type="file"
          onChange={handleFileChange}
          className="hidden"
        />
        <Button onClick={handleClick}>{t('settings.update.offline.upload')}</Button>
      </div>
    </>
  );
};
