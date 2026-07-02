import { ChangeEvent, useEffect, useRef, useState } from 'react';
import { Button, Divider, Input } from 'antd';
import type { InputRef } from 'antd';
import clsx from 'clsx';
import { useSetAtom } from 'jotai';
import { DownloadIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { downloadImage, imageEnabled, statusImage } from '@/api/download.ts';
import { getCsrfToken } from '@/lib/cookie.ts';
import { notifyImageListChanged } from '@/lib/image-events.ts';
import { isKeyboardEnableAtom } from '@/jotai/keyboard.ts';
import { MenuItem } from '@/components/menu-item.tsx';

type TransferKind = 'local' | 'remote';

export const DownloadImage = () => {
  const { t } = useTranslation();
  const setIsKeyboardEnable = useSetAtom(isKeyboardEnableAtom);

  const [input, setInput] = useState('');
  const [status, setStatus] = useState('');
  const [log, setLog] = useState('');
  const [diskEnabled, setDiskEnabled] = useState(false);
  const [remoteEnabled, setRemoteEnabled] = useState(false);
  const [popoverKey, setPopoverKey] = useState(0);

  const inputRef = useRef<InputRef>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const statusRef = useRef('');
  const activeTransferRef = useRef<TransferKind | null>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const intervalId = useRef<ReturnType<typeof setInterval> | undefined>(undefined);

  useEffect(() => {
    checkDiskEnabled();
  }, []);

  function setDownloadStatus(nextStatus: string) {
    statusRef.current = nextStatus;
    setStatus(nextStatus);
  }

  function stopStatusPolling() {
    if (!intervalId.current) return;

    clearInterval(intervalId.current);
    intervalId.current = undefined;
  }

  function startStatusPolling() {
    if (intervalId.current) return;

    intervalId.current = setInterval(getDownloadStatus, 2500);
  }

  function clearFileInput() {
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  }

  function checkDiskEnabled() {
    imageEnabled()
      .then((res) => {
        setDiskEnabled(res.data.enabled);
        setRemoteEnabled(res.data.remoteEnabled === true);
      })
      .catch(() => {
        setDiskEnabled(false);
        setRemoteEnabled(false);
      });
  }

  function handleOpenChange(open: boolean) {
    if (open) {
      stopStatusPolling();
      checkDiskEnabled();
      getDownloadStatus();
      startStatusPolling();
      setIsKeyboardEnable(false);
      setPopoverKey((prevKey) => prevKey + 1); // Force re-render
    } else {
      setInput('');
      setDownloadStatus('');
      setLog('');
      setSelectedFile(null);
      setIsDragging(false);
      activeTransferRef.current = null;
      clearFileInput();

      setIsKeyboardEnable(true);
      stopStatusPolling();
    }
  }

  function handleChange(e: ChangeEvent<HTMLInputElement>) {
    setInput(e.target.value);
    if (statusRef.current === 'complete') {
      setDownloadStatus('idle');
      setLog('');
    }
  }

  function getDownloadStatus() {
    statusImage().then((rsp) => {
      if (rsp.code !== 0 || !rsp.data?.status) {
        return;
      }

      const nextStatus = rsp.data.status;
      if (nextStatus === 'in_progress') {
        setDownloadStatus(nextStatus);
        // Check if rsp has a percentage value
        if (rsp.data.percentage) {
          setLog('Downloading (' + rsp.data.percentage + ')' + ': ' + rsp.data.file);
        } else {
          setLog('Downloading' + ': ' + rsp.data.file);
        }
        if (activeTransferRef.current === 'remote') {
          setInput(rsp.data.file);
        }
        return;
      }

      if (nextStatus === 'failed') {
        setDownloadStatus(nextStatus);
        setLog('Failed');
        activeTransferRef.current = null;
        stopStatusPolling();
        return;
      }

      if (nextStatus === 'idle') {
        const previousStatus = statusRef.current;
        const previousTransfer = activeTransferRef.current;
        activeTransferRef.current = null;
        stopStatusPolling();

        if (previousStatus === 'complete') {
          return;
        }

        if (previousStatus === 'in_progress' && previousTransfer === 'remote') {
          setInput('');
          setDownloadStatus('complete');
          setLog(t('download.complete'));
          notifyImageListChanged();
          return;
        }

        setDownloadStatus('idle');
        setLog(''); // Clear the log
      }
    });
  }

  function download(url?: string) {
    const targetUrl = url?.trim();
    if (!targetUrl) return;
    if (!remoteEnabled) {
      setDownloadStatus('failed');
      setLog(t('download.remoteDisabled'));
      return;
    }

    activeTransferRef.current = 'remote';
    setDownloadStatus('in_progress');
    setLog('Downloading: ' + targetUrl);
    // start the getDownloadStatus to tick every 5 seconds

    downloadImage(targetUrl)
      .then((rsp) => {
        if (rsp.code !== 0) {
          activeTransferRef.current = null;
          setDownloadStatus('failed');
          setLog(rsp.msg || t('download.remoteFailed'));
          return;
        }
        getDownloadStatus();
        // Start the interval to check the download status
        startStatusPolling();
      })
      .catch(() => {
        stopStatusPolling(); // Clear the interval when the download is complete or fails
        activeTransferRef.current = null;
        setDownloadStatus('failed');
        setLog('Failed');
      });
  }

  function selectLocalFile(file: File | null) {
    if (!file || !file.name.toLowerCase().endsWith('.iso')) {
      setDownloadStatus('failed');
      setLog(t('download.NoISO'));
      setSelectedFile(null);
      clearFileInput();
      return;
    }
    setDownloadStatus('idle');
    setLog('');
    setSelectedFile(file);
    activeTransferRef.current = null;
    stopStatusPolling();
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0] ?? null;
    selectLocalFile(file);
  }

  async function upload(file: File | null) {
    if (!file) return;

    if (!file || !file.name.toLowerCase().endsWith('.iso')) {
      setDownloadStatus('failed');
      setLog(t('download.NoISO'));
      return;
    }

    activeTransferRef.current = 'local';
    setDownloadStatus('in_progress');
    setLog('Downloading: ' + file.name);

    const formData = new FormData();
    formData.append('file', file);

    const csrfToken = getCsrfToken();

    try {
      const uploadRequest = fetch('/api/download/file', {
        method: 'POST',
        headers: csrfToken ? { 'x-csrf-token': csrfToken } : undefined,
        body: formData
      });
      startStatusPolling();
      const response = await uploadRequest;
      const body = await response.json().catch(() => null);

      if (!response.ok || body?.code !== 0) {
        throw new Error(body?.msg || 'Failed');
      }

      stopStatusPolling();
      activeTransferRef.current = null;
      setDownloadStatus('complete');
      setLog(t('download.complete'));
      setSelectedFile(null);
      clearFileInput();
      notifyImageListChanged();
    } catch (error) {
      stopStatusPolling(); // Clear the interval when the download is complete or fails
      activeTransferRef.current = null;
      setDownloadStatus('failed');
      setLog(error instanceof Error && error.message ? error.message : 'Failed');
    }
  }

  const content = (
    <div key={popoverKey} className="min-w-[300px]">
      <div className="flex items-center justify-between px-1">
        <span className="text-base font-bold text-neutral-300">{t('download.title')}</span>
      </div>

      <Divider style={{ margin: '10px 0 10px 0' }} />

      {!diskEnabled ? (
        <div className="text-red-500">{t('download.disabled')}</div>
      ) : (
        <>
          <div>
            <div className="pb-1 text-neutral-500">{t('download.input')}</div>
            <div className="flex items-center space-x-1">
              <Input
                ref={inputRef}
                value={input}
                onChange={handleChange}
                disabled={status === 'in_progress' || !remoteEnabled}
              />
              <Button
                type="primary"
                onClick={() => download(input)}
                disabled={status === 'in_progress' || status === 'complete' || !remoteEnabled || !input.trim()}
              >
                {t('download.ok')}
              </Button>
            </div>
            {!remoteEnabled && (
              <div className="pt-1 text-xs text-neutral-500">{t('download.remoteDisabled')}</div>
            )}
          </div>
          <div>
            <div className="pb-1 text-neutral-500">{t('download.inputfile')}</div>
            <div className="flex items-center space-x-1">
              <div
                className={clsx(
                  'css-9118ya ant-input-outlined flex h-10 w-full flex-col items-center justify-center rounded-xl border-2 border-solid transition',
                  isDragging ? 'border-blue-500 bg-neutral-500' : '',
                  status === 'in_progress'
                    ? 'pointer-events-none cursor-not-allowed border-neutral-600 bg-neutral-700 opacity-50'
                    : 'cursor-pointer hover:bg-neutral-500'
                )}
                onDrop={(e) => {
                  if (status === 'in_progress') return; // deaktiviert
                  e.preventDefault();
                  setIsDragging(false);
                  const file = e.dataTransfer.files?.[0] ?? null;
                  selectLocalFile(file);
                }}
                onDragOver={(e) => {
                  if (status === 'in_progress') return; // deaktiviert
                  e.preventDefault();
                  setIsDragging(true); // Datei wird über den Bereich gezogen
                }}
                onDragLeave={(e) => {
                  if (status === 'in_progress') return; // deaktiviert
                  e.preventDefault();
                  setIsDragging(false); // Maus verlässt Bereich
                }}
                onClick={() => {
                  if (status === 'in_progress') return; // deaktiviert
                  fileInputRef.current?.click();
                }}
              >
                <span className="p-1 text-sm text-neutral-100">
                  {selectedFile ? selectedFile.name : t('download.uploadbox')}
                </span>

                <input
                  id="file-upload"
                  ref={fileInputRef}
                  type="file"
                  accept=".iso"
                  onChange={handleFileChange}
                  disabled={status === 'in_progress'}
                  className="hidden"
                />
              </div>
              <Button
                type="primary"
                className="h-10 border-2"
                onClick={() => upload(selectedFile)}
                disabled={status === 'in_progress' || status === 'complete' || !selectedFile}
              >
                {t('download.ok')}
              </Button>
            </div>
          </div>
        </>
      )}
      <div className={clsx('py-2')}>
        {status && log && (
          <div
            className={clsx(
              'max-w-[300px] break-words text-sm',
              status === 'failed' ? 'text-red-500' : 'text-green-500'
            )}
          >
            {log}
          </div>
        )}
      </div>
    </div>
  );

  return (
    <MenuItem
      title={t('download.title')}
      icon={<DownloadIcon size={18} />}
      content={content}
      onOpenChange={handleOpenChange}
    />
  );
};
