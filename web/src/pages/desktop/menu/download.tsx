import { ChangeEvent, useEffect, useRef, useState } from 'react';
import { Button, Divider, Input, notification } from 'antd';
import type { InputRef } from 'antd';
import clsx from 'clsx';
import { useSetAtom } from 'jotai';
import { DownloadIcon, XCircleIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import { downloadImage, imageEnabled, statusImage } from '@/api/download.ts';
import { getMountedImage } from '@/api/storage.ts';
import { getVirtualDevice, updateVirtualDevice } from '@/api/virtual-device.ts';
import { getCsrfToken } from '@/lib/cookie.ts';
import { notifyImageListChanged } from '@/lib/image-events.ts';
import { isKeyboardEnableAtom } from '@/jotai/keyboard.ts';
import { MenuItem } from '@/components/menu-item.tsx';

type TransferKind = 'local' | 'remote';
type TransferStatus = '' | 'idle' | 'in_progress' | 'complete' | 'failed' | 'canceled';
type AbortReason = 'cancel' | 'stall';

const TRANSFER_STALL_TIMEOUT_MS = 90_000;

function isAllowedLocalImage(file: File | null) {
  if (!file) return false;
  const name = file.name.toLowerCase();
  return name.endsWith('.iso') || name.endsWith('.img');
}

export const DownloadImage = () => {
  const { t } = useTranslation();
  const [notify, contextHolder] = notification.useNotification();
  const setIsKeyboardEnable = useSetAtom(isKeyboardEnableAtom);

  const [input, setInput] = useState('');
  const [sha256sum, setSha256sum] = useState('');
  const [status, setStatus] = useState<TransferStatus>('');
  const [log, setLog] = useState('');
  const [diskEnabled, setDiskEnabled] = useState(false);
  const [remoteEnabled, setRemoteEnabled] = useState(false);
  const [isDiskShared, setIsDiskShared] = useState(false);
  const [isDisablingDisk, setIsDisablingDisk] = useState(false);
  const [popoverKey, setPopoverKey] = useState(0);
  const [activeTransfer, setActiveTransfer] = useState<TransferKind | null>(null);

  const inputRef = useRef<InputRef>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const statusRef = useRef<TransferStatus>('');
  const activeTransferRef = useRef<TransferKind | null>(null);
  const uploadXhrRef = useRef<XMLHttpRequest | null>(null);
  const abortReasonRef = useRef<AbortReason | null>(null);
  const lastProgressMarkerRef = useRef('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);

  const intervalId = useRef<ReturnType<typeof setInterval> | undefined>(undefined);
  const stallTimeoutId = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  useEffect(() => {
    checkDiskEnabled();
    return () => {
      stopStatusPolling();
      stopStallWatchdog();
    };
  }, []);

  function setDownloadStatus(nextStatus: TransferStatus) {
    statusRef.current = nextStatus;
    setStatus(nextStatus);
  }

  function setActiveTransferKind(nextTransfer: TransferKind | null) {
    activeTransferRef.current = nextTransfer;
    setActiveTransfer(nextTransfer);
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

  function stopStallWatchdog() {
    if (!stallTimeoutId.current) return;

    clearTimeout(stallTimeoutId.current);
    stallTimeoutId.current = undefined;
  }

  function resetStallWatchdog() {
    stopStallWatchdog();
    if (statusRef.current !== 'in_progress') return;

    stallTimeoutId.current = setTimeout(() => {
      if (statusRef.current !== 'in_progress') return;

      abortReasonRef.current = 'stall';
      uploadXhrRef.current?.abort();
      failTransfer(t('download.stalled'));
    }, TRANSFER_STALL_TIMEOUT_MS);
  }

  function noteProgress(marker: string) {
    if (!marker || marker === lastProgressMarkerRef.current) return;

    lastProgressMarkerRef.current = marker;
    resetStallWatchdog();
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

    // /data is read-only while the virtual disk serves it to the host
    getVirtualDevice()
      .then((res) => {
        setIsDiskShared(!!res.data?.disk);
      })
      .catch(() => {
        setIsDiskShared(false);
      });
  }

  // hand /data back to the KVM, which makes the download possible again
  function disableDisk() {
    if (isDisablingDisk) return;
    setIsDisablingDisk(true);

    updateVirtualDevice('disk')
      .then((rsp) => {
        if (rsp.code !== 0) {
          console.log(rsp.msg);
          return;
        }

        checkDiskEnabled();
      })
      .finally(() => {
        setIsDisablingDisk(false);
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
      if (statusRef.current !== 'in_progress') {
        setInput('');
        setSha256sum('');
        setDownloadStatus('');
        setLog('');
        setSelectedFile(null);
        setActiveTransferKind(null);
        stopStatusPolling();
        stopStallWatchdog();
        clearFileInput();
      }
      setIsDragging(false);

      setIsKeyboardEnable(true);
    }
  }

  function handleChange(e: ChangeEvent<HTMLInputElement>) {
    setInput(e.target.value);
    if (statusRef.current === 'complete') {
      setDownloadStatus('idle');
      setLog('');
    }
  }

  function handleSha256Change(e: ChangeEvent<HTMLInputElement>) {
    setSha256sum(e.target.value);
    if (statusRef.current === 'complete') {
      setDownloadStatus('idle');
      setLog('');
    }
  }

  // empty means no check; null means the entered value is not a SHA-256
  function getValidatedSHA256() {
    const checksum = sha256sum.trim();
    if (checksum && !/^[a-fA-F0-9]{64}$/.test(checksum)) {
      setDownloadStatus('failed');
      setLog(t('download.invalidSHA256'));
      return null;
    }

    return checksum;
  }

  function getDownloadStatus() {
    statusImage().then((rsp) => {
      if (rsp.code !== 0 || !rsp.data?.status) {
        return;
      }

      const nextStatus = rsp.data.status;
      if (nextStatus === 'in_progress') {
        setDownloadStatus(nextStatus);
        const transfer = activeTransferRef.current ?? 'remote';
        setLog(formatTransferLog(transfer, rsp.data.file, rsp.data.percentage));
        noteProgress(`${rsp.data.file};${rsp.data.percentage}`);
        if (activeTransferRef.current === 'remote') {
          setInput(rsp.data.file);
        }
        return;
      }

      if (nextStatus === 'failed') {
        failTransfer(t('download.failed'));
        return;
      }

      if (nextStatus === 'checksum_failed') {
        failTransfer(t('download.checksumFailed'));
        return;
      }

      if (nextStatus === 'idle') {
        const previousStatus = statusRef.current;
        const previousTransfer = activeTransferRef.current;
        setActiveTransferKind(null);
        stopStatusPolling();
        stopStallWatchdog();

        if (previousStatus === 'complete') {
          return;
        }

        if (previousStatus === 'in_progress' && previousTransfer === 'remote') {
          setInput('');
          setSha256sum('');
          setDownloadStatus('complete');
          setLog(t('download.complete'));
          notifyImageListChanged();
          return;
        }

        if (previousStatus === 'in_progress' && previousTransfer === 'local') {
          setDownloadStatus('complete');
          setLog(t('download.uploadComplete'));
          setSelectedFile(null);
          setSha256sum('');
          clearFileInput();
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

    const checksum = getValidatedSHA256();
    if (checksum === null) return;

    setActiveTransferKind('remote');
    lastProgressMarkerRef.current = '';
    setDownloadStatus('in_progress');
    setLog(formatTransferLog('remote', targetUrl));
    noteProgress(targetUrl);
    // start the getDownloadStatus to tick every 5 seconds

    downloadImage(targetUrl, checksum)
      .then((rsp) => {
        if (rsp.code !== 0) {
          failTransfer(rsp.msg || t('download.remoteFailed'));
          return;
        }
        getDownloadStatus();
        // Start the interval to check the download status
        startStatusPolling();
      })
      .catch(() => {
        failTransfer(t('download.remoteFailed'));
      });
  }

  function selectLocalFile(file: File | null) {
    if (!isAllowedLocalImage(file)) {
      setDownloadStatus('failed');
      setLog(t('download.NoISO'));
      setSelectedFile(null);
      clearFileInput();
      return;
    }
    setDownloadStatus('idle');
    setLog('');
    setSelectedFile(file);
    setActiveTransferKind(null);
    stopStatusPolling();
    stopStallWatchdog();
  }

  function handleFileChange(e: ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0] ?? null;
    selectLocalFile(file);
  }

  async function mountedImageName() {
    try {
      const rsp = await getMountedImage();
      return rsp.code === 0 ? String(rsp.data?.file ?? '').replace(/^.*[\\/]/, '') : '';
    } catch {
      return '';
    }
  }

  async function upload(file: File | null) {
    if (!file) return;

    if (!isAllowedLocalImage(file)) {
      setDownloadStatus('failed');
      setLog(t('download.NoISO'));
      return;
    }

    const checksum = getValidatedSHA256();
    if (checksum === null) return;

    // The server refuses to replace a mounted image, but only after the browser has started
    // sending the file, and the browser then reports a bare network error.
    if ((await mountedImageName()) === file.name) {
      setDownloadStatus('failed');
      setLog(t('download.mountedImage'));
      return;
    }

    setActiveTransferKind('local');
    lastProgressMarkerRef.current = '';
    setDownloadStatus('in_progress');
    setLog(formatTransferLog('local', file.name));
    noteProgress(file.name);

    const formData = new FormData();
    formData.append('file', file);
    startStatusPolling();
    resetStallWatchdog();

    try {
      await uploadFileWithProgress(file, formData, checksum);

      stopStatusPolling();
      stopStallWatchdog();
      setActiveTransferKind(null);
      setDownloadStatus('complete');
      setLog(t('download.uploadComplete'));
      setSelectedFile(null);
      setSha256sum('');
      clearFileInput();
      notifyImageListChanged();
    } catch (error) {
      if (isAbortError(error)) {
        if (abortReasonRef.current === 'stall') {
          abortReasonRef.current = null;
          return;
        }
        abortReasonRef.current = null;
        finishCanceled();
        return;
      }

      failTransfer(error instanceof Error && error.message ? error.message : t('download.failed'));
    }
  }

  function uploadFileWithProgress(file: File, formData: FormData, checksum: string) {
    const csrfToken = getCsrfToken();

    return new Promise<void>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      uploadXhrRef.current = xhr;
      xhr.open('POST', '/api/download/file');
      xhr.withCredentials = true;
      if (csrfToken) {
        xhr.setRequestHeader('x-csrf-token', csrfToken);
      }
      if (checksum) {
        xhr.setRequestHeader('X-SHA256-Sum', checksum);
      }

      xhr.upload.onprogress = (event) => {
        if (event.lengthComputable && event.total > 0) {
          const percentage = `${((event.loaded / event.total) * 100).toFixed(2)}%`;
          setLog(formatTransferLog('local', file.name, percentage));
          noteProgress(`${event.loaded}/${event.total}`);
        } else {
          setLog(formatTransferLog('local', file.name));
          noteProgress(`${event.loaded}`);
        }
      };

      xhr.onload = () => {
        uploadXhrRef.current = null;
        const body = parseJson(xhr.responseText);
        if (xhr.status >= 200 && xhr.status < 300 && body?.code === 0) {
          resolve();
          return;
        }
        const message = body?.msg === 'sha256 mismatch' ? t('download.checksumFailed') : body?.msg;
        reject(new Error(message || t('download.uploadFailed')));
      };

      xhr.onerror = () => {
        uploadXhrRef.current = null;
        reject(new Error(t('download.uploadFailed')));
      };
      xhr.ontimeout = () => {
        uploadXhrRef.current = null;
        reject(new Error(t('download.stalled')));
      };
      xhr.onabort = () => {
        uploadXhrRef.current = null;
        reject(new DOMException('upload canceled', 'AbortError'));
      };

      xhr.send(formData);
    });
  }

  function cancelTransfer() {
    if (statusRef.current !== 'in_progress' || activeTransferRef.current !== 'local') return;

    abortReasonRef.current = 'cancel';
    uploadXhrRef.current?.abort();
  }

  function failTransfer(message: string) {
    stopStatusPolling();
    stopStallWatchdog();
    setActiveTransferKind(null);
    uploadXhrRef.current = null;
    setDownloadStatus('failed');
    setLog(message);
    notify.error({
      message: t('download.failed'),
      description: message,
      duration: 10
    });
  }

  function finishCanceled() {
    stopStatusPolling();
    stopStallWatchdog();
    setActiveTransferKind(null);
    setDownloadStatus('canceled');
    setLog(t('download.canceled'));
  }

  function formatTransferLog(transfer: TransferKind, file: string, percentage?: string) {
    const label = transfer === 'local' ? t('download.uploading') : t('download.downloading');
    const progress = percentage ? ` (${percentage})` : '';
    return `${label}${progress}: ${file}`;
  }

  function parseJson(raw: string): { code?: number; msg?: string } | null {
    try {
      return JSON.parse(raw);
    } catch {
      return null;
    }
  }

  function isAbortError(error: unknown) {
    return error instanceof DOMException && error.name === 'AbortError';
  }

  const content = (
    <div key={popoverKey} className="min-w-[300px]">
      <div className="flex items-center justify-between px-1">
        <span className="text-base font-bold text-neutral-300">{t('download.title')}</span>
      </div>

      <Divider style={{ margin: '10px 0 10px 0' }} />

      {!diskEnabled ? (
        isDiskShared ? (
          <div className="space-y-3">
            <div className="text-neutral-300">{t('download.diskShared')}</div>
            <Button type="primary" block loading={isDisablingDisk} onClick={disableDisk}>
              {t('download.diskOff')}
            </Button>
          </div>
        ) : (
          <div className="max-w-[300px] text-red-500">{t('download.disabled')}</div>
        )
      ) : (
        <div className="space-y-3">
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
                disabled={
                  status === 'in_progress' ||
                  status === 'complete' ||
                  !remoteEnabled ||
                  !input.trim()
                }
              >
                {t('download.ok')}
              </Button>
            </div>
            {!remoteEnabled && (
              <div className="pt-1 text-xs text-neutral-500">{t('download.remoteDisabled')}</div>
            )}
          </div>
          <div>
            <div className="pb-1 text-neutral-500">{t('download.sha256')}</div>
            <Input
              value={sha256sum}
              onChange={handleSha256Change}
              disabled={status === 'in_progress'}
              maxLength={64}
              placeholder={t('download.sha256Placeholder')}
            />
          </div>
          <div>
            <div className="pb-1 text-neutral-500">{t('download.inputfile')}</div>
            <div className="flex items-center space-x-1">
              <div
                className={clsx(
                  'css-9118ya ant-input-outlined box-border flex h-8 w-full flex-col items-center justify-center rounded-xl border-2 border-solid transition',
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
                <span className="px-1 text-sm text-neutral-100">
                  {selectedFile ? selectedFile.name : t('download.uploadbox')}
                </span>

                <input
                  id="file-upload"
                  ref={fileInputRef}
                  type="file"
                  accept=".iso,.img"
                  onChange={handleFileChange}
                  disabled={status === 'in_progress'}
                  className="hidden"
                />
              </div>
              <Button
                type="primary"
                className="border-2"
                onClick={() => upload(selectedFile)}
                disabled={status === 'in_progress' || status === 'complete' || !selectedFile}
              >
                {t('download.ok')}
              </Button>
              {status === 'in_progress' && activeTransfer === 'local' && (
                <Button danger icon={<XCircleIcon size={14} />} onClick={cancelTransfer}>
                  {t('download.cancel')}
                </Button>
              )}
            </div>
          </div>
        </div>
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
    <>
      {contextHolder}
      <MenuItem
        title={t('download.title')}
        icon={<DownloadIcon size={18} />}
        content={content}
        onOpenChange={handleOpenChange}
      />
    </>
  );
};
