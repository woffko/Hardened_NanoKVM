import { useEffect, useState } from 'react';
import { Button, message, Modal, Switch } from 'antd';
import { useTranslation } from 'react-i18next';

import { statusImage } from '@/api/download.ts';
import { getHidMode, getUsbWakeup, setUsbWakeup } from '@/api/hid.ts';
import { getMountedImage } from '@/api/storage.ts';
import * as api from '@/api/virtual-device.ts';
import { notifyImageListChanged } from '@/lib/image-events.ts';

export const VirtualDevices = () => {
  const { t } = useTranslation();
  const [messageApi, messageContext] = message.useMessage();

  const [isHidOnlyMode, setIsHidOnlyMode] = useState(false);
  const [isUsbWakeupEnabled, setIsUsbWakeupEnabled] = useState(false);
  const [isDiskEnabled, setIsDiskEnabled] = useState(false);
  const [isNetworkEnabled, setIsNetworkEnabled] = useState(false);
  const [isImageMounted, setIsImageMounted] = useState(false);
  const [isConfirmOpen, setIsConfirmOpen] = useState(false);
  const [loading, setLoading] = useState<'' | 'disk' | 'network' | 'wakeup'>('');

  useEffect(() => {
    getHidOnlyMode();
    getVirtualDevice();
    getWakeup();
    getImageState();
  }, []);

  async function getHidOnlyMode() {
    try {
      const rsp = await getHidMode();
      if (rsp.code !== 0) {
        console.log(rsp.msg);
        return;
      }
      setIsHidOnlyMode(rsp.data.mode === 'hid-only');
    } catch (err) {
      console.log(err);
    }
  }

  async function getVirtualDevice() {
    try {
      const rsp = await api.getVirtualDevice();
      if (rsp.code !== 0) {
        console.log(rsp.msg);
        return;
      }

      setIsDiskEnabled(rsp.data.disk);
      setIsNetworkEnabled(rsp.data.network);
    } catch (err) {
      console.log(err);
    }
  }

  async function getImageState() {
    try {
      const rsp = await getMountedImage();
      if (rsp.code !== 0) {
        console.log(rsp.msg);
        return;
      }

      setIsImageMounted(!!rsp.data?.file);
    } catch (err) {
      console.log(err);
    }
  }

  async function getWakeup() {
    try {
      const rsp = await getUsbWakeup();
      if (rsp.code !== 0) {
        console.log(rsp.msg);
        return;
      }
      setIsUsbWakeupEnabled(rsp.data.enabled);
    } catch (err) {
      console.log(err);
    }
  }

  async function update(device: 'disk' | 'network') {
    if (loading) return;
    setLoading(device);

    try {
      const rsp = await api.updateVirtualDevice(device);
      if (rsp.code !== 0) {
        console.log(rsp.msg);
        messageApi.error(rsp.msg);
        return;
      }

      await getVirtualDevice();
      await getImageState();

      // the desktop shows the mounted image and the CD-ROM flag too
      notifyImageListChanged();
    } catch (err) {
      console.log(err);
    } finally {
      setLoading('');
    }
  }

  // enabling the disk hands /data to the host and takes it away from the
  // mounted image, and a running transfer would be cut short
  async function toggleDisk() {
    if (isDiskEnabled) {
      await update('disk');
      return;
    }

    try {
      const rsp = await statusImage();
      if (rsp.code === 0 && rsp.data?.status === 'in_progress') {
        messageApi.warning(t('settings.device.diskTransferRunning'));
        return;
      }
    } catch (err) {
      console.log(err);
    }

    if (isImageMounted) {
      setIsConfirmOpen(true);
      return;
    }

    await update('disk');
  }

  async function updateWakeup(enabled: boolean) {
    if (loading) return;
    setLoading('wakeup');

    try {
      const rsp = await setUsbWakeup(enabled);
      if (rsp.code !== 0) {
        console.log(rsp.msg);
        return;
      }
      setIsUsbWakeupEnabled(rsp.data.enabled);
    } catch (err) {
      console.log(err);
    } finally {
      setLoading('');
    }
  }

  const usbWakeup = (
    <div className="flex items-center justify-between">
      <div className="flex flex-col space-y-1">
        <span>{t('settings.device.usbWakeup')}</span>
        <span className="text-xs text-neutral-500">{t('settings.device.usbWakeupDesc')}</span>
      </div>

      <Switch checked={isUsbWakeupEnabled} loading={loading === 'wakeup'} onChange={updateWakeup} />
    </div>
  );

  if (isHidOnlyMode) {
    return (
      <>
        <div className="flex items-center justify-between space-x-10">
          <div className="flex flex-col space-y-1">
            <span>{t('settings.device.hidOnly')}</span>
            <span className="text-xs text-neutral-500">{t('settings.device.hidOnlyDesc')}</span>
          </div>

          <Switch checked={true} disabled={true} />
        </div>
        {usbWakeup}
      </>
    );
  }

  return (
    <>
      {messageContext}
      {/* Virtual Disk */}
      <div className="flex items-center justify-between">
        <div className="flex flex-col space-y-1">
          <span>{t('settings.device.disk')}</span>
          <span className="text-xs text-neutral-500">
            {isImageMounted ? t('settings.device.diskLocked') : t('settings.device.diskDesc')}
          </span>
        </div>

        <Switch checked={isDiskEnabled} loading={loading === 'disk'} onChange={toggleDisk} />
      </div>

      <Modal
        title={t('image.attention')}
        open={isConfirmOpen}
        width={520}
        footer={null}
        onCancel={() => setIsConfirmOpen(false)}
      >
        <div className="flex flex-col items-center space-y-1 pb-10">
          <p>{t('settings.device.diskCancelMount')}</p>
        </div>

        <div className="flex justify-center space-x-3 pb-3">
          <Button
            type="primary"
            loading={loading === 'disk'}
            onClick={async () => {
              setIsConfirmOpen(false);
              await update('disk');
            }}
          >
            {t('settings.device.okBtn')}
          </Button>
          <Button onClick={() => setIsConfirmOpen(false)}>{t('settings.device.cancelBtn')}</Button>
        </div>
      </Modal>

      {/* Virtual Network */}
      <div className="flex items-center justify-between">
        <div className="flex flex-col space-y-1">
          <span>{t('settings.device.network')}</span>
          <span className="text-xs text-neutral-500">{t('settings.device.networkDesc')}</span>
        </div>

        <Switch
          checked={isNetworkEnabled}
          loading={loading === 'network'}
          onChange={() => update('network')}
        />
      </div>

      {usbWakeup}
    </>
  );
};
