import { useEffect, useState } from 'react';
import { Button, Divider, Modal, Switch, Typography } from 'antd';
import { useTranslation } from 'react-i18next';

import { getHidMode, getUsbWakeup, setHidMode, setUsbWakeup } from '@/api/hid.ts';
import * as api from '@/api/virtual-device.ts';

const { Paragraph } = Typography;

export const VirtualDevices = () => {
  const { t } = useTranslation();

  const [isHidOnlyMode, setIsHidOnlyMode] = useState(false);
  const [isUsbWakeupEnabled, setIsUsbWakeupEnabled] = useState(false);
  const [isDiskEnabled, setIsDiskEnabled] = useState(false);
  const [isNetworkEnabled, setIsNetworkEnabled] = useState(false);
  const [loading, setLoading] = useState<'' | 'disk' | 'network' | 'wakeup' | 'hid'>('');
  const [isHidModalOpen, setIsHidModalOpen] = useState(false);
  const [hidErrMsg, setHidErrMsg] = useState('');

  useEffect(() => {
    getHidOnlyMode();
    getVirtualDevice();
    getWakeup();
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
        return;
      }

      await getVirtualDevice();
    } catch (err) {
      console.log(err);
    } finally {
      setLoading('');
    }
  }

  // the device reboots to apply the mode, so the page reloads once it is back
  function updateHidMode() {
    if (loading) return;
    setLoading('hid');
    setHidErrMsg('');

    const timeoutId = setTimeout(() => {
      window.location.reload();
    }, 30000);

    setHidMode(isHidOnlyMode ? 'normal' : 'hid-only')
      .then((rsp) => {
        if (rsp.code !== 0) {
          setHidErrMsg(rsp.msg);
          setLoading('');
          clearTimeout(timeoutId);
        }
      })
      .catch((err) => {
        console.log(err);
        setLoading('');
        clearTimeout(timeoutId);
      });
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

  const hidOnly = (
    <>
      <div className="flex items-center justify-between space-x-10">
        <div className="flex flex-col space-y-1">
          <span>{t('settings.device.hidOnly')}</span>
          <span className="text-xs text-neutral-500">{t('settings.device.hidOnlyDesc')}</span>
        </div>

        <Switch
          checked={isHidOnlyMode}
          loading={loading === 'hid'}
          onChange={() => setIsHidModalOpen(true)}
        />
      </div>

      <Modal
        open={isHidModalOpen}
        title={t('mouse.hidOnly.title')}
        width={580}
        centered={false}
        footer={false}
        onCancel={() => setIsHidModalOpen(false)}
      >
        <Divider />

        <Paragraph>{t('mouse.hidOnly.desc')}</Paragraph>

        <Paragraph type="secondary">
          <ul>
            <li>{t('mouse.hidOnly.tip1')}</li>
            <li>{t('mouse.hidOnly.tip2')}</li>
            <li>{t('mouse.hidOnly.tip3')}</li>
          </ul>
        </Paragraph>

        {hidErrMsg && <div className="pt-1 text-sm text-red-500">{hidErrMsg}</div>}

        <div className="flex justify-center pt-5">
          <Button
            danger
            type="primary"
            loading={loading === 'hid'}
            onClick={() => {
              setIsHidModalOpen(false);
              updateHidMode();
            }}
          >
            {isHidOnlyMode ? t('mouse.hidOnly.disable') : t('mouse.hidOnly.enable')}
          </Button>
        </div>
      </Modal>
    </>
  );

  if (isHidOnlyMode) {
    return (
      <>
        {hidOnly}
        {usbWakeup}
      </>
    );
  }

  return (
    <>
      {hidOnly}

      {/* Virtual Disk */}
      <div className="flex items-center justify-between">
        <div className="flex flex-col space-y-1">
          <span>{t('settings.device.disk')}</span>
          <span className="text-xs text-neutral-500">{t('settings.device.diskDesc')}</span>
        </div>

        <Switch
          checked={isDiskEnabled}
          loading={loading === 'disk'}
          onChange={() => update('disk')}
        />
      </div>

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
