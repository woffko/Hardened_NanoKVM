import { useCallback, useEffect, useState } from 'react';
import { Modal, Tooltip } from 'antd';
import { useAtomValue } from 'jotai';
import { CheckIcon, TvMinimalPlayIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as downloadApi from '@/api/download.ts';
import * as firewallApi from '@/api/system-firewall.ts';
import { setVideoMode as setCookie } from '@/lib/localstorage.ts';
import { videoModeAtom } from '@/jotai/screen.ts';
import { MenuSubmenu } from '@/components/menu-submenu.tsx';

const videoModes = [
  { key: 'direct', name: 'H.264 (Direct)' },
  { key: 'h264', name: 'H.264 (WebRTC)' },
  { key: 'mjpeg', name: 'MJPEG' }
];

export const VideoMode = () => {
  const { t } = useTranslation();
  const videoMode = useAtomValue(videoModeAtom);

  const [isDirectSupported, setIsDirectSupported] = useState<boolean | null>(null);
  const [isWebrtcBlocked, setIsWebrtcBlocked] = useState(false);

  const refreshFirewallStatus = useCallback(() => {
    firewallApi
      .getStatus()
      .then((rsp) => {
        if (rsp.code !== 0 || !rsp.data) return;
        const firewall = rsp.data;
        setIsWebrtcBlocked(
          firewall.webrtcBlocked ||
            firewall.restrictedActive ||
            firewall.paranoidActive ||
            firewall.effectiveMode === 'restricted' ||
            firewall.effectiveMode === 'paranoid'
        );
      })
      .catch(() => undefined);
  }, []);

  useEffect(() => {
    const isHttps = window.location.protocol === 'https:';
    const isDecoderSupported = !!window.VideoDecoder;

    setIsDirectSupported(isHttps && isDecoderSupported);
  }, []);

  useEffect(() => {
    refreshFirewallStatus();
  }, [refreshFirewallStatus]);

  useEffect(() => {
    function refreshIfVisible() {
      if (!document.hidden) {
        refreshFirewallStatus();
      }
    }

    window.addEventListener('focus', refreshFirewallStatus);
    document.addEventListener('visibilitychange', refreshIfVisible);

    return () => {
      window.removeEventListener('focus', refreshFirewallStatus);
      document.removeEventListener('visibilitychange', refreshIfVisible);
    };
  }, [refreshFirewallStatus]);

  useEffect(() => {
    if (!isWebrtcBlocked || videoMode !== 'h264' || isDirectSupported === null) return;

    setCookie(isDirectSupported ? 'direct' : 'mjpeg');
    setTimeout(() => {
      window.location.reload();
    }, 250);
  }, [isDirectSupported, isWebrtcBlocked, videoMode]);

  async function isTransferRunning() {
    try {
      const rsp = await downloadApi.statusImage();
      return rsp.code === 0 && rsp.data?.status === 'in_progress';
    } catch {
      return false;
    }
  }

  function applyMode(mode: string) {
    setCookie(mode);

    // reload after changing video mode
    setTimeout(() => {
      window.location.reload();
    }, 500);
  }

  async function update(mode: string) {
    if (mode === videoMode) return;
    if (mode === 'h264' && isWebrtcBlocked) return;

    // The reload below would cancel a running image upload or download.
    if (await isTransferRunning()) {
      Modal.confirm({
        title: t('screen.transferRunningTitle'),
        content: t('screen.transferRunningDesc'),
        okText: t('screen.transferRunningOk'),
        onOk: () => applyMode(mode)
      });
      return;
    }

    applyMode(mode);
  }

  const content = (
    <>
      {!isDirectSupported && (
        <Tooltip
          title={t('screen.videoDirectTips')}
          placement="right"
          styles={{ root: { maxWidth: '270px' } }}
        >
          <div className="flex cursor-not-allowed select-none items-center rounded py-1.5 pl-1 pr-5 text-neutral-500 hover:bg-neutral-700/70">
            <div className="flex h-[14px] w-[20px] items-end text-blue-500"></div>
            <span>H.264 (Direct)</span>
          </div>
        </Tooltip>
      )}

      {videoModes.map(
        (mode) =>
          (isDirectSupported || mode.key !== 'direct') && (
            <Tooltip
              key={mode.key}
              title={
                mode.key === 'h264' && isWebrtcBlocked
                  ? t('screen.videoWebrtcBlockedByFirewall')
                  : undefined
              }
              placement="right"
              styles={{ root: { maxWidth: '270px' } }}
            >
              <div
                className={
                  mode.key === 'h264' && isWebrtcBlocked
                    ? 'flex cursor-not-allowed select-none items-center rounded py-1.5 pl-1 pr-5 text-neutral-500 hover:bg-neutral-700/70'
                    : 'flex cursor-pointer select-none items-center rounded py-1.5 pl-1 pr-5 hover:bg-neutral-700/70'
                }
                onClick={() => update(mode.key)}
              >
                <div className="flex h-[14px] w-[20px] items-end text-blue-500">
                  {mode.key === videoMode && <CheckIcon size={15} />}
                </div>
                <span>{mode.name}</span>
              </div>
            </Tooltip>
          )
      )}
    </>
  );

  return (
    <MenuSubmenu
      icon={<TvMinimalPlayIcon size={18} />}
      label={t('screen.video')}
      content={content}
      onOpenChange={(open) => {
        if (open) refreshFirewallStatus();
      }}
    />
  );
};
