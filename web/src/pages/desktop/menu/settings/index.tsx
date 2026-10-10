import { useEffect, useRef, useState } from 'react';
import { Badge, Modal, Tooltip } from 'antd';
import clsx from 'clsx';
import { useSetAtom } from 'jotai';
import {
  BadgeInfoIcon,
  CircleArrowUpIcon,
  PaletteIcon,
  ServerCogIcon,
  SettingsIcon,
  SmartphoneIcon,
  UserRoundIcon
} from 'lucide-react';
import { useTranslation } from 'react-i18next';
import semver from 'semver';

import * as api from '@/api/application.ts';
import * as ls from '@/lib/localstorage.ts';
import { isKeyboardEnableAtom } from '@/jotai/keyboard.ts';
import { submenuOpenCountAtom } from '@/jotai/settings.ts';
import { Tailscale as TailscaleIcon } from '@/components/icons/tailscale';
import { ScrollArea } from '@/components/ui/scroll-area';
import { useIsTouchLayout } from '@/hooks/useResponsiveLayout.ts';

import { About } from './about';
import { Account } from './account';
import { Appearance } from './appearance';
import { Device } from './device';
import { System } from './system';
import { Tailscale } from './tailscale';
import { Update } from './update';

export const Settings = () => {
  const { t } = useTranslation();

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isLocked, setIsLocked] = useState(false);
  const [currentTab, setCurrentTab] = useState('about');
  const scrollViewportRef = useRef<HTMLDivElement>(null);
  const isTouchLayout = useIsTouchLayout();

  const [isUpdateAvailable, setIsUpdateAvailable] = useState(false);
  const setIsKeyboardEnable = useSetAtom(isKeyboardEnableAtom);
  const setSubmenuOpenCount = useSetAtom(submenuOpenCountAtom);

  const tabs = [
    { id: 'about', icon: <BadgeInfoIcon size={16} />, component: <About /> },
    { id: 'appearance', icon: <PaletteIcon size={16} />, component: <Appearance /> },
    { id: 'device', icon: <SmartphoneIcon size={16} />, component: <Device /> },
    { id: 'system', icon: <ServerCogIcon size={16} />, component: <System /> },
    {
      id: 'tailscale',
      icon: <TailscaleIcon />,
      component: <Tailscale setIsLocked={setIsLocked} />
    },
    {
      id: 'update',
      icon: <CircleArrowUpIcon size={16} />,
      component: <Update setIsLocked={setIsLocked} />
    },
    {
      id: 'account',
      icon: <UserRoundIcon size={18} />,
      component: <Account setIsLocked={setIsLocked} />
    }
  ];

  useEffect(() => {
    const skip = ls.getSkipUpdate();
    if (!skip) {
      checkForUpdates();
    }
  }, []);

  useEffect(() => {
    scrollViewportRef.current?.scrollTo({ top: 0, left: 0 });
  }, [currentTab]);

  function checkForUpdates() {
    api.getVersion().then((rsp: any) => {
      if (rsp.code !== 0) {
        return;
      }
      if (!rsp.data?.current || !rsp.data?.latest) {
        return;
      }

      if (semver.gt(rsp.data.latest, rsp.data.current)) {
        setIsUpdateAvailable(true);
      }
    });
  }

  function changeTab(tab: string) {
    if (isLocked) {
      return;
    }

    setCurrentTab(tab);

    if (isUpdateAvailable && tab === 'update') {
      setIsUpdateAvailable(false);
      ls.setSkipUpdate(true);
    }
  }

  function openModal() {
    setIsModalOpen(true);
    setIsKeyboardEnable(false);
    setSubmenuOpenCount((count) => count + 1);
  }

  function closeModal() {
    if (isLocked) {
      return;
    }

    setIsKeyboardEnable(true);
    setIsModalOpen(false);
    setCurrentTab('about');
    setSubmenuOpenCount((count) => Math.max(0, count - 1));
  }

  return (
    <>
      <Tooltip
        title={isTouchLayout ? undefined : t('settings.title')}
        placement="bottom"
        mouseEnterDelay={0.6}
        open={isTouchLayout ? false : undefined}
      >
        <div
          className="flex h-[30px] w-[30px] cursor-pointer items-center justify-center rounded hover:bg-neutral-700/80"
          onClick={openModal}
        >
          <Badge dot={isUpdateAvailable} color="blue" offset={[0, 2]}>
            <div className="pt-[3px] text-neutral-300 hover:text-white">
              <SettingsIcon size={18} />
            </div>
          </Badge>
        </div>
      </Tooltip>

      <Modal
        open={isModalOpen}
        width={isTouchLayout ? '100vw' : '80%'}
        centered={!isTouchLayout}
        footer={null}
        destroyOnHidden={true}
        onCancel={closeModal}
        className={isTouchLayout ? 'settings-modal-mobile' : undefined}
        style={
          isTouchLayout
            ? { maxWidth: 'none', margin: 0, paddingBottom: 0, top: 0 }
            : { maxWidth: '1080px' }
        }
        styles={{
          content: {
            padding: 0,
            ...(isTouchLayout ? { height: '100dvh', overflow: 'hidden', borderRadius: 0 } : {})
          },
          body: isTouchLayout ? { height: '100%' } : undefined
        }}
      >
        <div
          className={clsx(
            'outline outline-1 outline-neutral-700',
            isTouchLayout
              ? 'flex h-[100dvh] w-full max-w-[100vw] flex-col overflow-hidden rounded-none'
              : 'flex h-[80vh] max-h-[700px] rounded-lg'
          )}
        >
          <div
            className={clsx(
              isTouchLayout
                ? 'shrink-0 border-b border-neutral-700 bg-neutral-900/95 pt-[env(safe-area-inset-top)]'
                : 'flex h-full max-w-[260px] flex-col space-y-0.5 rounded-l-lg bg-neutral-800/90 px-1 sm:w-1/5 md:w-1/4 md:px-2'
            )}
          >
            <div
              className={clsx(
                isTouchLayout
                  ? 'flex min-h-11 items-center px-3 pr-12 text-base'
                  : 'hidden px-3 pt-10 text-xl sm:block'
              )}
            >
              {t('settings.title')}
            </div>
            {!isTouchLayout && <div className="h-10 sm:h-5" />}
            <div
              className={clsx(
                isTouchLayout
                  ? 'settings-mobile-tabs flex gap-1 overflow-x-auto px-2 pb-2'
                  : 'contents'
              )}
            >
              {tabs.map((tab) => (
                <div
                  key={tab.id}
                  className={clsx(
                    'cursor-pointer select-none rounded-lg',
                    isTouchLayout
                      ? 'flex min-w-[72px] flex-col items-center justify-center px-2 py-2'
                      : 'flex items-center space-x-2 p-2 sm:px-3',
                    currentTab === tab.id ? 'bg-neutral-700/50' : 'hover:bg-neutral-700/50'
                  )}
                  onClick={() => changeTab(tab.id)}
                >
                  <div className="flex h-[16px] w-[16px] items-center justify-center">
                    {tab.icon}
                  </div>

                  {isUpdateAvailable && tab.id === 'update' ? (
                    <Badge dot color="blue" offset={[6, 3]}>
                      <span
                        className={clsx(
                          isTouchLayout
                            ? 'mt-1 block max-w-[68px] truncate text-[11px] leading-tight'
                            : 'hidden truncate text-sm sm:block'
                        )}
                      >
                        {t(`settings.${tab.id}.title`)}
                      </span>
                    </Badge>
                  ) : (
                    <span
                      className={clsx(
                        isTouchLayout
                          ? 'mt-1 block max-w-[68px] truncate text-[11px] leading-tight'
                          : 'hidden truncate text-sm sm:block'
                      )}
                    >
                      {t(`settings.${tab.id}.title`)}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>

          <ScrollArea
            viewportRef={scrollViewportRef}
            className={clsx(
              'w-full max-w-full overflow-x-hidden bg-neutral-900/50 [&_[data-slot=scroll-area-scrollbar]]:w-1.5 [&_[data-slot=scroll-area-scrollbar]]:p-0 [&_[data-slot=scroll-area-thumb]]:bg-neutral-500/30',
              isTouchLayout ? 'min-h-0 flex-1 rounded-none pl-3 pr-8' : 'h-full rounded-r-lg px-3'
            )}
          >
            <div className="flex h-full w-full min-w-0 justify-center">
              <div
                className={clsx(
                  'min-w-0',
                  isTouchLayout ? 'w-full max-w-[calc(100vw-44px)]' : 'w-full max-w-[600px]',
                  isTouchLayout
                    ? 'pb-[calc(env(safe-area-inset-bottom)+1rem)] pt-4'
                    : 'pb-10 pt-14'
                )}
              >
                <>{tabs.find((tab) => tab.id === currentTab)?.component}</>
              </div>
            </div>
          </ScrollArea>
        </div>
      </Modal>
    </>
  );
};
