import { useEffect, useState } from 'react';
import { Modal, Switch } from 'antd';
import { useAtom } from 'jotai';
import {
  DiscIcon,
  DownloadIcon,
  FileJsonIcon,
  MaximizeIcon,
  NetworkIcon,
  PowerIcon,
  TerminalSquareIcon,
  XIcon
} from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as vmApi from '@/api/vm.ts';
import * as ls from '@/lib/localstorage.ts';
import { menuDisabledItemsAtom } from '@/jotai/settings.ts';
import { Robot } from '@/components/icons/robot.tsx';

export const MenuIcons = () => {
  const { t } = useTranslation();

  const [menuDisabledItems, setMenuDisabledItems] = useAtom(menuDisabledItemsAtom);
  const [isTerminalWarningOpen, setIsTerminalWarningOpen] = useState(false);
  const [isTerminalLoading, setIsTerminalLoading] = useState(false);

  const items = [
    { key: 'image', icon: <DiscIcon size={16} /> },
    { key: 'download', icon: <DownloadIcon size={16} /> },
    { key: 'terminal', icon: <TerminalSquareIcon size={16} /> },
    { key: 'script', icon: <FileJsonIcon size={16} /> },
    { key: 'wol', icon: <NetworkIcon size={16} /> },
    { key: 'picoclaw', icon: <Robot size={16} /> },
    { key: 'power', icon: <PowerIcon size={16} /> },
    { key: 'fullscreen', icon: <MaximizeIcon size={16} />, label: 'fullscreen.toggle' },
    { key: 'collapse', icon: <XIcon size={16} />, label: 'menu.collapse' }
  ];

  useEffect(() => {
    vmApi.getTerminalEnabled().then((rsp) => {
      if (rsp.code !== 0 || typeof rsp.data?.enabled !== 'boolean') return;
      setItemVisible('terminal', rsp.data.enabled);
    });
  }, []);

  function saveItems(newItems: string[]) {
    setMenuDisabledItems(newItems);
    ls.setMenuDisabledItems(newItems);
  }

  function setItemVisible(key: string, visible: boolean) {
    const newItems = visible
      ? menuDisabledItems.filter((item) => item !== key)
      : Array.from(new Set([...menuDisabledItems, key]));

    saveItems(newItems);
  }

  function updateItems(key: string) {
    const enabled = !menuDisabledItems.includes(key);
    const nextEnabled = !enabled;

    if (key === 'terminal') {
      if (nextEnabled) {
        setIsTerminalWarningOpen(true);
      } else {
        updateTerminal(false);
      }
      return;
    }

    setItemVisible(key, nextEnabled);
  }

  function updateTerminal(enabled: boolean) {
    if (isTerminalLoading) return;
    setIsTerminalLoading(true);

    vmApi
      .setTerminalEnabled(enabled)
      .then((rsp) => {
        if (rsp.code !== 0) return;
        setItemVisible('terminal', enabled);
        setIsTerminalWarningOpen(false);
      })
      .finally(() => setIsTerminalLoading(false));
  }

  return (
    <>
      <div className="mt-8 flex flex-col space-y-5">
        <div className="flex flex-col">
          <span className="text-neutral-400">{t('settings.appearance.menuBar.icons')}</span>
          <span className="text-xs text-neutral-500">
            {t('settings.appearance.menuBar.iconsDesc')}
          </span>
        </div>

        <div className="mt-5 flex flex-col space-y-5">
          {items.map((item) => (
            <div key={item.key} className="flex items-center justify-between">
              <div className="flex items-center space-x-2 text-neutral-400">
                {item.icon}
                <span className="text-neutral-300">
                  {item.label ? t(item.label) : t(`${item.key}.title`)}
                </span>
              </div>

              <Switch
                checked={!menuDisabledItems.includes(item.key)}
                loading={item.key === 'terminal' && isTerminalLoading}
                onChange={() => updateItems(item.key)}
              />
            </div>
          ))}
        </div>
      </div>

      <Modal
        title={t('settings.appearance.menuBar.terminalWarningTitle')}
        open={isTerminalWarningOpen}
        centered={true}
        okType="danger"
        okText={t('settings.appearance.menuBar.terminalWarningConfirm')}
        cancelText={t('settings.appearance.menuBar.terminalWarningCancel')}
        onOk={() => updateTerminal(true)}
        onCancel={() => setIsTerminalWarningOpen(false)}
        confirmLoading={isTerminalLoading}
      >
        <div className="py-4 text-neutral-300">
          {t('settings.appearance.menuBar.terminalWarningDesc')}
        </div>
      </Modal>
    </>
  );
};
