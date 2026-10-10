import { useEffect } from 'react';
import { Divider } from 'antd';
import { useSetAtom } from 'jotai';
import { MouseIcon } from 'lucide-react';
import { useTranslation } from 'react-i18next';

import * as ls from '@/lib/localstorage';
import {
  mouseModeAtom,
  mouseStyleAtom,
  pointerSensitivityAtom,
  scrollDirectionAtom,
  scrollIntervalAtom
} from '@/jotai/mouse';
import { MenuItem } from '@/components/menu-item.tsx';
import { useIsTouchLayout } from '@/hooks/useResponsiveLayout.ts';

import { Cursor } from './cursor.tsx';
import { Direction } from './direction.tsx';
import { MobilePointerMode as MobilePointerModeMenu } from './mobile-pointer-mode.tsx';
import { MouseMode } from './mouse-mode.tsx';
import { PointerSensitivity } from './pointer-sensitivity.tsx';
import { ResetHid } from './reset-hid.tsx';
import { Speed } from './speed.tsx';

export const Mouse = () => {
  const { t } = useTranslation();
  const isTouchLayout = useIsTouchLayout();

  const setMouseStyle = useSetAtom(mouseStyleAtom);
  const setMouseMode = useSetAtom(mouseModeAtom);
  const setPointerSensitivity = useSetAtom(pointerSensitivityAtom);
  const setScrollDirection = useSetAtom(scrollDirectionAtom);
  const setScrollInterval = useSetAtom(scrollIntervalAtom);

  useEffect(() => {
    const mouseStyle = ls.getMouseStyle();
    if (mouseStyle) {
      setMouseStyle(mouseStyle);
    }

    const mouseMode = ls.getMouseMode();
    if (mouseMode) {
      setMouseMode(mouseMode);
    }

    const pointerSensitivity = ls.getPointerSensitivity();
    if (pointerSensitivity) {
      setPointerSensitivity(pointerSensitivity);
    }

    const direction = ls.getMouseScrollDirection();
    if (direction) {
      setScrollDirection(direction > 0 ? 1 : -1);
    }

    const interval = ls.getMouseScrollInterval();
    if (interval) {
      setScrollInterval(interval);
    }
  }, []);

  const desktopContent = (
    <div className="flex flex-col space-y-1">
      <Cursor />
      <MouseMode />
      <PointerSensitivity />
      <Direction />
      <Speed />
      <Divider style={{ margin: '10px 0' }} />

      <ResetHid />
    </div>
  );

  const mobileContent = (
    <div className="flex flex-col space-y-1">
      <MobilePointerModeMenu />
      <Direction />
      <Speed />
      <Divider style={{ margin: '10px 0' }} />
      <ResetHid />
    </div>
  );

  return (
    <MenuItem
      title={t('mouse.title')}
      icon={<MouseIcon size={18} />}
      content={isTouchLayout ? mobileContent : desktopContent}
    />
  );
};
