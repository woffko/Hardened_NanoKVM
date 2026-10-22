import { useEffect, useRef } from 'react';
import { message } from 'antd';
import { useAtomValue } from 'jotai';
import { useTranslation } from 'react-i18next';

import { MouseReportRelative } from '@/lib/mouse.ts';
import { client, MessageEvent } from '@/lib/websocket.ts';
import { pointerSensitivityAtom, scrollDirectionAtom, scrollIntervalAtom } from '@/jotai/mouse.ts';
import { resolutionAtom } from '@/jotai/screen.ts';

import {
  getResolutionMovementScale,
  hasAccumulatedMovement,
  RELATIVE_DRAIN_INTERVAL_MS,
  takeAccumulatedMovement
} from './movement-scale.ts';
import { MouseRelativeEvent } from './types.ts';

export const Relative = () => {
  const { t } = useTranslation();
  const [messageApi, contextHolder] = message.useMessage();

  const resolution = useAtomValue(resolutionAtom);
  const scrollDirection = useAtomValue(scrollDirectionAtom);
  const scrollInterval = useAtomValue(scrollIntervalAtom);
  const pointerSensitivity = useAtomValue(pointerSensitivityAtom);

  const mouseRef = useRef(new MouseReportRelative());
  const isLockedRef = useRef(false);
  const lastScrollTimeRef = useRef(0);
  const moveAccumulatorRef = useRef({ x: 0, y: 0 });
  const drainTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    const screen = document.getElementById('screen');
    if (!screen) return;
    const target = document.getElementById('kvm-pointer-surface') ?? screen;

    showMessage();

    target.addEventListener('click', handleMouseClick);
    target.addEventListener('mousedown', handleMouseDown);
    target.addEventListener('mouseup', handleMouseUp);
    target.addEventListener('mousemove', handleMouseMove);
    target.addEventListener('wheel', handleMouseWheel, { passive: false });
    target.addEventListener('contextmenu', disableEvent);
    document.addEventListener('pointerlockchange', handlePointerLockChange);
    window.addEventListener('mouseup', handleWindowMouseUp);
    window.addEventListener('blur', releaseHeldButtons);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    // A release outside the screen never reaches the target's own listener,
    // which stops propagation: send it from here, or it stays held.
    function handleWindowMouseUp(e: MouseEvent) {
      if (!mouseRef.current.hasButtons()) return;
      handleMouseEvent({ type: 'mouseup', button: e.button });
    }

    // Losing focus or visibility can swallow a release: release them all.
    function releaseHeldButtons() {
      const mouse = mouseRef.current;
      if (!mouse.hasButtons()) return;
      mouse.releaseButtons();
      sendReport(mouse.buildButtonReport());
    }

    function handleVisibilityChange() {
      if (document.visibilityState === 'hidden') releaseHeldButtons();
    }

    // Mouse click event
    function handleMouseClick(event: MouseEvent) {
      disableEvent(event);

      if (!isLockedRef.current) {
        target.requestPointerLock();
      }
    }

    // Mouse down event
    function handleMouseDown(e: MouseEvent) {
      disableEvent(e);
      handleMouseEvent({ type: 'mousedown', button: e.button });
    }

    // Mouse up event
    function handleMouseUp(e: MouseEvent) {
      disableEvent(e);
      handleMouseEvent({ type: 'mouseup', button: e.button });
    }

    // Mouse move event
    function handleMouseMove(e: any) {
      disableEvent(e);

      const x = e.movementX || e.mozMovementX || e.webkitMovementX || 0;
      const y = e.movementY || e.mozMovementY || e.webkitMovementY || 0;
      if (x === 0 && y === 0) return;

      const baseDeltaX = Math.abs(x * window.devicePixelRatio) < 10 ? x * 2 : x;
      const baseDeltaY = Math.abs(y * window.devicePixelRatio) < 10 ? y * 2 : y;
      const movementScale = getResolutionMovementScale(resolution);
      const deltaX = baseDeltaX * pointerSensitivity * movementScale;
      const deltaY = baseDeltaY * pointerSensitivity * movementScale;

      queueRelativeMove(deltaX, deltaY);
    }

    // Mouse wheel event
    function handleMouseWheel(e: WheelEvent) {
      disableEvent(e);

      if (Math.floor(e.deltaY) === 0) {
        return;
      }

      const currentTime = Date.now();
      if (currentTime - lastScrollTimeRef.current < scrollInterval) {
        return;
      }

      const deltaY = (e.deltaY > 0 ? 1 : -1) * scrollDirection;
      handleMouseEvent({ type: 'wheel', deltaY });
      lastScrollTimeRef.current = currentTime;
    }

    function handlePointerLockChange() {
      isLockedRef.current = document.pointerLockElement === target;
    }

    function queueRelativeMove(deltaX: number, deltaY: number) {
      const move = takeAccumulatedMovement(moveAccumulatorRef.current, deltaX, deltaY);
      if (move) {
        handleMouseEvent({ type: 'move', deltaX: move.x, deltaY: move.y });
      }
      scheduleMovementDrain();
    }

    function scheduleMovementDrain() {
      if (drainTimerRef.current !== null || !hasAccumulatedMovement(moveAccumulatorRef.current)) {
        return;
      }

      drainTimerRef.current = setTimeout(() => {
        drainTimerRef.current = null;
        const move = takeAccumulatedMovement(moveAccumulatorRef.current, 0, 0);
        if (move) {
          handleMouseEvent({ type: 'move', deltaX: move.x, deltaY: move.y });
        }
        scheduleMovementDrain();
      }, RELATIVE_DRAIN_INTERVAL_MS);
    }

    return () => {
      if (drainTimerRef.current !== null) {
        clearTimeout(drainTimerRef.current);
        drainTimerRef.current = null;
      }
      target.removeEventListener('click', handleMouseClick);
      target.removeEventListener('mousemove', handleMouseMove);
      target.removeEventListener('mousedown', handleMouseDown);
      target.removeEventListener('mouseup', handleMouseUp);
      target.removeEventListener('wheel', handleMouseWheel);
      target.removeEventListener('contextmenu', disableEvent);
      document.removeEventListener('pointerlockchange', handlePointerLockChange);
      window.removeEventListener('mouseup', handleWindowMouseUp);
      window.removeEventListener('blur', releaseHeldButtons);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [resolution, scrollDirection, scrollInterval, pointerSensitivity]);

  // Mouse handler
  function handleMouseEvent(event: MouseRelativeEvent) {
    let report: Uint8Array;
    const mouse = mouseRef.current;

    switch (event.type) {
      case 'mousedown':
        mouse.buttonDown(event.button);
        report = mouse.buildButtonReport();
        break;
      case 'mouseup':
        mouse.buttonUp(event.button);
        report = mouse.buildButtonReport();
        break;
      case 'wheel':
        report = mouse.buildReport(0, 0, event.deltaY);
        break;
      case 'move':
        sendReport(mouse.buildReport(event.deltaX, event.deltaY));
        return;
      default:
        report = mouse.buildReport(0, 0);
        break;
    }

    sendReport(report);
  }

  function sendReport(report: Uint8Array) {
    const data = new Uint8Array([MessageEvent.Mouse, ...report]);
    client.send(data);
  }

  // show message
  function showMessage() {
    messageApi.open({
      key: 'requestPointer',
      type: 'info',
      content: t('mouse.requestPointer'),
      duration: 3,
      style: {
        marginTop: '40vh'
      }
    });
  }

  // disable default events
  function disableEvent(event: any) {
    event.preventDefault();
    event.stopPropagation();
  }

  return <>{contextHolder}</>;
};
