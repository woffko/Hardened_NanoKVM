import { useEffect, useState } from 'react';
import clsx from 'clsx';
import { useAtom, useAtomValue } from 'jotai';

import { stopFrameDetect, updateFrameDetect } from '@/api/stream.ts';
import { getFrameDetect } from '@/lib/localstorage.ts';
import * as storage from '@/lib/localstorage.ts';
import { getBaseUrl } from '@/lib/service.ts';
import { mouseStyleAtom } from '@/jotai/mouse.ts';
import { resolutionAtom, videoScaleAtom } from '@/jotai/screen.ts';

import { useScreenFit } from './use-screen-fit.ts';

export const Mjpeg = () => {
  const resolution = useAtomValue(resolutionAtom);
  const mouseStyle = useAtomValue(mouseStyleAtom);
  const [videoScale, setVideoScale] = useAtom(videoScaleAtom);
  const [hasError, setHasError] = useState(false);
  const [streamNonce, setStreamNonce] = useState(0);
  const streamURL = `${getBaseUrl('http')}/api/stream/mjpeg`;
  const streamSrc = hasError ? undefined : `${streamURL}?v=${streamNonce}`;
  const { containerRef, mediaStyle } = useScreenFit(resolution, videoScale, {
    maxWidth: '100%',
    maxHeight: '100%',
    objectFit: 'scale-down'
  });

  useEffect(() => {
    // Announce the stored choice (the backend starts with detection off and
    // returns to this value after a pause), then pause it for a while.
    const enabled = getFrameDetect();
    updateFrameDetect(enabled);
    if (enabled) {
      stopFrameDetect(10);
    }
    setHasError(false);
    setStreamNonce((current) => current + 1);
  }, [resolution]);

  useEffect(() => {
    const scale = storage.getVideoScale();
    if (scale) {
      setVideoScale(scale);
    }
  }, [setVideoScale]);

  return (
    <div
      ref={containerRef}
      data-kvm-screen-scroll
      className="flex h-full min-h-0 w-full min-w-0 items-start justify-start overflow-auto overscroll-contain bg-black"
    >
      <img
        id="screen"
        className={clsx('m-auto block select-none', mouseStyle)}
        style={{
          ...mediaStyle,
          visibility: hasError ? 'hidden' : 'visible'
        }}
        src={streamSrc}
        onError={() => setHasError(true)}
        alt="screen"
      />
    </div>
  );
};
