import { useAtomValue } from 'jotai';

import { resolutionAtom, videoModeAtom } from '@/jotai/screen.ts';

import { H264Direct } from './h264-direct.tsx';
import { H264Webrtc } from './h264-webrtc.tsx';
import { Mjpeg } from './mjpeg.tsx';

export const Screen = () => {
  const videoMode = useAtomValue(videoModeAtom);
  const resolution = useAtomValue(resolutionAtom);
  const streamKey = `${resolution?.width ?? 0}x${resolution?.height ?? 0}`;

  if (videoMode === 'mjpeg') {
    return <Mjpeg />;
  }

  if (videoMode === 'direct') {
    return <H264Direct key={streamKey} />;
  }

  return <H264Webrtc key={streamKey} />;
};
