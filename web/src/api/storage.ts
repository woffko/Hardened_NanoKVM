import { http } from '@/lib/http.ts';

// get image list
export function getImages() {
  return http.get('/api/storage/image');
}

// get mounted image
export function getMountedImage() {
  return http.get('/api/storage/image/mounted');
}

// Must match MEDIA_LOCKED_CODE in server-rust/src/api/storage.rs.
export const MEDIA_LOCKED_CODE = -423;

// mount/unmount image; force takes the USB gadget down to release a medium the computer has locked
export function mountImage(file?: string, cdrom?: boolean, force?: boolean) {
  const data = {
    file: file ? file : '',
    cdrom: cdrom,
    force: force ?? false
  };
  return http.post('/api/storage/image/mount', data);
}

export function reconnectUsbGadget() {
  return http.post('/api/storage/usb/reconnect');
}

// get CD-ROM flag
export function getCdRom() {
  return http.get('/api/storage/cdrom');
}

export function deleteImage(file: string) {
  const data = {
    file
  };
  return http.post('/api/storage/image/delete', data);
}
