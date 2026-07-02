export const IMAGE_LIST_CHANGED_EVENT = 'nanokvm:image-list-changed';

export function notifyImageListChanged() {
  window.dispatchEvent(new Event(IMAGE_LIST_CHANGED_EVENT));
}
