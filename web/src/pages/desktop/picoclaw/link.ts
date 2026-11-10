// A link in an assistant answer is followed only when it names another site in
// full. The assistant reads the screen of the controlled computer, so text
// shown there can end up in an answer. A relative address, or one that names
// this device, would open a page of this interface with parameters of that
// text's choosing, such as the serial terminal with a prepared command line.
export function isExternalLink(url: string, ownHost: string): boolean {
  if (!/^https?:\/\//i.test(url)) return false;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;
    return parsed.host.toLowerCase() !== ownHost.toLowerCase();
  } catch {
    return false;
  }
}
