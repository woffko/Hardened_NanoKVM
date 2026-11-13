// Passwords are protected by the TLS transport; there is no static client-side
// cipher. Encoding keeps the existing form/API boundary without pretending the
// value is confidential on its own.
export function encrypt(data: string) {
  return encodeURIComponent(data);
}
