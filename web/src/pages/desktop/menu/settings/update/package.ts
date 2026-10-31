export interface OfflinePackage {
  file: File;
  metadata: File;
  signature: File;
}

const ARCHIVE_NAME = /^(nanokvm_\d+\.\d+\.\d+|hardened-nanokvm-kvmapp-\d+\.\d+\.\d+)\.tar\.gz$/;

// The three files of a release, in whatever order the file dialog gives them.
export function pickOfflinePackage(files: File[]): OfflinePackage | null {
  const file = files.find((item) => ARCHIVE_NAME.test(item.name));
  const metadata = files.find((item) => item.name.endsWith('.json'));
  const signature = files.find((item) => item.name.endsWith('.sig'));
  if (files.length !== 3 || !file || !metadata || !signature) return null;
  return { file, metadata, signature };
}
