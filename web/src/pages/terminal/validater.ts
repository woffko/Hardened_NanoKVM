type PicocomParameters = {
  port: string | null;
  baud: string | null;
  parity: string | null;
  flowControl: string | null;
  dataBits: string | null;
  stopBits: string | null;
};

const ALLOWED_BAUD_RATES = [
  '50',
  '75',
  '110',
  '134',
  '150',
  '200',
  '300',
  '600',
  '1200',
  '1800',
  '2400',
  '4800',
  '9600',
  '19200',
  '38400',
  '57600',
  '115200',
  '230400',
  '460800',
  '500000',
  '576000',
  '921600',
  '1000000',
  '1152000',
  '1500000',
  '2000000',
  '2500000',
  '3000000',
  '3500000',
  '4000000'
];
const ALLOWED_PARITIES = ['n', 'o', 'e', 'm', 's', 'none', 'even', 'odd'];
const ALLOWED_FLOW_CONTROLS = ['n', 'h', 's', 'x', 'none', 'soft', 'hard'];
const ALLOWED_DATA_BITS = ['5', '6', '7', '8'];
const ALLOWED_STOP_BITS = ['1', '2'];

const PORT_REGEX = /^\/dev\/[A-Za-z0-9._-]+$/;

function hasControlChar(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function canonicalValue(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  if (value === '' || hasControlChar(value)) return null;
  if (value !== value.trim()) return null;
  return value;
}

function optionalValue(
  value: string | null | undefined,
  allowed: readonly string[],
  fallback: string
): string | null {
  if (value === null || value === undefined || value === '') return fallback;
  const canonical = canonicalValue(value);
  if (canonical === null) return null;
  const normalized = canonical.toLowerCase();
  return allowed.includes(normalized) ? normalized : null;
}

export function buildPicocomCommand(params: PicocomParameters): string | null {
  const port = canonicalValue(params.port);
  if (
    port === null ||
    !port.startsWith('/dev/') ||
    port.includes('..') ||
    !PORT_REGEX.test(port)
  ) {
    return null;
  }

  const baud = canonicalValue(params.baud);
  if (baud === null || !ALLOWED_BAUD_RATES.includes(baud)) {
    return null;
  }

  const parity = optionalValue(params.parity, ALLOWED_PARITIES, 'none');
  const flowControl = optionalValue(params.flowControl, ALLOWED_FLOW_CONTROLS, 'none');
  const dataBits = optionalValue(params.dataBits, ALLOWED_DATA_BITS, '8');
  const stopBits = optionalValue(params.stopBits, ALLOWED_STOP_BITS, '1');
  if (parity === null || flowControl === null || dataBits === null || stopBits === null) {
    return null;
  }

  return `picocom ${port} --baud ${baud} --parity ${parity} --flow ${flowControl} --databits ${dataBits} --stopbits ${stopBits}`;
}

export function validatePicocomParameters(params: PicocomParameters): boolean {
  return buildPicocomCommand(params) !== null;
}
