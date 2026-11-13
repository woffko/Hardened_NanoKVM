'use strict';

// Only locally constructed, non-sensitive summaries may enter failure reports.
// Node errors can include paths/argv; child stderr and remote data are untrusted.
class DeviceTestFailure extends Error {}

function reportableFailure(error) {
  return error instanceof DeviceTestFailure
    ? error.message
    : 'operation failed; untrusted diagnostic detail suppressed';
}

module.exports = { DeviceTestFailure, reportableFailure };
