# Wi-Fi provisioning response regression

The AP setup page treats only the numeric API response `code: 0` as an accepted
configuration request. Codes `-1` and `-4` keep the existing denied state. Every
other code, missing response and rejected request produces the failed state,
leaving the submit action available for retry. An unknown response must not
become success merely because it did not match an older known error code.

The request contract is unchanged: `POST /api/network/wifi` carries the requested
SSID/password and `X-AP-Key`. Its success means the backend accepted/persisted a
request for the independent native Wi-Fi state machine. It does **not** prove
association, DHCP completion or continued management connectivity. Transactional
Wi-Fi apply/rollback and truthful completion reporting remain separate WP-09/20
work; this regression does not close the whole Wi-Fi finding.

With the web development dependencies already installed, run:

```sh
node scripts/test-wifi-provisioning-result.cjs
```

The fixture parses the actual TSX component with TypeScript, locates its single
`Wifi.connect` declaration and executes that handler with a synthetic API/state
sink. It covers known and unknown codes, malformed/absent responses, rejection,
pending response and the existing empty-input/busy guards. It contacts no device
and uses no real credentials. This is a handler regression, not React rendering,
browser, native-runtime or physical Wi-Fi acceptance.

For a checked existing TypeScript installation outside `web/node_modules`, pass
`--typescript-module /absolute/path/to/typescript`; the fixture installs nothing.
`--baseline-ref COMMIT_HASH` runs the same cases against the historical component
from that commit without replacing the working tree.
