# Web input hygiene

Four small faults in the browser side of HID input, found by the RC12 audit
(L-B11), and the host test that keeps them fixed:
`node scripts/test-web-input-hygiene.cjs`. It transpiles the real modules with
the web tree's TypeScript compiler and runs them with stubs for the socket
library and the timers. It is not a browser, React or device test.

## HID WebSocket client (`web/src/lib/websocket.ts`)

The client gave up after one failed reconnect, and a reconnect or a second
`connect()` created a new socket without closing the previous one, which
could still be connecting; that socket then opened or closed on its own and
drove the client's heartbeat and reconnect logic. Now:

- it retries up to ten times, with delays growing from the configured
  interval by 1.5 per attempt up to 30 s, and a successful open starts the
  count over;
- before a new socket is created, and on `close()`, the current socket is
  closed whatever its state (connecting or open), with its handlers detached;
- only the current socket's events reach the client: a discarded socket that
  opens or closes later changes nothing.

## Keymap (`web/src/lib/keymap.ts`)

Browser, media, launch, sleep/wake and transport keys were mapped to usages
0xe8 and above. Those are consumer-page usages; the keyboard page ends at
0xe7 (RightMeta), and the boot keyboard report has no place for them, so the
report carried made-up keyboard usages. They are unmapped now and such keys
are ignored. The test checks every remaining entry stays within 0x04..0xe7.

## Mobile keyboard and IME (`web/src/pages/desktop/mobile-local-keyboard/`)

Text entered through an IME arrives as a run of input events while the
composition is open, each carrying the partial text so far; the keyboard sent
every one of them, so fragments were typed repeatedly. A `CompositionGate`
(`web/src/lib/composition.ts`) holds input while a composition is open and
sends the final text once when it ends. The backend refuses characters the
chosen layout cannot type, by name; the keyboard shows that message instead
of dropping the text silently. Typing Cyrillic, Korean or Japanese through
HID still needs a target-side layout that the backend's tables do not model;
that is unchanged and now visible.

## Wheel (`web/src/pages/desktop/mouse/{relative,absolute}.tsx`)

The wheel handler floored the delta before testing it for zero, so a small
positive delta (a trackpad or a high-resolution wheel) became 0 and was
dropped while the same negative delta became -1 and scrolled. `wheelStep`
(`web/src/lib/wheel.ts`) turns any non-zero finite delta into one notch in
its direction; the per-event rate limit is unchanged.
