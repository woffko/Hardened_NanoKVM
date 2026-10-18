# RC12 app-only bootstrap input

`S95nanokvm` is an exact historical data asset, not the current init script and
not an independently executable recovery fallback. Its mode in source is 0644.
Do not install it in a full SD/rootfs image or load it as ordinary current code.

Provenance: `387793ab944437bbedc534d2ba231dd88d1fd2ca:kvmapp/system/init.d/S95nanokvm`.
It also byte-matches the retained accepted app `2.0.42` archive. SHA-256:
`8030d0f81581a417eca91e3db7e0c3d96cba197b519022d7c73c3c5caca05365`.

The old archive validator requires a regular `system/init.d/S95nanokvm` file.
The old copier leaves an equal installed S95 untouched. The first fixing app
archive therefore carries these exact legacy bytes, omits the three new ancillary
gates, and leaves publication of canonical compile-bound scripts to the new
backend after helper bootstrap. The full-image packaging stage stays canonical.
Build checks reject an old backend lacking those exact canonical embedded scripts,
a changed compatibility asset or a mismatched archive profile.

This only addresses premature gate/self-copy publication for the exact supported
RC12/app42 starting bytes. It does not make the old installer atomic, establish
trust in legacy p3 state, authorize unknown customized init scripts, migrate an
existing different helper, prove native quiescence, or replace device acceptance.
Legacy USB-data isolation and the complete migration/recovery matrix still apply.
