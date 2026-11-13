//! Controller-side ownership. The subreaper itself runs only in the separate
//! `nanokvm-native-owner` executable, never in the asynchronous backend.
/// What the linked native programs need from the musl loader that starts them.
pub const LIBRARY_PATH: &str = "/kvmapp/server/dl_lib:/mnt/system/usr/lib:/mnt/system/usr/lib/3rd";

pub mod broker;
pub mod controller;
pub mod embedded;
pub mod picoclaw_home;
