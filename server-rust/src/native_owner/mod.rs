//! Controller-side ownership. The subreaper itself runs only in the separate
//! `nanokvm-native-owner` executable, never in the asynchronous backend.
pub mod broker;
pub mod controller;
pub mod embedded;
