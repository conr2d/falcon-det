// Copyright (c) Jeeyong Um <conr2d@proton.me>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Deterministic Falcon post-quantum signature scheme.
//!
//! This crate provides Rust bindings to a deterministic version of
//! [Falcon] post-quantum signature scheme by [Algorand].
//!
//! [Falcon]: https://falcon-sign.info
//! [Algorand]: https://github.com/algorand/falcon
//!
//! ## MSRV
//!
//! The `falcon-det` minimum supported Rust version is **1.82.0**.

extern crate falcon_det_sys as sys;

#[doc(hidden)]
pub mod aux;
pub mod det1024;
pub mod error;
pub mod shake256;

#[doc(hidden)]
pub use error::Error;
