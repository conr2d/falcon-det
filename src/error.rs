// Copyright (c) Jeeyong Um <conr2d@proton.me>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[derive(Debug)]
pub enum Error {
	/// [`Error::Random`] is returned when the library tries to use an
	/// OS-provided RNG, but either none is supported, or that RNG fails.
	Random,
	/// [`Error::Size`] is returned when a buffer has been provided to
	/// the library but is too small to receive the intended value.
	Size,
	/// [`Error::Format`] is returned when decoding of an external object
	/// (public key, private key, signature) fails.
	Format,
	/// [`Error::BadSig`] is returned when verifying a signature, the signature
	/// is validly encoded, but its value does not match the provided message
	/// and public key.
	BadSig,
	/// [`Error::BadArg`] is returned when a provided parameter is not in
	/// a valid range.
	BadArg,
	/// [`Error::Internal`] is returned when some internal computation failed.
	Internal,
	Unknown(i32),
}

impl From<i32> for Error {
	fn from(e: i32) -> Self {
		match e {
			sys::FALCON_ERR_RANDOM => Error::Random,
			sys::FALCON_ERR_SIZE => Error::Size,
			sys::FALCON_ERR_FORMAT => Error::Format,
			sys::FALCON_ERR_BADSIG => Error::BadSig,
			sys::FALCON_ERR_BADARG => Error::BadArg,
			sys::FALCON_ERR_INTERNAL => Error::Internal,
			_ => Error::Unknown(e),
		}
	}
}
