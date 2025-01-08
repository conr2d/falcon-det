// Copyright (c) Jeeyong Um <conr2d@proton.me>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! SHAKE256 context for PRNG and hashing.
//!
//! SHAKE256 is used in two places:
//!
//!  - As a PRNG: all functions that require randomness (key pair
//!    generation, signature generation) receive as parameter a [`Shake256Context`],
//!    in output mode, from which pseudorandom data is obtained.
//!
//!    A SHAKE256 instance, to be used as a RNG, can be initialized
//!    from an explicit 48-byte seed, or from an OS-provided RNG. Using
//!    an explicit seed is meant for reproducibility of test vectors,
//!    or to be used in cases where no OS-provided RNG is available and
//!    supported.
//!
//!  - As the hashing mechanism for the message which should be signed.
//!    The streamed signature API exposes that SHAKE256 object, since
//!    the caller then performs the hashing externally.

use crate::Error;

/// Context for a SHAKE256 computation. Contents are opaque.
pub struct Shake256Context(pub(crate) sys::shake256_context);

impl Default for Shake256Context {
	fn default() -> Self {
		Self::new()
	}
}

impl Shake256Context {
	/// Initialize a SHAKE256 context to its initial state. The state is
	/// then ready to receive data (with [`Shake256Context::inject()`]).
	pub fn new() -> Self {
		let mut ctx = core::mem::MaybeUninit::<sys::shake256_context>::uninit();
		unsafe {
			sys::shake256_init(ctx.as_mut_ptr() as *mut _);
			Self(ctx.assume_init())
		}
	}

	/// Initialize a SHAKE256 context as a PRNG from the provided seed.
	/// This initializes the context, injects the seed, then flips the context
	/// to output mode to make it ready to produce bytes.
	pub fn new_prng_from_seed(seed: &[u8]) -> Self {
		let mut ctx = core::mem::MaybeUninit::<sys::shake256_context>::uninit();
		unsafe {
			sys::shake256_init_prng_from_seed(
				ctx.as_mut_ptr() as *mut _,
				seed.as_ptr() as *const _,
				seed.len(),
			);
			Self(ctx.assume_init())
		}
	}

	/// Initialize a SHAKE256 context as a PRNG, using an initial seed from
	/// the OS-provided RNG. If there is no known/supported OS-provided RNG,
	/// or if that RNG fails, then the context is not properly initialized
	/// and [`Error::Random`] is returned.
	pub fn new_prng_from_system() -> Result<Self, Error> {
		let mut ctx = core::mem::MaybeUninit::<sys::shake256_context>::uninit();
		unsafe {
			match sys::shake256_init_prng_from_system(ctx.as_mut_ptr() as *mut _) {
				0 => Ok(Self(ctx.assume_init())),
				e => Err(e.into()),
			}
		}
	}

	/// Inject some data bytes into the SHAKE256 context ("absorb" operation).
	/// This function can be called several times, to inject several chunks
	/// of data of arbitrary length.
	pub fn inject(&mut self, data: &[u8]) {
		unsafe {
			sys::shake256_inject(&mut self.0, data.as_ptr() as *const _, data.len());
		}
	}

	/// Flip the SHAKE256 state to output mode. After this call, [`Shake256Context::inject()`]
	/// can no longer be called on the context, but [`Shake256Context::extract()`] can be
	/// called.
	///
	/// Flipping is one-way; a given context can be converted back to input
	/// mode only by initializing it again, which forgets all previously
	/// injected data.
	pub fn flip(&mut self) {
		unsafe {
			sys::shake256_flip(&mut self.0);
		}
	}

	/// Extract bytes from the SHAKE256 context ("squeeze" operation). The
	/// context must have been flipped to output mode (with [`Shake256Context::flip()`]).
	/// Arbitrary amounts of data can be extracted, in one or several calls
	/// to this function.
	pub fn extract_into(&mut self, out: &mut [u8]) {
		unsafe {
			sys::shake256_extract(&mut self.0, out.as_mut_ptr() as *mut _, out.len());
		}
	}

	/// Extract bytes from the SHAKE256 context ("squeeze" operation). The
	/// context must have been flipped to output mode (with [`Shake256Context::flip()`]).
	/// Arbitrary amounts of data can be extracted, in one or several calls
	/// to this function.
	pub fn extract(&mut self, len: usize) -> Vec<u8> {
		let mut out = vec![0u8; len];
		self.extract_into(&mut out);
		out
	}
}
