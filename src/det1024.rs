// Copyright (c) Jeeyong Um <conr2d@proton.me>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Deterministic Falcon-1024 signature scheme.

use crate::{aux::*, shake256::Shake256Context, Error};
use static_assertions::const_assert_eq;
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const FALCON_DET1024_LOGN: usize = 10;
pub const FALCON_DET1024_PUBKEY_SIZE: usize = falcon_pubkey_size(FALCON_DET1024_LOGN);
pub const FALCON_DET1024_PRIVKEY_SIZE: usize = falcon_privkey_size(FALCON_DET1024_LOGN);

// Replace the 40 byte salt (nonce) with a single byte representing
// the salt version:
pub const FALCON_DET1024_SIG_COMPRESSED_MAXSIZE: usize =
	falcon_sig_compressed_maxsize(FALCON_DET1024_LOGN) - 40 + 1;
pub const FALCON_DET1024_SIG_CT_SIZE: usize = falcon_sig_ct_size(FALCON_DET1024_LOGN) - 40 + 1;

const_assert_eq!(FALCON_DET1024_PUBKEY_SIZE, 1793);
const_assert_eq!(FALCON_DET1024_PRIVKEY_SIZE, 2305);
const_assert_eq!(FALCON_DET1024_SIG_COMPRESSED_MAXSIZE, 1423);
const_assert_eq!(FALCON_DET1024_SIG_CT_SIZE, 1538);

/// Generate a keypair (for Falcon parameter n=1024).
///
/// The source of randomness is the provided SHAKE256 context `rng`,
/// which must have been already initialized, seeded, and set to output
/// mode (see [`Shake256Context::new_prng_from_seed()`] and
/// [`Shake256Context::new_prng_from_system()`]).
pub fn generate_keypair(rng: &mut Shake256Context) -> Result<(SigningKey, VerifyingKey), Error> {
	let mut secret = [0u8; FALCON_DET1024_PRIVKEY_SIZE];
	let mut public = [0u8; FALCON_DET1024_PUBKEY_SIZE];
	match unsafe {
		sys::falcon_det1024_keygen(
			&mut rng.0 as *mut _,
			secret.as_mut_ptr() as *mut _,
			public.as_mut_ptr() as *mut _,
		)
	} {
		0 => Ok((SigningKey(secret), VerifyingKey(public))),
		e => Err(e.into()),
	}
}

/// Deterministic Falcon-1024 signing key.
#[derive(Clone, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SigningKey(pub(crate) [u8; FALCON_DET1024_PRIVKEY_SIZE]);

impl PartialEq for SigningKey {
	fn eq(&self, other: &Self) -> bool {
		self.0.ct_eq(&other.0).unwrap_u8() == 1u8
	}
}

impl ConstantTimeEq for SigningKey {
	fn ct_eq(&self, other: &Self) -> Choice {
		self.0.ct_eq(&other.0)
	}
}

impl SigningKey {
	/// Initialize signing key from a byte array.
	pub const fn from_bytes(bytes: [u8; FALCON_DET1024_PRIVKEY_SIZE]) -> Self {
		Self(bytes)
	}

	/// Initialize signing key from a byte slice.
	pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
		if bytes.len() != FALCON_DET1024_PRIVKEY_SIZE {
			return Err(Error::Size);
		}
		let mut key = [0u8; FALCON_DET1024_PRIVKEY_SIZE];
		key.copy_from_slice(bytes);
		Ok(Self(key))
	}

	/// Get the [`VerifyingKey`] which corresponds to this [`SigningKey`].
	pub fn verifying_key(&self) -> VerifyingKey {
		let mut pubkey = [0u8; FALCON_DET1024_PUBKEY_SIZE];
		let mut tmp = [0u8; falcon_tmpsize_makepub(FALCON_DET1024_LOGN)];
		unsafe {
			sys::falcon_make_public(
				pubkey.as_mut_ptr() as *mut _,
				FALCON_DET1024_PUBKEY_SIZE,
				self.0.as_ptr() as *const _,
				self.0.len(),
				tmp.as_mut_ptr() as *mut _,
				tmp.len(),
			);
		}
		VerifyingKey(pubkey)
	}

	/// Deterministically sign the data provided in `msg` slice.
	///
	/// The resulting compressed-format, variable-length signature is
	/// returned in a [`Signature`] object.
	///
	/// The resulting signature is incompatible with randomized ("salted")
	/// Falcon signatures: it excludes the salt (nonce), adds a salt
	/// version byte, and changes the header byte. See the [Deterministic Falcon]
	/// specification for further details.
	///
	/// [Deterministic Falcon]: https://github.com/algorand/falcon/blob/ce15e75bceb372867daf6b8e81918ab6978686eb/falcon-det.pdf
	///
	/// This function implements only the following subset of the
	/// specification:
	///
	///  - the parameter n is fixed to n=1024
	///  - the signature format is 'compressed'
	pub fn sign_compressed(&self, msg: &[u8]) -> Result<Signature, Error> {
		let mut sig = [0u8; FALCON_DET1024_SIG_COMPRESSED_MAXSIZE];
		let mut siglen = 0;
		match unsafe {
			sys::falcon_det1024_sign_compressed(
				sig.as_mut_ptr() as *mut _,
				&mut siglen,
				self.0.as_ptr() as *const _,
				msg.as_ptr() as *const _,
				msg.len(),
			)
		} {
			0 => Ok(Signature(sig[..siglen].to_vec())),
			e => Err(e.into()),
		}
	}
}

impl TryFrom<&[u8]> for SigningKey {
	type Error = Error;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		Self::from_slice(bytes)
	}
}

impl core::fmt::Debug for SigningKey {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_tuple("SigningKey").finish_non_exhaustive()
	}
}

impl signature::Signer<Signature> for SigningKey {
	fn try_sign(&self, msg: &[u8]) -> Result<Signature, signature::Error> {
		Self::sign_compressed(self, msg).map_err(|_| signature::Error::new())
	}
}

/// Deterministic Falcon-1024 verifying key (i.e. public key).
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerifyingKey(pub(crate) [u8; FALCON_DET1024_PUBKEY_SIZE]);

impl ConstantTimeEq for VerifyingKey {
	fn ct_eq(&self, other: &Self) -> Choice {
		self.0.ct_eq(&other.0)
	}
}

impl VerifyingKey {
	/// Initialize verifying key from a byte array.
	pub const fn from_bytes(bytes: [u8; FALCON_DET1024_PUBKEY_SIZE]) -> Self {
		Self(bytes)
	}

	/// Initialize verifying key from a byte slice.
	pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
		if bytes.len() != FALCON_DET1024_PUBKEY_SIZE {
			return Err(Error::Size);
		}
		let mut key = [0u8; FALCON_DET1024_PUBKEY_SIZE];
		key.copy_from_slice(bytes);
		Ok(Self(key))
	}

	/// Verify the compressed-format, deterministic-mode (det1024)
	/// signature provided in `signature` with respect to this verifying
	/// key and the data provided in `msg`.
	///
	/// This function accepts a strict subset of valid deterministic-mode
	/// Falcon signatures, namely, only those having n=1024 and
	/// "compressed" signature format (thus matching the choices
	/// implemented by [`SigningKey::sign_compressed()`]).
	pub fn verify_compressed(&self, msg: &[u8], signature: &Signature) -> Result<(), Error> {
		match unsafe {
			sys::falcon_det1024_verify_compressed(
				signature.0.as_ptr() as *const _,
				signature.0.len(),
				self.0.as_ptr() as *const _,
				msg.as_ptr() as *const _,
				msg.len(),
			)
		} {
			0 => Ok(()),
			e => Err(e.into()),
		}
	}

	/// Verify the CT-format, deterministic-mode (det1024) signature
	/// provided in `signature` with respect to this verifying key and the
	/// data provided in `msg`.
	///
	/// This function accepts a strict subset of valid deterministic-mode
	/// Falcon signatures, namely, only those having n=1024 and "CT"
	/// signature format.
	pub fn verify_ct(&self, msg: &[u8], signature: &CtSignature) -> Result<(), Error> {
		match unsafe {
			sys::falcon_det1024_verify_ct(
				signature.0.as_ptr() as *const _,
				self.0.as_ptr() as *const _,
				msg.as_ptr() as *const _,
				msg.len(),
			)
		} {
			0 => Ok(()),
			e => Err(e.into()),
		}
	}
}

impl AsRef<[u8]> for VerifyingKey {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl TryFrom<&[u8]> for VerifyingKey {
	type Error = Error;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		Self::from_slice(bytes)
	}
}

impl core::fmt::Debug for VerifyingKey {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_tuple("VerifyingKey").field(&const_hex::encode(self.0)).finish()
	}
}

impl signature::Verifier<Signature> for VerifyingKey {
	fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), signature::Error> {
		Self::verify_compressed(self, msg, signature).map_err(|_| signature::Error::new())
	}
}

impl signature::Verifier<CtSignature> for VerifyingKey {
	fn verify(&self, msg: &[u8], signature: &CtSignature) -> Result<(), signature::Error> {
		Self::verify_ct(self, msg, signature).map_err(|_| signature::Error::new())
	}
}

/// Deterministic Falcon-1024 compressed signature (variable-length).
#[derive(Clone, Eq, PartialEq)]
pub struct Signature(pub(crate) Vec<u8>);

#[allow(clippy::len_without_is_empty)]
impl Signature {
	/// Initialize compressed signature from a byte slice.
	pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
		if bytes.len() > FALCON_DET1024_SIG_COMPRESSED_MAXSIZE {
			return Err(Error::Size);
		}
		Ok(Self(bytes.to_vec()))
	}

	/// Returns the number of bytes in the signature, also referred to as its ‘length’.
	pub fn len(&self) -> usize {
		self.0.len()
	}

	/// Returns the salt version of a signature.
	pub fn salt_version(&self) -> i32 {
		unsafe { sys::falcon_det1024_get_salt_version(self.0.as_ptr() as *const _) }
	}
}

impl AsRef<[u8]> for Signature {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl TryFrom<&[u8]> for Signature {
	type Error = Error;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		Self::from_slice(bytes)
	}
}

impl core::fmt::Debug for Signature {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_tuple("Signature").field(&const_hex::encode(&self.0)).finish()
	}
}

/// Deterministic Falcon-1024 constant-time signature (fixed-size).
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CtSignature(pub(crate) [u8; FALCON_DET1024_SIG_CT_SIZE]);

impl CtSignature {
	/// Initialize constant-time signature from a byte array.
	pub const fn from_bytes(bytes: [u8; FALCON_DET1024_SIG_CT_SIZE]) -> Self {
		Self(bytes)
	}

	/// Initialize constant-time signature from a byte slice.
	pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
		if bytes.len() != FALCON_DET1024_SIG_CT_SIZE {
			return Err(Error::Size);
		}
		let mut sig = [0u8; FALCON_DET1024_SIG_CT_SIZE];
		sig.copy_from_slice(bytes);
		Ok(Self(sig))
	}

	/// Returns the salt version of a signature.
	pub fn salt_version(&self) -> i32 {
		unsafe { sys::falcon_det1024_get_salt_version(self.0.as_ptr() as *const _) }
	}
}

impl AsRef<[u8]> for CtSignature {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

impl TryFrom<&[u8]> for CtSignature {
	type Error = Error;

	fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
		Self::from_slice(bytes)
	}
}

impl TryFrom<Signature> for CtSignature {
	type Error = Error;

	fn try_from(sig: Signature) -> Result<CtSignature, Self::Error> {
		let mut ct = [0u8; FALCON_DET1024_SIG_CT_SIZE];
		match unsafe {
			sys::falcon_det1024_convert_compressed_to_ct(
				ct.as_mut_ptr() as *mut _,
				sig.0.as_ptr() as *const _,
				sig.0.len(),
			)
		} {
			0 => Ok(CtSignature(ct)),
			e => Err(e.into()),
		}
	}
}

impl core::fmt::Debug for CtSignature {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		f.debug_tuple("CtSignature").field(&const_hex::encode(self.0)).finish()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use signature::{Signer, Verifier};

	#[test]
	fn test_det1024() {
		let mut rng = Shake256Context::new_prng_from_system().expect("RNG failed");
		let (sk, vk) = generate_keypair(&mut rng).expect("Keygen failed");
		let msg = b"hello, world!";
		let sig = sk.try_sign(msg).expect("Sign failed");
		assert!(vk.verify(msg, &sig).is_ok());
	}
}
