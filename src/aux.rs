// Copyright (C) Jeeyong Um <conr2d@proton.me>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

/// Private key size (in bytes). The size is exact.
pub const fn falcon_privkey_size(logn: usize) -> usize {
    (if logn <= 3 {
        3 << logn
    } else {
        ((10 - (logn >> 1)) << (logn - 2)) + (1 << logn)
    }) + 1
}

/// Public key size (in bytes). The size is exact.
pub const fn falcon_pubkey_size(logn: usize) -> usize {
    (if logn <= 1 { 4 } else { 7 << (logn - 2) }) + 1
}

/// Maximum signature size (in bytes) when using the COMPRESSED format.
pub const fn falcon_sig_compressed_maxsize(logn: usize) -> usize {
    ((((11 << logn) + (101 >> (10 - logn))) + 7) >> 3) + 41
}

/// Signature size (in bytes) when using the PADDED format. The size is exact.
pub const fn falcon_sig_padded_size(logn: usize) -> usize {
    44 + 3 * (256 >> (10 - logn))
        + 2 * (128 >> (10 - logn))
        + 3 * (64 >> (10 - logn))
        + 2 * (16 >> (10 - logn))
        - 2 * (2 >> (10 - logn))
        - 8 * (1 >> (10 - logn))
}

/// Signature size (in bytes) when using the CT format. The size is exact.
pub const fn falcon_sig_ct_size(logn: usize) -> usize {
    (3 << (logn - 1)) - if logn == 3 { 1 } else { 0 } + 41
}

/// Temporary buffer size for key pair generation.
pub const fn falcon_tmpsize_keygen(logn: usize) -> usize {
    (if logn <= 3 { 272 } else { 28 << logn }) + (3 << logn) + 7
}

/// Temporary buffer size for computing the public key from the private key.
pub const fn falcon_tmpsize_makepub(logn: usize) -> usize {
    (6 << logn) + 1
}

/// Temporary buffer size for generating a signature ("dynamic" variant).
pub const fn falcon_tmpsize_signdyn(logn: usize) -> usize {
    (78 << logn) + 7
}

/// Temporary buffer size for generating a signature ("tree" variant, with an expanded key).
pub const fn falcon_tmpsize_signtree(logn: usize) -> usize {
    (50 << logn) + 7
}

/// Temporary buffer size for expanding a private key.
pub const fn falcon_tmpsize_expandpriv(logn: usize) -> usize {
    (52 << logn) + 7
}

/// Size of an expanded private key.
pub const fn falcon_expandedkey_size(logn: usize) -> usize {
    ((8 * logn + 40) << logn) + 8
}

/// Temporary buffer size for verifying a signature.
pub const fn falcon_tmpsize_verify(logn: usize) -> usize {
    (8 << logn) + 1
}
