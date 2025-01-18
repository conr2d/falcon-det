// Copyright (c) Jeeyong Um <conr2d@proton.me>
// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

mod test_deterministic_kat;

use test_deterministic_kat::*;

use crate::{
    det1024::{self, CtSignature, Signature, FALCON_DET1024_CURRENT_SALT_VERSION},
    shake256::Shake256Context,
};
use signature::{Signer, Verifier};

fn test_inner(data_len: usize) {
    let mut msg_rng =
        Shake256Context::new_prng_from_seed(format!("msg-{:04}", data_len).as_bytes());
    let data = msg_rng.extract(data_len);

    let mut key_rng =
        Shake256Context::new_prng_from_seed(format!("key-{:04}", data_len).as_bytes());
    let (sk, vk) = match det1024::generate_keypair(&mut key_rng) {
        Ok((sk, vk)) => (sk, vk),
        Err(e) => panic!("keygen (data_len={}) failed: {:?}", data_len, e),
    };

    let sig = match sk.try_sign(&data) {
        Ok(sig) => sig,
        Err(e) => panic!("sign_compressed (data_len={}) failed: {:?}", data_len, e),
    };

    assert_eq!(sig.salt_version(), FALCON_DET1024_CURRENT_SALT_VERSION);

    match vk.verify(&data, &sig) {
        Ok(_) => (),
        Err(e) => panic!("verify_compressed (data_len={}) failed: {:?}", data_len, e),
    };

    let sig_ct = match CtSignature::try_from(sig.clone()) {
        Ok(sig_ct) => sig_ct,
        Err(e) => panic!(
            "conversion to CT format (data_len={}) failed: {:?}",
            data_len, e
        ),
    };

    assert_eq!(sig_ct.salt_version(), FALCON_DET1024_CURRENT_SALT_VERSION);

    match vk.verify(&data, &sig_ct) {
        Ok(_) => (),
        Err(e) => panic!("verify_ct (data_len={}) failed: {:?}", data_len, e),
    };

    let expected_sig =
        Signature::from_vec(const_hex::decode(FALCON_DET1024_KAT[data_len]).unwrap()).unwrap();
    assert!(
        sig.len() == expected_sig.len(),
        "sign_compressed (data_len={}) length {} does not match KAT length {}",
        data_len,
        sig.len(),
        expected_sig.len()
    );

    assert!(
        sig == expected_sig,
        "sign_compressed (data_len={}) does not match KAT",
        data_len
    );

    if data_len < NUM_KATS_CT {
        let expected_sig_ct = CtSignature::from_bytes(
            const_hex::decode_to_array(FALCON_DET1024_KAT_CT[data_len]).unwrap(),
        );
        assert!(
            sig_ct == expected_sig_ct,
            "convert_compressed_to_ct (data_len={}) does not match KAT",
            data_len
        );
    }
}

#[test]
fn test_det1024() {
    for kat in 0..NUM_KATS {
        test_inner(kat);
    }
}
