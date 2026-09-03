//! Generic behaviour tests for the `hazmat` traits (`bouncycastle_core::traits::hazmat`).

use crate::DUMMY_SEED;
use bouncycastle_core::errors::SymmetricCipherError;
use bouncycastle_core::key_material::{
    KeyMaterial, KeyMaterialTrait, KeyType, do_hazardous_operations,
};
use bouncycastle_core::traits::SecurityStrength;
use bouncycastle_core::traits::hazmat::BlockPermutation;

/// Instance of the test framework.
pub struct TestFrameworkBlockPermutation {
    // Put any config options here
}

impl TestFrameworkBlockPermutation {
    ///
    pub fn new() -> Self {
        Self {}
    }

    /// Test all the members of trait [`BlockPermutation`] for a given key/block length pair.
    /// This gives good baseline test coverage, but is not exhaustive.
    pub fn test<
        const KEY_LEN: usize,
        const BLOCK_LEN: usize,
        P: BlockPermutation<KEY_LEN, BLOCK_LEN>,
    >(
        &self,
    ) {
        let key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        let permutation = P::new(&key).unwrap();

        let mut a = [0u8; BLOCK_LEN];
        a.copy_from_slice(&DUMMY_SEED[..BLOCK_LEN]);
        let mut b = [0u8; BLOCK_LEN];
        b.copy_from_slice(&DUMMY_SEED[BLOCK_LEN..2 * BLOCK_LEN]);
        let all_zero = [0u8; BLOCK_LEN];
        let all_ff = [0xFFu8; BLOCK_LEN];

        // decrypt_block(encrypt_block(x)) == x, on a handful of representative blocks.
        for block in [a, b, all_zero, all_ff] {
            let mut buf = block;
            permutation.encrypt_block(&mut buf);
            permutation.decrypt_block(&mut buf);
            assert_eq!(buf, block, "decrypt_block(encrypt_block(x)) must equal x");
        }

        // Pair contract: encrypt_blocks2([x, y]) must equal [encrypt_block(x), encrypt_block(y)],
        // order-preserved and independent -- checked with distinct, equal, and swapped block pairs
        // to catch an override that ignores one half or transposes the two.
        for (x, y) in [(a, b), (b, a), (a, a)] {
            let mut want_encrypted = [x, y];
            permutation.encrypt_block(&mut want_encrypted[0]);
            permutation.encrypt_block(&mut want_encrypted[1]);

            let mut got_encrypted = [x, y];
            permutation.encrypt_blocks2(&mut got_encrypted);
            assert_eq!(
                got_encrypted, want_encrypted,
                "encrypt_blocks2 must match two independent encrypt_block calls, order preserved"
            );

            let mut want_decrypted = got_encrypted;
            permutation.decrypt_block(&mut want_decrypted[0]);
            permutation.decrypt_block(&mut want_decrypted[1]);

            let mut got_decrypted = got_encrypted;
            permutation.decrypt_blocks2(&mut got_decrypted);
            assert_eq!(
                got_decrypted, want_decrypted,
                "decrypt_blocks2 must match two independent decrypt_block calls, order preserved"
            );
            assert_eq!(got_decrypted, [x, y], "decrypt_blocks2 must invert encrypt_blocks2");
        }

        // error case: KeyMaterial of wrong type
        let mac_key =
            KeyMaterial::<KEY_LEN>::from_bytes_as_type(&DUMMY_SEED[..KEY_LEN], KeyType::MACKey)
                .unwrap();
        match P::new(&mac_key) {
            Err(SymmetricCipherError::KeyMaterialError(_)) => { /* good */ }
            _ => panic!("Unexpected error"),
        };

        // error case: security strengths too weak and too strong
        let mut key = KeyMaterial::<KEY_LEN>::from_bytes_as_type(
            &DUMMY_SEED[..KEY_LEN],
            KeyType::SymmetricCipherKey,
        )
        .unwrap();
        let security_strengths = [
            SecurityStrength::None,
            SecurityStrength::_112bit,
            SecurityStrength::_128bit,
            SecurityStrength::_192bit,
            SecurityStrength::_256bit,
        ];
        for ss in security_strengths.iter() {
            // `set_security_strength` enforces its key-length guard even inside a
            // do_hazardous_operations() closure -- a KEY_LEN-byte key cannot be tagged at a
            // strength above `from_bytes(KEY_LEN)` -- so skip the strengths this key cannot carry
            // rather than unwrapping an error. (A 16-byte key can reach 128-bit and no higher.)
            if ss > &SecurityStrength::from_bytes(KEY_LEN) {
                continue;
            }

            // Tag the key at an arbitrary strength for the purpose of this test.
            do_hazardous_operations(&mut key, |key| key.set_security_strength(ss.clone())).unwrap();

            match P::new(&key) {
                Ok(_) => {
                    if ss >= &P::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should have been a strong enough key");
                    }
                }
                Err(SymmetricCipherError::KeyMaterialError(_)) => {
                    if ss < &P::MAX_SECURITY_STRENGTH { /* good */
                    } else {
                        panic!("Should not have accepted a key weaker than algorithm");
                    }
                }
                _ => panic!("Unexpected error"),
            };
        }
    }
}
