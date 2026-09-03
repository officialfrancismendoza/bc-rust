//! Raw cryptographic primitives. Not for application use -- a block permutation applied directly
//! to data is ECB mode. Use these to implement a mode in `bouncycastle-modes`, or consume them
//! through one.
//!
//! This module is the intended home for keyed permutations, such as a block cipher's forward and
//! inverse functions considered in isolation from any mode of operation, and, in the future, other
//! raw primitives that a mode or construction is built from (for example a raw Keccak-f
//! permutation, if one is ever exposed as a public API). Anything that adds an initialization
//! vector, nonce, or padding is a mode, not a primitive, and belongs in [`crate::traits`] instead.

use crate::errors::SymmetricCipherError;
use crate::key_material::KeyMaterial;
use crate::traits::BlockCipher;
use core::marker::Sized;

/// A keyed block permutation: the forward and inverse functions of a block cipher algorithm,
/// considered in isolation from any mode of operation.
///
/// # Not for application use
/// Every method here is public API, and Rust has no mechanism to make a trait method callable
/// only by trusted code, so this warning is enforced by convention, not by the type system: calling
/// [`BlockPermutation::encrypt_block`] directly on application data *is* ECB mode, which leaks
/// equal-plaintext-block patterns into the ciphertext and is not semantically secure for any
/// realistic use case. Third-party implementations (for example a hardware-backed or
/// platform-accelerated permutation) are intentionally allowed -- this trait is not sealed -- but
/// callers should reach it through a type in `bouncycastle-modes` (which takes a
/// `P: BlockPermutation` type parameter), or through such a type's consumer, rather than calling
/// these methods directly.
///
/// # Spec correspondence
/// NIST SP 800-38A §5.1 ("Underlying Block Cipher Algorithm"):
/// > For any given key, the underlying block cipher algorithm of the mode also consists of two
/// > functions that are inverses of each other. ... as part of the choice of the block cipher
/// > algorithm, one of the two functions is designated as the forward cipher function, denoted
/// > CIPH_K; the other function is then called the inverse cipher function, denoted CIPH⁻¹_K. The
/// > inputs and outputs of both functions are called input blocks and output blocks. The input and
/// > output blocks of the block cipher algorithm have the same bit length, called the block size,
/// > denoted b.
///
/// §4.2.2 ("Operations and Functions") gives the notation used above:
/// > CIPH_K(X)  The forward cipher function of the block cipher algorithm under the key K applied
/// >            to the data block X.
/// > CIPH⁻¹_K(X) The inverse cipher function of the block cipher algorithm under the key K applied
/// >            to the data block X.
///
/// `KEY_LEN` is the length of `K` in bytes; `BLOCK_LEN` is the block size `b` from §5.1, in bytes
/// (the spec's `b` is a bit length).
pub trait BlockPermutation<const KEY_LEN: usize, const BLOCK_LEN: usize>:
    BlockCipher + Sized
{
    /// Establishes the key `K` referenced throughout SP 800-38A §5.1.
    fn new(key: &KeyMaterial<KEY_LEN>) -> Result<Self, SymmetricCipherError>;

    /// Applies the forward cipher function CIPH_K (SP 800-38A §4.2.2) to `block`, in place.
    fn encrypt_block(&self, block: &mut [u8; BLOCK_LEN]);

    /// Applies the inverse cipher function CIPH⁻¹_K (SP 800-38A §4.2.2) to `block`, in place.
    fn decrypt_block(&self, block: &mut [u8; BLOCK_LEN]);

    /// Applies [`BlockPermutation::encrypt_block`] to each of the two blocks independently:
    /// `encrypt_blocks2([a, b])` always produces `[encrypt_block(a), encrypt_block(b)]` -- the two
    /// blocks are independent (neither result depends on the other block's value) and order is
    /// preserved. This is a hook for implementations that can process two blocks more efficiently
    /// together (for example a bit-sliced or SIMD implementation); the provided default just calls
    /// [`BlockPermutation::encrypt_block`] twice, so overriding it is optional and never changes
    /// the result.
    fn encrypt_blocks2(&self, blocks: &mut [[u8; BLOCK_LEN]; 2]) {
        let [a, b] = blocks;
        self.encrypt_block(a);
        self.encrypt_block(b);
    }

    /// Applies [`BlockPermutation::decrypt_block`] to each of the two blocks independently, with
    /// the same independence-and-order-preservation contract as
    /// [`BlockPermutation::encrypt_blocks2`].
    fn decrypt_blocks2(&self, blocks: &mut [[u8; BLOCK_LEN]; 2]) {
        let [a, b] = blocks;
        self.decrypt_block(a);
        self.decrypt_block(b);
    }
}
