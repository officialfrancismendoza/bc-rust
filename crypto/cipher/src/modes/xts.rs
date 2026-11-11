//! XTS, the XEX-based tweaked-codebook mode with ciphertext stealing, as IEEE Std 1619-2007
//! specifies it for AES and NIST SP 800-38E approves it, over any 128-bit block permutation.
//!
//! XTS encrypts one *data unit* -- a disk sector, say -- under a key and a 128-bit *tweak* that
//! names the data unit's position, and the ciphertext is exactly as long as the plaintext: there
//! is no IV, no nonce, no padding and no tag. A data unit is at least one block, 16 bytes, and at
//! most 2^20 blocks, 16 MiB, the limit SP 800-38E Sec 4 adds to IEEE 1619: "The length of the data
//! unit for any instance of an implementation of XTS-AES shall not exceed 2^20 AES blocks". A data
//! unit that is not a whole number of blocks is encrypted with ciphertext stealing, so its
//! ciphertext is as long as it is.
//!
//! The key is [`XTSKey`], built with `from_key_material` from the XTS key `Key = Key_1 | Key_2`:
//! two keys for the permutation, `Key_1` encrypting the data and `Key_2` the tweak, so 32 bytes
//! over a permutation with a 16-byte key and 64 over one with a 32-byte key. The data-unit length
//! is the key type's `DATA_UNIT_LEN`, because SP 800-38E Sec 4 defines an instance of XTS-AES by
//! "a secret key" and "a single, fixed length for the data units that the key protects"; a length
//! outside the range is a compile error. The ready-made `XTS_AES_128` / `XTS_AES_256` aliases are
//! in `bouncycastle-aes`. IEEE 1619 specifies XTS for AES only, and AES is the only cipher
//! SP 800-38E approves it for.
//!
//! # The tweak
//!
//! The tweak is the 128-bit value `i` that the mode encrypts under `Key_2`, taken as given. For
//! storage it is the data unit's sequence number as a 128-bit little-endian integer,
//! `u128::to_le_bytes(n)`, the encoding of NIST's ACVP sequence-number vectors (sequence number
//! 255 is the tweak `FF 00 .. 00`).
//!
//! # Usage Examples
//!
//! Over `ToyBlockCipher` (see the [module docs](super) for why); `bouncycastle-aes`'s aliases
//! carry examples over AES with published vectors:
//!
//! ```
//! # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
//! # use toy::ToyBlockCipher;
//! use bouncycastle_cipher::modes::XTSKey;
//! use bouncycastle_core::key_material::{KeyMaterial, KeyType};
//! use bouncycastle_core::symmetric_key::FromKeyMaterial;
//!
//! // Key = Key_1 | Key_2: 32 bytes over a permutation with a 16-byte key, the two halves distinct.
//! let key_bytes: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
//! let material = KeyMaterial::<32>::from_bytes_as_type(&key_bytes, KeyType::SymmetricCipherKey)
//!     .expect("a 32-byte symmetric cipher key");
//!
//! // 512-byte data units: the length is part of the key's type.
//! let key = XTSKey::<ToyBlockCipher, 512>::from_key_material(&material).expect("an XTS key");
//!
//! let mut sector = [0x5Au8; 512];
//! let tweak = 7u128.to_le_bytes(); // the data unit's sequence number
//! assert_eq!(key.encrypt_inplace(&tweak, &mut sector), 512);
//! assert_ne!(sector, [0x5Au8; 512]);
//! assert_eq!(key.decrypt_inplace(&tweak, &mut sector), 512);
//! assert_eq!(sector, [0x5Au8; 512]);
//! ```
//!
//! # 🚨 Security Considerations 🚨
//!
//! ## XTS provides confidentiality only
//!
//! SP 800-38E: "The mode does not provide authentication of the data or its source." A changed
//! ciphertext block decrypts to an unpredictable plaintext block rather than to an error, and an
//! older ciphertext of a data unit decrypts to the older plaintext. Each 16-byte block is
//! encrypted on its own under its position's mask, so someone who sees two versions of a data
//! unit learns which of its blocks changed, and the same plaintext under the same key and tweak
//! always gives the same ciphertext. Where any of that matters, authenticate the data, or use an
//! AEAD, which a format that can store a nonce and a tag should.
//!
//! ## XTS is for storage
//!
//! SP 800-38E Sec 3: "The XTS-AES mode was not designed for other purposes, such as the
//! encryption of data in transit", and FIPS 140-3 IG C.I: "AES-XTS is only approved for storage
//! purposes."
//!
//! ## One tweak per data unit
//!
//! The tweak is what makes the encryption of each data unit differ. Two data units encrypted
//! under one key and one tweak are encrypted under the same masks, so a block that is equal in
//! both, at the same offset, has an equal ciphertext in both. Give every data unit under a key its
//! own tweak, its sequence number.
//!
//! ## `Key_1` and `Key_2` must be independent
//!
//! FIPS 140-3 IG C.I requires `Key_1` and `Key_2` to be "generated and/or established
//! independently", and a module to "check explicitly that Key_1 ≠ Key_2": with equal halves, XTS
//! falls to a chosen-ciphertext attack. The key's constructor refuses equal halves, and one of
//! all zeros, but it cannot check independence. Draw the whole key from an RNG, with
//! `FromKeyMaterial::generate`, rather than deriving one half from the other.
//!
//! ## One data-unit length per key
//!
//! An instance of XTS-AES has "a single, fixed length for the data units that the key protects"
//! (SP 800-38E Sec 4), which a key type, with its `DATA_UNIT_LEN`, keeps to. Constructing a
//! second key type of another length from the same material steps outside it.

use crate::{Decrypting, Encrypting};
use bouncycastle_core::errors::{KeyMaterialError, SymmetricCipherError};
use bouncycastle_core::hazmat::{BlockPermutation, KeyExpansion};
use bouncycastle_core::key_material::{KeyMaterial, KeyMaterialTrait, KeyType};
use bouncycastle_core::security_strength::SecurityStrength;
use bouncycastle_core::symmetric_key::FromKeyMaterial;
use bouncycastle_utils::ct::ct_eq_bytes;
use bouncycastle_utils::min;
use bouncycastle_utils::secret::Secret;

/// The block length XTS is defined on: 128 bits, the width of the field GF(2^128) in which the
/// tweak's mask is multiplied by α from one block to the next.
const BLOCK_LEN: usize = 16;

/// A 128-bit block.
type Block = [u8; BLOCK_LEN];

/// The length of the tweak, in bytes: the 128-bit tweak value `i`.
pub const XTS_TWEAK_LEN: usize = 16;

/// The shortest data unit, in bytes: one block.
pub const XTS_MIN_DATA_UNIT_LEN: usize = BLOCK_LEN;

/// The longest data unit, in bytes: 2^20 blocks, 16 MiB (SP 800-38E Sec 4).
pub const XTS_MAX_DATA_UNIT_LEN: usize = (1 << 20) * BLOCK_LEN;

/// An XTS key over the permutation `P`, for data units of exactly `DATA_UNIT_LEN` bytes:
/// `Key_1` and `Key_2`, each expanded once, when the key is made.
///
/// Built with [`FromKeyMaterial`] from `Key = Key_1 | Key_2`, which is 32 bytes over a permutation
/// with a 16-byte key and 64 over one with a 32-byte key, tagged [`KeyType::SymmetricCipherKey`].
/// It encrypts and decrypts one data unit at a time, in place, under the data unit's tweak; see
/// the [module docs](self) for the tweak, and for the security considerations.
///
/// The only state is the two expanded keys, which the permutation holds so that they are
/// zeroized on drop; the key has no `Debug` and no way to read the material back.
///
/// # Construction
///
/// `from_key_material` refuses the key, as a [`SymmetricCipherError::KeyMaterialError`], with:
/// * [`KeyMaterialError::InvalidKeyType`] if it is not tagged [`KeyType::SymmetricCipherKey`],
///   or if either half is all zeros, which the permutation refuses as it does an all-zero key;
/// * [`KeyMaterialError::InvalidLength`] if it holds fewer bytes than the full key length;
/// * [`KeyMaterialError::GenericError`] if `Key_1` and `Key_2` are equal (FIPS 140-3 IG C.I);
/// * [`KeyMaterialError::SecurityStrength`] if it is tagged below the permutation's strength.
///   Each half carries the key's strength, capped at what the half's length can carry.
///
/// # The data-unit length is checked at compile time
///
/// A `DATA_UNIT_LEN` below [`XTS_MIN_DATA_UNIT_LEN`], an empty data unit included, or above
/// [`XTS_MAX_DATA_UNIT_LEN`] does not build. The check runs where the key type is used, so
/// `cargo build` and `cargo test` report it, and `cargo check` does not:
///
/// ```compile_fail
/// # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
/// # use toy::ToyBlockCipher;
/// # use bouncycastle_cipher::modes::{XTS_MAX_DATA_UNIT_LEN, XTSKey};
/// # use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// # use bouncycastle_core::symmetric_key::FromKeyMaterial;
/// # let bytes: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
/// # let km = KeyMaterial::<32>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
/// #     .expect("a 32-byte key");
/// // Shorter than one block.
/// let key = XTSKey::<ToyBlockCipher, 15>::from_key_material(&km);
/// ```
///
/// ```compile_fail
/// # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
/// # use toy::ToyBlockCipher;
/// # use bouncycastle_cipher::modes::{XTS_MAX_DATA_UNIT_LEN, XTSKey};
/// # use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// # use bouncycastle_core::symmetric_key::FromKeyMaterial;
/// # let bytes: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
/// # let km = KeyMaterial::<32>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
/// #     .expect("a 32-byte key");
/// // Longer than 2^20 blocks.
/// let key = XTSKey::<ToyBlockCipher, { XTS_MAX_DATA_UNIT_LEN + 1 }>::from_key_material(&km);
/// ```
///
/// The two bounds themselves build:
///
/// ```
/// # mod toy { include!("../../tests/common/toy_block_cipher.rs"); }
/// # use toy::ToyBlockCipher;
/// # use bouncycastle_cipher::modes::{XTS_MAX_DATA_UNIT_LEN, XTSKey};
/// # use bouncycastle_core::key_material::{KeyMaterial, KeyType};
/// # use bouncycastle_core::symmetric_key::FromKeyMaterial;
/// # let bytes: [u8; 32] = core::array::from_fn(|i| i as u8 + 1);
/// # let km = KeyMaterial::<32>::from_bytes_as_type(&bytes, KeyType::SymmetricCipherKey)
/// #     .expect("a 32-byte key");
/// let shortest = XTSKey::<ToyBlockCipher, 16>::from_key_material(&km);
/// let longest = XTSKey::<ToyBlockCipher, { XTS_MAX_DATA_UNIT_LEN }>::from_key_material(&km);
/// # assert!(shortest.is_ok() && longest.is_ok());
/// ```
pub struct XTSKey<P, const DATA_UNIT_LEN: usize> {
    /// `Key_1`, which encrypts the data.
    key1: P,
    /// `Key_2`, which encrypts the tweak.
    key2: P,
}

impl<P, const DATA_UNIT_LEN: usize> XTSKey<P, DATA_UNIT_LEN> {
    /// The bounds on the data-unit length, a compile-time error where the key type is used:
    /// evaluated when a constructor or a method is monomorphised, so that the private functions
    /// below are never handed a data unit outside them.
    const DATA_UNIT_LEN_CHECK: () = assert!(
        DATA_UNIT_LEN >= XTS_MIN_DATA_UNIT_LEN && DATA_UNIT_LEN <= XTS_MAX_DATA_UNIT_LEN,
        "an XTS data unit is from one block to 2^20 blocks (SP 800-38E Sec 4)"
    );
}

impl<P: BlockPermutation<BLOCK_LEN>, const DATA_UNIT_LEN: usize> XTSKey<P, DATA_UNIT_LEN> {
    /// Encrypts one data unit in place under its tweak, and returns the number of bytes written,
    /// which is always `DATA_UNIT_LEN`: the ciphertext is as long as the plaintext.
    pub fn encrypt_inplace(
        &self,
        tweak: &[u8; XTS_TWEAK_LEN],
        data_unit: &mut [u8; DATA_UNIT_LEN],
    ) -> usize {
        const { Self::DATA_UNIT_LEN_CHECK };
        encrypt(&self.key1, &self.key2, tweak, data_unit);
        DATA_UNIT_LEN
    }

    /// Decrypts one data unit in place under the tweak it was encrypted under, and returns the
    /// number of bytes written, which is always `DATA_UNIT_LEN`. There is nothing to verify: any
    /// data unit decrypts, a modified one to unpredictable plaintext.
    pub fn decrypt_inplace(
        &self,
        tweak: &[u8; XTS_TWEAK_LEN],
        data_unit: &mut [u8; DATA_UNIT_LEN],
    ) -> usize {
        const { Self::DATA_UNIT_LEN_CHECK };
        decrypt(&self.key1, &self.key2, tweak, data_unit);
        DATA_UNIT_LEN
    }
}

// One impl per key length, because the XTS key's length, twice the permutation's, cannot be
// written as an expression over the permutation's on stable Rust.

impl<P, const DATA_UNIT_LEN: usize> FromKeyMaterial<32> for XTSKey<P, DATA_UNIT_LEN>
where
    P: KeyExpansion<16> + BlockPermutation<BLOCK_LEN>,
{
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    /// Splits the 32-byte `Key_1 | Key_2` into two 16-byte keys and expands each; see
    /// [`XTSKey`] for when it refuses.
    fn from_key_material(key: &KeyMaterial<32>) -> Result<Self, SymmetricCipherError> {
        const { Self::DATA_UNIT_LEN_CHECK };
        let (key1, key2) = expand_halves::<P, 16, 32>(key)?;
        Ok(Self { key1, key2 })
    }
}

impl<P, const DATA_UNIT_LEN: usize> FromKeyMaterial<64> for XTSKey<P, DATA_UNIT_LEN>
where
    P: KeyExpansion<32> + BlockPermutation<BLOCK_LEN>,
{
    const KEY_TYPE: KeyType = KeyType::SymmetricCipherKey;

    /// Splits the 64-byte `Key_1 | Key_2` into two 32-byte keys and expands each; see
    /// [`XTSKey`] for when it refuses.
    fn from_key_material(key: &KeyMaterial<64>) -> Result<Self, SymmetricCipherError> {
        const { Self::DATA_UNIT_LEN_CHECK };
        let (key1, key2) = expand_halves::<P, 32, 64>(key)?;
        Ok(Self { key1, key2 })
    }
}

/// Parses `key` as `Key_1 | Key_2` and expands each half for `P`, after the checks that belong to
/// the XTS key as a whole: its type, its length, and `Key_1 != Key_2`. The permutation then checks
/// each half as it would any key of its own.
fn expand_halves<P, const HALF: usize, const FULL: usize>(
    key: &KeyMaterial<FULL>,
) -> Result<(P, P), SymmetricCipherError>
where
    P: KeyExpansion<HALF>,
{
    const { assert!(FULL == 2 * HALF, "an XTS key is two keys for the permutation") };

    // The halves are retagged for the permutation below, so the XTS key's own type is checked
    // here; otherwise a MAC key, say, would pass as a cipher key.
    if key.key_type() != KeyType::SymmetricCipherKey {
        return Err(KeyMaterialError::InvalidKeyType(
            "XTS requires a key of type KeyType::SymmetricCipherKey.",
        )
        .into());
    }
    // A `KeyMaterial<FULL>` can hold fewer than FULL bytes. Splitting a short key would hand the
    // permutation a short second half, or none; refuse it rather than take the buffer's zeros.
    if key.key_len() != FULL {
        return Err(KeyMaterialError::InvalidLength.into());
    }

    // FIPS 140-3 IG C.I: "Key is then parsed as the concatenation of two AES keys, denoted by
    // Key_1 and Key_2".
    let (key1, key2) = key.ref_to_bytes().split_at(HALF);

    // FIPS 140-3 IG C.I: "The module shall check explicitly that Key_1 ≠ Key_2, regardless of how
    // Key_1 and Key_2 are obtained." In constant time; only the outcome, a refusal, is public.
    if ct_eq_bytes(key1, key2) {
        return Err(KeyMaterialError::GenericError(
            "XTS requires Key_1 != Key_2 (FIPS 140-3 IG C.I).",
        )
        .into());
    }

    let strength = key.security_strength();
    Ok((P::new(&half(key1, strength)?)?, P::new(&half(key2, strength)?)?))
}

/// One half of the XTS key as a key for the permutation: `bytes` tagged
/// [`KeyType::SymmetricCipherKey`], at the XTS key's `strength` capped at what `HALF` bytes carry.
///
/// `from_bytes_as_type` credits a key with its full length, which for an XTS key tagged below
/// that would raise its strength in the halves; lowering it again needs no hazardous-operations
/// window. An all-zero half comes back [`KeyType::Zeroized`], at no strength, for the permutation
/// to refuse.
fn half<const HALF: usize>(
    bytes: &[u8],
    strength: SecurityStrength,
) -> Result<KeyMaterial<HALF>, SymmetricCipherError> {
    let mut half = KeyMaterial::<HALF>::from_bytes_as_type(bytes, KeyType::SymmetricCipherKey)?;
    let capped = *min(&strength, &half.security_strength());
    half.set_security_strength(capped)?;
    Ok(half)
}

// The algorithm. IEEE 1619-2007 itself was not to hand when this was written; the conventions
// below -- the order of the key halves, the byte order of the multiplication by α, and the order
// of the two blocks that ciphertext stealing produces -- are those of NIST's ACVP reference
// implementation of XTS-AES, and the NIST ACVP and Wycheproof vectors in `bouncycastle-aes` pin
// every one of them. The procedure names are SP 800-38E's: XTS-AES-blockEnc and -blockDec on one
// block, XTS-AES-Enc and -Dec on a data unit. The step numbers in the comments are the ones that
// reference implementation gives the steps of XTS-AES-blockEnc and -blockDec.

/// Step 3 of XTS-AES-blockEnc and XTS-AES-blockDec, the only step in which the two directions
/// differ: the forward cipher under `Key_1` when encrypting, the inverse when decrypting. The
/// mask, and its XOR on either side of the cipher, are the same in both.
trait CipherStep<P> {
    fn one(key1: &P, block: &mut Block);
    fn two(key1: &P, blocks: &mut [Block; 2]);
    fn four(key1: &P, blocks: &mut [Block; 4]);
}

impl<P: BlockPermutation<BLOCK_LEN>> CipherStep<P> for Encrypting {
    fn one(key1: &P, block: &mut Block) {
        key1.encrypt_block(block);
    }

    fn two(key1: &P, blocks: &mut [Block; 2]) {
        key1.encrypt_2blocks(blocks);
    }

    fn four(key1: &P, blocks: &mut [Block; 4]) {
        key1.encrypt_4blocks(blocks);
    }
}

impl<P: BlockPermutation<BLOCK_LEN>> CipherStep<P> for Decrypting {
    fn one(key1: &P, block: &mut Block) {
        key1.decrypt_block(block);
    }

    fn two(key1: &P, blocks: &mut [Block; 2]) {
        key1.decrypt_2blocks(blocks);
    }

    fn four(key1: &P, blocks: &mut [Block; 4]) {
        key1.decrypt_4blocks(blocks);
    }
}

/// `T ⊗ α`: multiplication by the primitive element α = x of GF(2^128), modulo
/// x^128 + x^7 + x^2 + x + 1, with the block read as a little-endian polynomial -- byte 0 holds
/// the coefficients of x^0..x^7 (bit k of the byte for x^k), byte 15 those of x^120..x^127.
///
/// That is a one-bit shift towards the top across the bytes, from byte 0 up; when the bit
/// shifted out of byte 15, the coefficient of x^127, is set, x^128 reduces to x^7 + x^2 + x + 1
/// and 0x87 is XORed into byte 0. The reduction is selected with a mask rather than a branch,
/// since `T` is secret (it is the tweak encrypted under `Key_2`), as CMAC's doubling does.
fn mul_alpha(t: &mut Block) {
    // The carry out of x^127, read before byte 15 is overwritten.
    let carry = t[BLOCK_LEN - 1] >> 7;
    // From the top byte down, so that byte k - 1 still holds its old value when byte k takes its
    // top bit. The two operands of `|` have no bit in common, so `|` and `^` agree here.
    for k in (1..BLOCK_LEN).rev() {
        t[k] = (t[k] << 1) | (t[k - 1] >> 7);
    }
    t[0] = (t[0] << 1) ^ (0x87 & 0u8.wrapping_sub(carry));
}

/// `block ^= mask`.
fn xor_into(block: &mut Block, mask: &Block) {
    for (b, m) in block.iter_mut().zip(mask) {
        *b ^= m;
    }
}

/// XTS-AES-blockEnc (`D = Encrypting`) or -blockDec (`D = Decrypting`) of one block in place,
/// under the mask `t`, which is `T = AES-enc(Key_2, i) ⊗ α^j` for the block's index `j` (step
/// 1): step 2 XORs `T` in, step 3 runs the cipher under `Key_1`, step 4 XORs `T` in again.
fn xex<P, D: CipherStep<P>>(key1: &P, t: &Block, block: &mut Block) {
    xor_into(block, t); // step 2: PP = P ^ T (CC = C ^ T)
    D::one(key1, block); // step 3: CC = AES-enc(Key_1, PP) (PP = AES-dec(Key_1, CC))
    xor_into(block, t); // step 4: C = CC ^ T (P = PP ^ T)
}

/// [`xex`] on each of `blocks` in turn, with consecutive indices: the first under the mask in `t`
/// and each later one under the mask before it times α. Returns with `t` holding the mask for the
/// index after the last block.
///
/// Given its mask, each block is independent of the others, so they go through the permutation
/// four at a time, then two, then one; the masks are the same sequence whatever the grouping.
fn xex_blocks<P, D: CipherStep<P>>(key1: &P, t: &mut Block, blocks: &mut [Block]) {
    // The masks of the blocks in flight. Declared once, before the loops, so that they are
    // zeroized once, after them.
    let mut masks: Secret<[Block; 4]> = Secret::new();

    let (fours, rest) = blocks.as_chunks_mut::<4>();
    for four in fours {
        for (block, mask) in four.iter_mut().zip(masks.iter_mut()) {
            *mask = *t;
            xor_into(block, mask);
            mul_alpha(t);
        }
        D::four(key1, four);
        for (block, mask) in four.iter_mut().zip(masks.iter()) {
            xor_into(block, mask);
        }
    }

    // At most three blocks are left: a pair and a single, or one of them, or none.
    let (twos, ones) = rest.as_chunks_mut::<2>();
    for two in twos {
        for (block, mask) in two.iter_mut().zip(masks.iter_mut()) {
            *mask = *t;
            xor_into(block, mask);
            mul_alpha(t);
        }
        D::two(key1, two);
        for (block, mask) in two.iter_mut().zip(masks.iter()) {
            xor_into(block, mask);
        }
    }
    for one in ones {
        xex::<P, D>(key1, t, one);
        mul_alpha(t);
    }
}

/// The mask of block 0 of a data unit under the tweak `i`: `T = AES-enc(Key_2, i) ⊗ α^0`, the
/// tweak encrypted under `Key_2` in both directions.
fn first_mask<P: BlockPermutation<BLOCK_LEN>>(key2: &P, i: &Block) -> Secret<Block> {
    let mut t: Secret<Block> = Secret::new();
    *t = *i;
    key2.encrypt_block(&mut t);
    t
}

/// XTS-AES-Enc of the data unit `data`, in place, under the tweak `i`. `data` is from
/// [`XTS_MIN_DATA_UNIT_LEN`] to [`XTS_MAX_DATA_UNIT_LEN`] bytes long, which the callers check at
/// compile time.
fn encrypt<P: BlockPermutation<BLOCK_LEN>>(key1: &P, key2: &P, i: &Block, data: &mut [u8]) {
    let mut t = first_mask(key2, i);

    // `blocks` are P_0 .. P_{m-1}, the whole blocks, and `tail` is P_m, the b < 16 bytes after
    // them, which is empty when the data unit is a whole number of blocks.
    let (blocks, tail) = data.as_chunks_mut::<BLOCK_LEN>();

    // C_q = XTS-AES-blockEnc(P_q, i, q) for every whole block. Without a partial block that is
    // the whole data unit; with one, the last of them is the CC that ciphertext stealing takes
    // apart.
    xex_blocks::<P, Encrypting>(key1, &mut t, blocks);

    // Ciphertext stealing, SP 800-38E Sec 5: "Cm is the truncation of a block that is derived
    // from Pm-1, and Cm-1 is derived from Pm, concatenated with the discarded bits from the
    // truncation." The last whole block holds CC, P_{m-1} encrypted under index m - 1. Swapping
    // its first b bytes with the tail leaves C_m = CC[..b] in the tail, in its place after C_{m-1},
    // and PP = P_m || CC[b..] in the block, which is then encrypted under index m -- the mask now
    // in `t` -- to C_{m-1}. Every index here depends on the length alone.
    if !tail.is_empty()
        && let Some(last) = blocks.last_mut()
    {
        last[..tail.len()].swap_with_slice(tail);
        xex::<P, Encrypting>(key1, &t, last);
    }
}

/// XTS-AES-Dec of the data unit `data`, in place, under the tweak `i`. The length is as for
/// [`encrypt`].
fn decrypt<P: BlockPermutation<BLOCK_LEN>>(key1: &P, key2: &P, i: &Block, data: &mut [u8]) {
    let mut t = first_mask(key2, i);
    let (blocks, tail) = data.as_chunks_mut::<BLOCK_LEN>();

    // With a partial block, ciphertext stealing undoes the encryption's last two block
    // operations, which used indices m - 1 and m, in the reverse order: C_{m-1} first, under m.
    if !tail.is_empty()
        && let Some((last, head)) = blocks.split_last_mut()
    {
        // P_q = XTS-AES-blockDec(C_q, i, q) for q < m - 1, leaving the mask of m - 1 in `t`.
        xex_blocks::<P, Decrypting>(key1, &mut t, head);

        // PP = XTS-AES-blockDec(C_{m-1}, i, m) = P_m || CC[b..], under the mask after `t`'s.
        let mut t_m: Secret<Block> = Secret::new();
        *t_m = *t;
        mul_alpha(&mut t_m);
        xex::<P, Decrypting>(key1, &t_m, last);

        // Swapping the first b bytes back puts P_m in the tail and CC = C_m || CC[b..] in the
        // block, and P_{m-1} = XTS-AES-blockDec(CC, i, m - 1).
        last[..tail.len()].swap_with_slice(tail);
        xex::<P, Decrypting>(key1, &t, last);
    } else {
        // P_q = XTS-AES-blockDec(C_q, i, q) for every block.
        xex_blocks::<P, Decrypting>(key1, &mut t, blocks);
    }
}
