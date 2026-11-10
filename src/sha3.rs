use crate::keccak::Update;

mod sealed {
    pub trait Sealed {}
    impl<const N: usize> Sealed for [u8; N] {}
}

/// The output of a [`Digest`] hasher, only implemented for constant length arrays.
///
/// This trait uses a bound which is not exported, and therefore can't be implemented for foreign types.
/// This means that [`Digest`] implementations MUST use constant-length arrays as the output type,
/// which is what a hashing algorithm should always do.
pub trait Output: AsRef<[u8]> + AsMut<[u8]> + sealed::Sealed {
    const LEN: usize;
}

impl<const N: usize> Output for [u8; N] {
    const LEN: usize = N;
}

/// pad10*1 domain suffix for the SHA-3 fixed-output variants (FIPS 202 §6.1): 0b01 || 1.
const SHA3_PAD: u8 = 0x06;

/// The core trait for fixed-length output hashers.
///
/// Note: [`Output`] can only be a constant-length array.
///
/// [`Output`]: Self::Output
pub trait Digest: Default + Update {
    type Output: Output;

    fn finalize(self) -> Self::Output;

    // Provided convenience method
    fn digest(data: &[u8]) -> Self::Output {
        let mut h = Self::default();
        h.update(data);
        h.finalize()
    }
}

pub trait DynDigest: Update {
    fn output_len(&self) -> usize;

    // Legally distinct name. (Joke, avoiding name collisions since DynDigest is implemented for every Digest type)
    /// Write the digest into the provided slice.
    ///
    /// # Panics
    ///
    /// Panics if the size of the slice is not equal to [`output_len`].
    ///
    /// [`output_len`]: Self::output_len
    fn finalize_into(self: Box<Self>, out: &mut [u8]);

    // Provided convenience method
    fn digest_boxed(self: Box<Self>) -> Box<[u8]> {
        let mut buffer = vec![0; self.output_len()];
        self.finalize_into(&mut buffer);
        buffer.into_boxed_slice()
    }
}

impl<D: Digest> DynDigest for D {
    fn output_len(&self) -> usize {
        D::Output::LEN
    }

    fn finalize_into(self: Box<Self>, out: &mut [u8]) {
        let digest = self.finalize();
        assert_eq!(
            out.len(),
            D::Output::LEN,
            "Output buffer must be exactly {} bytes long",
            D::Output::LEN
        );
        out.copy_from_slice(digest.as_ref());
    }
}

mod inner {
    use crate::keccak::{Keccak, Update};
    use crate::sha3::{Digest, SHA3_PAD};

    #[derive(Copy, Clone, Default)]
    pub struct Sha3<const OUT: usize, const CAP: usize>(Keccak<CAP>);

    impl<const OUT: usize, const CAP: usize> Update for Sha3<OUT, CAP> {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }
    }

    impl<const OUT: usize, const CAP: usize> Digest for Sha3<OUT, CAP> {
        type Output = [u8; OUT];

        fn finalize(self) -> Self::Output {
            let mut output = [0; OUT];
            let mut squeeze = self.0.squeeze(SHA3_PAD);
            squeeze.squeeze(&mut output);
            output
        }
    }
}

pub type Sha3_224 = inner::Sha3<28, 56>;
pub type Sha3_256 = inner::Sha3<32, 64>;
pub type Sha3_384 = inner::Sha3<48, 96>;
pub type Sha3_512 = inner::Sha3<64, 128>;

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::sha3::{Digest, DynDigest, Sha3_224, Sha3_256, Sha3_384, Sha3_512};

    #[test]
    fn test_sha3_224_on_empty_string() {
        let expected = hex!("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
        let digest = Sha3_224::digest(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha3_256_on_empty_string() {
        let expected = hex!("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        let digest = Sha3_256::digest(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha3_384_on_empty_string() {
        let expected = hex!(
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
        );
        let digest = Sha3_384::digest(b"");
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_sha3_512_on_empty_string() {
        let expected = hex!(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        let digest = Sha3_512::digest("".as_bytes());
        assert_eq!(digest, expected);
    }

    #[test]
    fn test_dyn_digest_output() {
        let sha3_224 = Sha3_224::default();
        let sha3_256 = Sha3_256::default();
        let mut hashers: Vec<Box<dyn DynDigest>> = vec![Box::new(sha3_224), Box::new(sha3_256)];

        let sha3_224_digest = hashers.swap_remove(0).digest_boxed();
        let sha3_224_expected: Box<[_]> = Box::new(hex!(
            "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7"
        ));
        assert_eq!(sha3_224_digest, sha3_224_expected);

        let sha3_256_digest = hashers.swap_remove(0).digest_boxed();
        let sha3_256_expected: Box<[_]> = Box::new(hex!(
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        ));
        assert_eq!(sha3_256_digest, sha3_256_expected);
    }

    #[test]
    fn test_finalize_into_subslice_of_bigger_array() {
        let sha3_256 = Box::new(Sha3_256::default());
        let mut buffer = [0; 50];
        sha3_256.finalize_into(&mut buffer[0..32]);
        let sha3_256_expected =
            hex!("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(buffer[0..32], sha3_256_expected);
        assert_eq!(buffer[32..], [0; 18]);
    }

    #[test]
    #[should_panic = "Output buffer must be exactly 32 bytes long"]
    fn test_finalize_into_panics_with_incorrect_buffer_length() {
        let sha3_256 = Box::new(Sha3_256::default());
        let mut wrong_length_buffer = [0; 50];
        sha3_256.finalize_into(&mut wrong_length_buffer)
    }
}
