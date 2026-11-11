use crate::keccak::Squeeze;

/// pad10*1 domain suffix for SHAKE (FIPS 202 §6.2): 0b1111 || 1.
const SHAKE_PAD: u8 = 0x1f;

pub trait XofRead {
    fn read(&mut self, buffer: &mut [u8]);

    /// Fills `n` fresh bytes of the output stream.
    fn read_boxed(&mut self, n: usize) -> Box<[u8]> {
        let mut buffer = vec![0; n];
        <Self as XofRead>::read(self, &mut buffer);
        buffer.into_boxed_slice()
    }
}

impl<const CAP: usize> XofRead for Squeeze<CAP> {
    fn read(&mut self, buffer: &mut [u8]) {
        self.squeeze(buffer);
    }
}

mod inner {
    use crate::keccak::{Keccak, Squeeze, Update};
    use crate::shake::SHAKE_PAD;

    #[derive(Copy, Clone, Default)]
    pub struct Shake<const CAP: usize>(Keccak<CAP>);

    impl<const CAP: usize> Shake<CAP> {
        pub fn update(&mut self, data: &[u8]) {
            self.0.update(data)
        }

        /// Absorbs the final block and returns the output stream.
        pub fn squeeze(self) -> Squeeze<CAP> {
            self.0.squeeze(SHAKE_PAD)
        }
    }

    impl<const CAP: usize> Update for Shake<CAP> {
        fn update(&mut self, data: &[u8]) {
            self.0.update(data);
        }
    }
}

pub type Shake128 = inner::Shake<32>;
pub type Shake256 = inner::Shake<64>;

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use crate::shake::{Shake128, Shake256, XofRead};

    #[test]
    fn test_shake128_on_empty_string() {
        let mut hasher = Shake128::default();
        hasher.update(b"");
        let mut reader = hasher.squeeze();
        let hash = reader.read_boxed(32);
        let expected = hex!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        assert_eq!(*hash, expected);
    }

    #[test]
    fn test_shake256_on_empty_string() {
        let expected = hex!(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
        let mut hasher = Shake256::default();
        hasher.update(b"");
        let hash = hasher.squeeze().read_boxed(64);
        assert_eq!(*hash, expected);
    }
    #[test]
    fn test_shake_128_double_read() {
        let hasher = Shake128::default();
        let mut reader = hasher.squeeze();
        let mut two_reads = reader.read_boxed(32).to_vec();
        two_reads.extend(reader.read_boxed(32).into_iter());

        let hasher = Shake128::default();
        let single_read = hasher.squeeze().read_boxed(64);

        assert_eq!(two_reads, single_read.to_vec());
    }

    #[test]
    fn test_shake_256_double_read() {
        // 2 sequential reads should be the same as a single bigger read
        let hasher = Shake256::default();
        let mut reader = hasher.squeeze();
        let mut two_reads = reader.read_boxed(32).to_vec();
        two_reads.extend(reader.read_boxed(32).into_iter());

        let hasher = Shake256::default();
        let single_read = hasher.squeeze().read_boxed(64);

        assert_eq!(two_reads, single_read.to_vec());
    }
}
