/// Type alias for the Keccak sponge.
type KeccakArray = [[u64; 5]; 5];

/// Largest rate any capacity allows, i.e. the size of the absorb buffer.
const MAX_RATE: usize = 200;

/// Generic keccak implementation with capacity CAP and output size CAP / 2 (for the digest variants).
pub(crate) struct Keccak<const CAP: usize> {
    sponge: KeccakArray,
    /// The current block being absorbed: `buffer_len` message bytes followed by zeros.
    buffer: [u8; MAX_RATE],
    /// How many bytes of `buffer` hold absorbed message bytes.
    buffer_len: usize,
}

impl<const C: usize> Default for Keccak<C> {
    fn default() -> Self {
        Self {
            sponge: [[0; 5]; 5],
            buffer: [0; MAX_RATE],
            buffer_len: 0,
        }
    }
}

const KECCAK_ROUNDS: usize = 24;

impl<const C: usize> Keccak<C> {
    /// Rate in bytes: 1600-bit state minus the capacity.
    const RATE: usize = 200 - C;

    /// Update the hasher with the given data.
    pub(crate) fn update(&mut self, mut data: &[u8]) {
        let rate = Self::RATE;

        if self.buffer_len > 0 {
            let take = (rate - self.buffer_len).min(data.len());
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[..take]);
            self.buffer_len += take;
            data = &data[take..];
            if self.buffer_len < rate {
                return;
            }
            Self::xor_block(&mut self.sponge, &self.buffer[..rate]);
            self.sponge = Self::keccak_f1600(self.sponge);
            self.buffer_len = 0;
        }

        let mut blocks = data.chunks_exact(rate);
        for block in &mut blocks {
            self.absorb(block);
        }

        let remainder = blocks.remainder();
        self.buffer[..remainder.len()].copy_from_slice(remainder);
        self.buffer[remainder.len()..rate].fill(0);
        self.buffer_len = remainder.len();
    }

    /// Absorbs the final padded block and hands the sponge over to output production.
    pub(crate) fn squeeze(mut self, pad: u8) -> Squeeze<C> {
        let rate = Self::RATE;
        let len = self.buffer_len;
        Self::pad(&mut self.buffer[..rate], len, pad);
        Self::xor_block(&mut self.sponge, &self.buffer[..rate]);
        Squeeze {
            sponge: Self::keccak_f1600(self.sponge),
            offset: 0,
        }
    }

    fn xor_block(sponge: &mut KeccakArray, block: &[u8]) {
        for (i, lane_bytes) in block.chunks_exact(8).enumerate() {
            sponge[i % 5][i / 5] ^= u64::from_le_bytes(lane_bytes.try_into().unwrap());
        }
    }

    fn absorb(&mut self, block: &[u8]) {
        Self::xor_block(&mut self.sponge, block);
        self.sponge = Self::keccak_f1600(self.sponge);
    }

    fn read_block(sponge: &KeccakArray, offset: usize, out: &mut [u8]) {
        for (i, byte) in out.iter_mut().enumerate() {
            let index = offset + i;
            let lane = sponge[(index / 8) % 5][(index / 8) / 5];
            *byte = (lane >> (8 * (index % 8))) as u8;
        }
    }

    /// The "θ step" of the permutation functions.
    ///
    /// This step can be found in the "Pseudo-code description of the permutations" section
    /// of the [keccak spec](https://keccak.team/keccak_specs_summary.html).
    fn theta(mut array: KeccakArray) -> KeccakArray {
        let mut columns = [0; 5];
        for x in 0..5 {
            columns[x] = array[x][0] ^ array[x][1] ^ array[x][2] ^ array[x][3] ^ array[x][4];
        }
        for x in 0..5 {
            let neighbor_column_parity = columns[(x + 4) % 5] ^ columns[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                array[x][y] ^= neighbor_column_parity;
            }
        }
        array
    }

    /// The "ρ step" of the permutation functions.
    ///
    /// This step can be found in the "Pseudo-code description of the permutations" section
    /// of the [keccak spec](https://keccak.team/keccak_specs_summary.html).
    fn rho(mut array: KeccakArray) -> KeccakArray {
        /// Constants from Appendices table 2.
        /// https://keccak.team/keccak_specs_summary.html#rotationOffsets
        ///
        /// This is the "r" value in the ρ step of the pseudo-code.
        const ROTATION_CONSTANTS: [[u32; 5]; 5] = [
            [0, 36, 3, 41, 18],
            [1, 44, 10, 45, 2],
            [62, 6, 43, 15, 61],
            [28, 55, 25, 21, 56],
            [27, 20, 39, 8, 14],
        ];
        for x in 0..5 {
            for y in 0..5 {
                let rotation_constant = ROTATION_CONSTANTS[x][y];
                array[x][y] = array[x][y].rotate_left(rotation_constant);
            }
        }
        array
    }

    /// The "π step" of the permutation functions.
    ///
    /// This step can be found in the "Pseudo-code description of the permutations" section
    /// of the [keccak spec](https://keccak.team/keccak_specs_summary.html).
    fn pi(mut array: KeccakArray) -> KeccakArray {
        let old = array;
        for x in 0..5 {
            for y in 0..5 {
                let new_x = y;
                let new_y = (2 * x + 3 * y) % 5;
                array[new_x][new_y] = old[x][y];
            }
        }
        array
    }

    /// The "χ step" of the permutation functions.
    ///
    /// This step can be found in the "Pseudo-code description of the permutations" section
    /// of the [keccak spec](https://keccak.team/keccak_specs_summary.html).
    fn chi(array: KeccakArray) -> KeccakArray {
        let mut new_array = array;
        for x in 0..5 {
            for y in 0..5 {
                let left_x = (x + 1) % 5;
                let left = !array[left_x][y];

                let right_x = (x + 2) % 5;
                let right = array[right_x][y];
                new_array[x][y] ^= left & right;
            }
        }
        new_array
    }

    /// The "ι step" of the permutation functions.
    ///
    /// This step can be found in the "Pseudo-code description of the permutations" section
    /// of the [keccak spec](https://keccak.team/keccak_specs_summary.html).
    ///
    /// The spec uses "RC" as the Round Constant in the pseudocode,
    /// here we use the round number to index the ROUND_CONSTANTS lookup table.
    fn iota(mut array: KeccakArray, round_number: usize) -> KeccakArray {
        /// Constants from Appendices table 1.
        /// https://keccak.team/keccak_specs_summary.html#roundConstants
        const ROUND_CONSTANTS: [u64; KECCAK_ROUNDS] = [
            0x0000000000000001,
            0x0000000000008082,
            0x800000000000808A,
            0x8000000080008000,
            0x000000000000808B,
            0x0000000080000001,
            0x8000000080008081,
            0x8000000000008009,
            0x000000000000008A,
            0x0000000000000088,
            0x0000000080008009,
            0x000000008000000A,
            0x000000008000808B,
            0x800000000000008B,
            0x8000000000008089,
            0x8000000000008003,
            0x8000000000008002,
            0x8000000000000080,
            0x000000000000800A,
            0x800000008000000A,
            0x8000000080008081,
            0x8000000000008080,
            0x0000000080000001,
            0x8000000080008008,
        ];
        array[0][0] ^= ROUND_CONSTANTS[round_number];
        array
    }

    fn apply_round(mut array: KeccakArray, round_number: usize) -> KeccakArray {
        array = Self::theta(array);
        array = Self::rho(array);
        array = Self::pi(array);
        array = Self::chi(array);
        array = Self::iota(array, round_number);
        array
    }

    fn keccak_f1600(mut array: KeccakArray) -> KeccakArray {
        for round_number in 0..KECCAK_ROUNDS {
            array = Self::apply_round(array, round_number);
        }
        array
    }

    fn pad(block: &mut [u8], len: usize, domain: u8) {
        block[len] ^= domain;
        block[block.len() - 1] ^= 0x80;
    }
}

/// A sponge that has absorbed its final block, so it can only produce output.
pub struct Squeeze<const CAP: usize> {
    sponge: KeccakArray,
    /// How many bytes of the current rate block have already been handed out.
    offset: usize,
}

impl<const C: usize> Squeeze<C> {
    /// Fills `buffer` with the next bytes of the output stream, permuting when the
    /// current rate block runs out.
    pub fn squeeze(&mut self, mut buffer: &mut [u8]) {
        let rate = Keccak::<C>::RATE;
        while !buffer.is_empty() {
            if self.offset == rate {
                self.sponge = Keccak::<C>::keccak_f1600(self.sponge);
                self.offset = 0;
            }
            let take = (rate - self.offset).min(buffer.len());
            let (head, tail) = buffer.split_at_mut(take);
            Keccak::<C>::read_block(&self.sponge, self.offset, head);
            self.offset += take;
            buffer = tail;
        }
    }
}

pub trait Update {
    fn update(&mut self, data: &[u8]);
}
