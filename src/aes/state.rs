use crate::aes::{inv_mix_column, inv_sub_byte, key_expansion, mix_column, sub_byte};

#[derive(Debug, PartialEq)]
struct State {
    raw: [u8; 16],
}

impl State {
    fn new(input: [u8; 16]) -> State {
        Self {
            raw: [
                input[0], input[4], input[8], input[12], input[1], input[5], input[9], input[13],
                input[2], input[6], input[10], input[14], input[3], input[7], input[11], input[15],
            ],
        }
    }

    fn columns(&self) -> [u32; 4] {
        [
            u32::from_be_bytes([self.raw[0], self.raw[4], self.raw[8], self.raw[12]]),
            u32::from_be_bytes([self.raw[1], self.raw[5], self.raw[9], self.raw[13]]),
            u32::from_be_bytes([self.raw[2], self.raw[6], self.raw[10], self.raw[14]]),
            u32::from_be_bytes([self.raw[3], self.raw[7], self.raw[11], self.raw[15]]),
        ]
    }

    fn rows(&self) -> [u32; 4] {
        [
            u32::from_be_bytes([self.raw[0], self.raw[1], self.raw[2], self.raw[3]]),
            u32::from_be_bytes([self.raw[4], self.raw[5], self.raw[6], self.raw[7]]),
            u32::from_be_bytes([self.raw[8], self.raw[9], self.raw[10], self.raw[11]]),
            u32::from_be_bytes([self.raw[12], self.raw[13], self.raw[14], self.raw[15]]),
        ]
    }

    fn from_columns(columns: [u32; 4]) -> [u8; 16] {
        let c1: [u8; 4] = columns[0].to_be_bytes();
        let c2: [u8; 4] = columns[1].to_be_bytes();
        let c3: [u8; 4] = columns[2].to_be_bytes();
        let c4: [u8; 4] = columns[3].to_be_bytes();

        let r1 = [c1[0], c2[0], c3[0], c4[0]];
        let r2 = [c1[1], c2[1], c3[1], c4[1]];
        let r3 = [c1[2], c2[2], c3[2], c4[2]];
        let r4 = [c1[3], c2[3], c3[3], c4[3]];

        [
            r1[0], r1[1], r1[2], r1[3], r2[0], r2[1], r2[2], r2[3], r3[0], r3[1], r3[2], r3[3],
            r4[0], r4[1], r4[2], r4[3],
        ]
    }

    fn add_round_key(&mut self, key: &[u32; 4]) {
        let mut columns = self.columns();
        columns[0] ^= key[0];
        columns[1] ^= key[1];
        columns[2] ^= key[2];
        columns[3] ^= key[3];

        self.raw = Self::from_columns(columns);
    }

    fn sub_bytes(&mut self) {
        self.raw = self.raw.map(sub_byte);
    }

    fn inv_sub_bytes(&mut self) {
        self.raw = self.raw.map(inv_sub_byte);
    }

    fn shift_rows(&mut self) {
        let rows = self.rows();

        let new_rows = [
            rows[0].to_be_bytes(),
            rows[1].rotate_left(8).to_be_bytes(),
            rows[2].rotate_left(16).to_be_bytes(),
            rows[3].rotate_left(24).to_be_bytes(),
        ]
        .concat();

        self.raw.copy_from_slice(&new_rows);
    }

    fn inv_shift_rows(&mut self) {
        let rows = self.rows();

        let new_rows = [
            rows[0].to_be_bytes(),
            rows[1].rotate_right(8).to_be_bytes(),
            rows[2].rotate_right(16).to_be_bytes(),
            rows[3].rotate_right(24).to_be_bytes(),
        ]
        .concat();

        self.raw.copy_from_slice(&new_rows);
    }

    fn mix_columns(&mut self) {
        let columns = self.columns();
        let mixed_columns = [
            mix_column(columns[0]),
            mix_column(columns[1]),
            mix_column(columns[2]),
            mix_column(columns[3]),
        ];
        self.raw = Self::from_columns(mixed_columns);
    }

    fn inv_mix_columns(&mut self) {
        let columns = self.columns();
        let inv_mixed_columns = [
            inv_mix_column(columns[0]),
            inv_mix_column(columns[1]),
            inv_mix_column(columns[2]),
            inv_mix_column(columns[3]),
        ];
        self.raw = Self::from_columns(inv_mixed_columns);
    }

    fn encrypt<const KEY_LEN: usize, const EX_KEY_LEN: usize, const ROUNDS: usize>(
        &mut self,
        key: [u32; KEY_LEN],
    ) {
        let expanded_key: [u32; EX_KEY_LEN] = key_expansion(key);
        let mut round_key = [0u32; 4];
        round_key.copy_from_slice(&expanded_key[0..4]);
        self.add_round_key(&round_key);
        for r in 1..ROUNDS {
            round_key.copy_from_slice(&expanded_key[4 * r..4 * r + 4]);
            self.sub_bytes();
            self.shift_rows();
            self.mix_columns();
            self.add_round_key(&round_key)
        }
        round_key.copy_from_slice(&expanded_key[4 * ROUNDS..4 * ROUNDS + 4]);
        self.sub_bytes();
        self.shift_rows();
        self.add_round_key(&round_key);
    }

    fn encrypt_128(&mut self, key: [u32; 4]) {
        self.encrypt::<4, 44, 10>(key)
    }

    fn encrypt_192(&mut self, key: [u32; 6]) {
        self.encrypt::<6, 52, 12>(key)
    }

    fn encrypt_256(&mut self, key: [u32; 8]) {
        self.encrypt::<8, 60, 14>(key)
    }

    fn decrypt<const KEY_LEN: usize, const EX_KEY_LEN: usize, const ROUNDS: usize>(
        &mut self,
        key: [u32; KEY_LEN],
    ) {
        let expanded_key: [u32; EX_KEY_LEN] = key_expansion(key);
        let mut round_key = [0u32; 4];
        round_key.copy_from_slice(&expanded_key[4 * ROUNDS..4 * ROUNDS + 4]);
        self.add_round_key(&round_key);
        for r in (1..ROUNDS).rev() {
            round_key.copy_from_slice(&expanded_key[4 * r..4 * r + 4]);
            self.inv_shift_rows();
            self.inv_sub_bytes();
            self.add_round_key(&round_key);
            self.inv_mix_columns()
        }
        round_key.copy_from_slice(&expanded_key[0..4]);
        self.inv_shift_rows();
        self.inv_sub_bytes();
        self.add_round_key(&round_key);
    }

    fn decrypt_128(&mut self, key: [u32; 4]) {
        self.decrypt::<4, 44, 10>(key)
    }

    fn decrypt_192(&mut self, key: [u32; 6]) {
        self.decrypt::<6, 52, 12>(key)
    }

    fn decrypt_256(&mut self, key: [u32; 8]) {
        self.decrypt::<8, 60, 14>(key)
    }
}

#[cfg(test)]
mod tests {
    use super::State;

    #[test]
    fn test_sub_bytes() {
        let mut state = State::new([
            0x19, 0x3D, 0xE3, 0xBE, 0xA0, 0xF4, 0xE2, 0x2B, 0x9A, 0xC6, 0x8D, 0x2A, 0xE9, 0xF8,
            0x48, 0x08,
        ]);

        let result = State::new([
            0xD4, 0x27, 0x11, 0xAE, 0xE0, 0xBF, 0x98, 0xF1, 0xB8, 0xB4, 0x5D, 0xE5, 0x1E, 0x41,
            0x52, 0x30,
        ]);
        state.sub_bytes();

        assert_eq!(state, result);
    }

    #[test]
    fn test_inv_sub_bytes() {
        let mut state = State::new([
            0xD4, 0x27, 0x11, 0xAE, 0xE0, 0xBF, 0x98, 0xF1, 0xB8, 0xB4, 0x5D, 0xE5, 0x1E, 0x41,
            0x52, 0x30,
        ]);

        let result = State::new([
            0x19, 0x3D, 0xE3, 0xBE, 0xA0, 0xF4, 0xE2, 0x2B, 0x9A, 0xC6, 0x8D, 0x2A, 0xE9, 0xF8,
            0x48, 0x08,
        ]);
        state.inv_sub_bytes();

        assert_eq!(state, result);
    }

    #[test]
    fn test_rows() {
        let aes = State::new([
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37,
            0x07, 0x34,
        ]);
        let rows = aes.rows();
        let result = [0x328831E0, 0x435A3137, 0xF6309807, 0xA88DA234];

        assert_eq!(rows, result);
    }

    #[test]
    fn test_columns() {
        let aes = State::new([
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37,
            0x07, 0x34,
        ]);
        let columns = aes.columns();
        let result = [0x3243F6A8, 0x885A308D, 0x313198A2, 0xE0370734];

        assert_eq!(columns, result);
    }

    #[test]
    fn test_shift_rows() {
        let mut aes = State::new([
            0xD4, 0x27, 0x11, 0xAE, 0xE0, 0xBF, 0x98, 0xF1, 0xB8, 0xB4, 0x5D, 0xE5, 0x1E, 0x41,
            0x52, 0x30,
        ]);

        let result = State::new([
            0xD4, 0xBF, 0x5D, 0x30, 0xE0, 0xB4, 0x52, 0xAE, 0xB8, 0x41, 0x11, 0xF1, 0x1E, 0x27,
            0x98, 0xE5,
        ]);

        aes.shift_rows();
        assert_eq!(aes, result);
    }

    #[test]
    fn test_inv_shift_rows() {
        let mut aes = State::new([
            0xD4, 0xBF, 0x5D, 0x30, 0xE0, 0xB4, 0x52, 0xAE, 0xB8, 0x41, 0x11, 0xF1, 0x1E, 0x27,
            0x98, 0xE5,
        ]);

        let result = State::new([
            0xD4, 0x27, 0x11, 0xAE, 0xE0, 0xBF, 0x98, 0xF1, 0xB8, 0xB4, 0x5D, 0xE5, 0x1E, 0x41,
            0x52, 0x30,
        ]);

        aes.inv_shift_rows();
        assert_eq!(aes, result);
    }

    #[test]
    fn test_mix_columns() {
        let mut state = State::new([
            0xD4, 0xBF, 0x5D, 0x30, 0xE0, 0xB4, 0x52, 0xAE, 0xB8, 0x41, 0x11, 0xF1, 0x1E, 0x27,
            0x98, 0xE5,
        ]);

        let result = State::new([
            0x04, 0x66, 0x81, 0xE5, 0xE0, 0xCB, 0x19, 0x9A, 0x48, 0xF8, 0xD3, 0x7A, 0x28, 0x06,
            0x26, 0x4C,
        ]);

        state.mix_columns();

        assert_eq!(state, result);
    }

    #[test]
    fn test_inv_mix_columns() {
        let mut state = State::new([
            0x04, 0x66, 0x81, 0xE5, 0xE0, 0xCB, 0x19, 0x9A, 0x48, 0xF8, 0xD3, 0x7A, 0x28, 0x06,
            0x26, 0x4C,
        ]);
        let result = State::new([
            0xD4, 0xBF, 0x5D, 0x30, 0xE0, 0xB4, 0x52, 0xAE, 0xB8, 0x41, 0x11, 0xF1, 0x1E, 0x27,
            0x98, 0xE5,
        ]);
        state.inv_mix_columns();
        assert_eq!(state, result);
    }

    #[test]
    fn test_add_round_key() {
        let mut aes = State::new([
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37,
            0x07, 0x34,
        ]);

        let round_key: [u32; 4] = [0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C];

        let result = State::new([
            0x19, 0x3D, 0xE3, 0xBE, 0xA0, 0xF4, 0xE2, 0x2B, 0x9A, 0xC6, 0x8D, 0x2A, 0xE9, 0xF8,
            0x48, 0x08,
        ]);

        aes.add_round_key(&round_key);
        assert_eq!(aes, result);
    }

    #[test]
    fn test_aes_128_encrypt() {
        let mut aes = State::new([
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37,
            0x07, 0x34,
        ]);

        let key: [u32; 4] = [0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C];

        let result = State::new([
            0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A,
            0x0B, 0x32,
        ]);
        aes.encrypt_128(key);
        assert_eq!(aes, result);
    }

    #[test]
    fn test_aes_128_decrypt() {
        let mut aes = State::new([
            0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A,
            0x0B, 0x32,
        ]);

        let key: [u32; 4] = [0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C];

        let result = State::new([
            0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37,
            0x07, 0x34,
        ]);
        aes.decrypt_128(key);
        assert_eq!(aes, result);
    }
}
