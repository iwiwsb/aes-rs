fn main() {
    println!("Hello, world!");
}

const S_BOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

const INV_S_BOX: [u8; 256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
];

const ROUND_CONSTANTS: [u32; 10] = [
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
    0x1B000000, 0x36000000,
];

/*fn euclid_alg_ex(a: i32, b: i32) -> (i32, i32, i32) {
    let mut x2 = 1;
    let mut x1 = 0;
    let mut y2 = 0;
    let mut y1 = 1;
    let mut x: i32;
    let mut y: i32;

    let mut a_= a;
    let mut b_= b;

    let mut q: i32;
    let mut r: i32;

    while b_ != 0 {
        q = a_ / b_;
        r = a_ - q * b_;
        x = x2 - q * x1;
        y = y2 - q * y1;

        a_ = b_;
        b_ = r;
        x2 = x1;
        x1 = x;
        y2 = y1;
        y1 = y;
    }
    (a_, x2, y2)
}*/

fn x_times(b: u8) -> u8 {
    if b & 0b10000000 == 0 {
        b << 1
    } else {
        (b << 1) ^ 0b00011011
    }
}

fn sub_byte(byte: u8) -> u8 {
    S_BOX[byte as usize]
}

fn inv_sub_byte(byte: u8) -> u8 {
    INV_S_BOX[byte as usize]
}

fn sub_word(word: u32) -> u32 {
    let bytes: [u8; 4] = word.to_be_bytes();
    u32::from_be_bytes([
        sub_byte(bytes[0]),
        sub_byte(bytes[1]),
        sub_byte(bytes[2]),
        sub_byte(bytes[3]),
    ])
}

fn mix_column(column: u32) -> u32 {
    let bytes: [u8; 4] = column.to_be_bytes();
    let s0 = x_times(bytes[0]) ^ (x_times(bytes[1]) ^ bytes[1]) ^ bytes[2] ^ bytes[3];
    let s1 = bytes[0] ^ x_times(bytes[1]) ^ (x_times(bytes[2]) ^ bytes[2]) ^ bytes[3];
    let s2 = bytes[0] ^ bytes[1] ^ x_times(bytes[2]) ^ (x_times(bytes[3]) ^ bytes[3]);
    let s3 = (x_times(bytes[0]) ^ bytes[0]) ^ bytes[1] ^ bytes[2] ^ x_times(bytes[3]);
    u32::from_be_bytes([s0, s1, s2, s3])
}

fn key_expansion<const NK: usize, const S: usize>(key: [u32; NK]) -> [u32; S] {
    let mut w: [u32; S] = [0; S];
    w[..NK].copy_from_slice(&key[..NK]);
    let mut temp;
    for i in NK..S {
        temp = w[i - 1];
        if i % NK == 0 {
            temp = sub_word(temp.rotate_left(8)) ^ ROUND_CONSTANTS[(i - 1) / NK];
        } else if NK > 6 && i % NK == 4 {
            temp = sub_word(temp);
        }
        w[i] = w[i - NK] ^ temp;
    }
    w
}

fn key_expansion_128(key: [u32; 4]) -> [u32; 44] {
    key_expansion::<4, 44>(key)
}

fn key_expansion_192(key: [u32; 6]) -> [u32; 52] {
    key_expansion::<6, 52>(key)
}

fn key_expansion_256(key: [u32; 8]) -> [u32; 60] {
    key_expansion::<8, 60>(key)
}

fn aes_128(input: [u8; 16], key: [u32; 4]) -> AESState {
    let mut state = AESState { raw: input };
    let expanded_key = key_expansion_128(key);
    let mut round_key = [0u32; 4];
    round_key.copy_from_slice(&expanded_key[0..4]);
    println!("{:X?}", round_key);
    state.add_round_key(&round_key);
    println!("{:X?}", state);
    for r in 1..10 {
        round_key.copy_from_slice(&expanded_key[4 * r..4 * r + 4]);
        state.sub_bytes();
        state.shift_rows();
        state.mix_columns();
        state.add_round_key(&round_key)
    }
    round_key.copy_from_slice(&expanded_key[4 * 10..4 * 10 + 4]);
    state.sub_bytes();
    state.shift_rows();
    state.add_round_key(&round_key);
    state
}

fn aes_192(input: [u8; 16], key: [u32; 6]) -> [u8; 16] {
    todo!()
}

fn aes_256(input: [u8; 16], key: [u32; 8]) -> [u8; 16] {
    todo!()
}

#[derive(Debug, PartialEq)]
struct AESState {
    raw: [u8; 16],
}

impl AESState {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sub_byte() {
        assert_eq!(sub_byte(0x19), 0xD4);
    }

    #[test]
    fn test_x_times() {
        assert_eq!(x_times(0xAE), 0x47);
    }

    #[test]
    fn test_key_expansion_128() {
        let key: [u32; 4] = [0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C];
        let result: [u32; 44] = [
            0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C, 0xA0FAFE17, 0x88542CB1, 0x23A33939,
            0x2A6C7605, 0xF2C295F2, 0x7A96B943, 0x5935807A, 0x7359F67F, 0x3D80477D, 0x4716FE3E,
            0x1E237E44, 0x6D7A883B, 0xEF44A541, 0xA8525B7F, 0xB671253B, 0xDB0BAD00, 0xD4D1C6F8,
            0x7C839D87, 0xCAF2B8BC, 0x11F915BC, 0x6D88A37A, 0x110B3EFD, 0xDBF98641, 0xCA0093FD,
            0x4E54F70E, 0x5F5FC9F3, 0x84A64FB2, 0x4EA6DC4F, 0xEAD27321, 0xB58DBAD2, 0x312BF560,
            0x7F8D292F, 0xAC7766F3, 0x19FADC21, 0x28D12941, 0x575C006E, 0xD014F9A8, 0xC9EE2589,
            0xE13F0CC8, 0xB6630CA6,
        ];
        assert_eq!(key_expansion_128(key), result)
    }

    #[test]
    fn test_key_expansion_192() {
        let key: [u32; 6] = [
            0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5, 0x62F8EAD2, 0x522C6B7B,
        ];
        let result: [u32; 52] = [
            0x8E73B0F7, 0xDA0E6452, 0xC810F32B, 0x809079E5, 0x62F8EAD2, 0x522C6B7B, 0xFE0C91F7,
            0x2402F5A5, 0xEC12068E, 0x6C827F6B, 0x0E7A95B9, 0x5C56FEC2, 0x4DB7B4BD, 0x69B54118,
            0x85A74796, 0xE92538FD, 0xE75FAD44, 0xBB095386, 0x485AF057, 0x21EFB14F, 0xA448F6D9,
            0x4D6DCE24, 0xAA326360, 0x113B30E6, 0xA25E7ED5, 0x83B1CF9A, 0x27F93943, 0x6A94F767,
            0xC0A69407, 0xD19DA4E1, 0xEC1786EB, 0x6FA64971, 0x485F7032, 0x22CB8755, 0xE26D1352,
            0x33F0B7B3, 0x40BEEB28, 0x2F18A259, 0x6747D26B, 0x458C553E, 0xA7E1466C, 0x9411F1DF,
            0x821F750A, 0xAD07D753, 0xCA400538, 0x8FCC5006, 0x282D166A, 0xBC3CE7B5, 0xE98BA06F,
            0x448C773C, 0x8ECC7204, 0x01002202,
        ];
        assert_eq!(key_expansion_192(key), result)
    }

    #[test]
    fn test_key_expansion_256() {
        let key: [u32; 8] = [
            0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781, 0x1F352C07, 0x3B6108D7, 0x2D9810A3,
            0x0914DFF4,
        ];
        let result: [u32; 60] = [
            0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781, 0x1F352C07, 0x3B6108D7, 0x2D9810A3,
            0x0914DFF4, 0x9BA35411, 0x8E6925AF, 0xA51A8B5F, 0x2067FCDE, 0xA8B09C1A, 0x93D194CD,
            0xBE49846E, 0xB75D5B9A, 0xD59AECB8, 0x5BF3C917, 0xFEE94248, 0xDE8EBE96, 0xB5A9328A,
            0x2678A647, 0x98312229, 0x2F6C79B3, 0x812C81AD, 0xDADF48BA, 0x24360AF2, 0xFAB8B464,
            0x98C5BFC9, 0xBEBD198E, 0x268C3BA7, 0x09E04214, 0x68007BAC, 0xB2DF3316, 0x96E939E4,
            0x6C518D80, 0xC814E204, 0x76A9FB8A, 0x5025C02D, 0x59C58239, 0xDE136967, 0x6CCC5A71,
            0xFA256395, 0x9674EE15, 0x5886CA5D, 0x2E2F31D7, 0x7E0AF1FA, 0x27CF73C3, 0x749C47AB,
            0x18501DDA, 0xE2757E4F, 0x7401905A, 0xCAFAAAE3, 0xE4D59B34, 0x9ADF6ACE, 0xBD10190D,
            0xFE4890D1, 0xE6188D0B, 0x046DF344, 0x706C631E,
        ];
        assert_eq!(key_expansion_256(key), result)
    }

    #[test]
    fn test_aes_state_sub_bytes() {
        let mut state = AESState {
            raw: [
                0x19, 0xA0, 0x9A, 0xE9, 0x3D, 0xF4, 0xC6, 0xF8, 0xE3, 0xE2, 0x8D, 0x48, 0xBE, 0x2B,
                0x2A, 0x08,
            ],
        };

        let result: [u8; 16] = [
            0xD4, 0xE0, 0xB8, 0x1E, 0x27, 0xBF, 0xB4, 0x41, 0x11, 0x98, 0x5D, 0x52, 0xAE, 0xF1,
            0xE5, 0x30,
        ];
        state.sub_bytes();

        assert_eq!(state.raw, result);
    }

    #[test]
    fn test_aes_state_shift_rows() {
        let mut state = AESState {
            raw: [
                0xD4, 0xE0, 0xB8, 0x1E, 0x27, 0xBF, 0xB4, 0x41, 0x11, 0x98, 0x5D, 0x52, 0xAE, 0xF1,
                0xE5, 0x30,
            ],
        };

        let result: [u8; 16] = [
            0xD4, 0xE0, 0xB8, 0x1E, 0xBF, 0xB4, 0x41, 0x27, 0x5D, 0x52, 0x11, 0x98, 0x30, 0xAE,
            0xF1, 0xE5,
        ];

        state.shift_rows();

        assert_eq!(state.raw, result);
    }

    #[test]
    fn test_aes_state_mix_columns() {
        let mut state = AESState {
            raw: [
                0xD4, 0xE0, 0xB8, 0x1E, 0xBF, 0xB4, 0x41, 0x27, 0x5D, 0x52, 0x11, 0x98, 0x30, 0xAE,
                0xF1, 0xE5,
            ],
        };

        let result: [u8; 16] = [
            0x04, 0xE0, 0x48, 0x28, 0x66, 0xCB, 0xF8, 0x06, 0x81, 0x19, 0xD3, 0x26, 0xE5, 0x9A,
            0x7A, 0x4C,
        ];

        state.mix_columns();

        assert_eq!(state.raw, result);
    }

    #[test]
    fn test_aes_state_add_round_key() {
        let mut state = AESState {
            raw: [
                0x32, 0x88, 0x31, 0xE0, 0x43, 0x5A, 0x31, 0x37, 0xF6, 0x30, 0x98, 0x07, 0xA8, 0x8D,
                0xA2, 0x34,
            ],
        };

        let round_key: [u32; 4] = [0x2B7E1516, 0x28AED2A6, 0xABF71588, 0x09CF4F3C];

        let result: [u8; 16] = [
            0x19, 0xA0, 0x9A, 0xE9, 0x3D, 0xF4, 0xC6, 0xF8, 0xE3, 0xE2, 0x8D, 0x48, 0xBE, 0x2B,
            0x2A, 0x08,
        ];

        state.add_round_key(&round_key);
        assert_eq!(state.raw, result);
    }

    #[test]
    fn test_aes_128() {
        let input: [u8; 16] = [
            0x32, 0x88, 0x31, 0xE0, 0x43, 0x5A, 0x31, 0x37, 0xF6, 0x30, 0x98, 0x07, 0xA8, 0x8D,
            0xA2, 0x34,
        ];

        let key: [u32; 4] = [
            u32::from_be_bytes([0x2B, 0x7E, 0x15, 0x16]),
            u32::from_be_bytes([0x28, 0xAE, 0xD2, 0xA6]),
            u32::from_be_bytes([0xAB, 0xF7, 0x15, 0x88]),
            u32::from_be_bytes([0x09, 0xCF, 0x4F, 0x3C]),
        ];

        let result = AESState {
            raw: [
                0x39, 0x02, 0xDC, 0x19, 0x25, 0xDC, 0x11, 0x6A, 0x84, 0x09, 0x85, 0x0B, 0x1D, 0xFB,
                0x97, 0x32,
            ],
        };

        assert_eq!(aes_128(input, key), result);
    }
}
