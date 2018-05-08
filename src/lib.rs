#![no_std]

use core::mem::transmute;

const RHO: [u32; 24] = [
     1,  3,  6, 10, 15, 21,
    28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43,
    62, 18, 39, 61, 20, 44
];

const PI: [usize; 24] = [
    10,  7, 11, 17, 18, 3,
     5, 16,  8, 21, 24, 4,
    15, 23, 19, 13, 12, 2,
    20, 14, 22,  9,  6, 1
];

const RC: [u64; 24] = [
    1u64, 0x8082u64, 0x800000000000808au64, 0x8000000080008000u64,
    0x808bu64, 0x80000001u64, 0x8000000080008081u64, 0x8000000000008009u64,
    0x8au64, 0x88u64, 0x80008009u64, 0x8000000au64,
    0x8000808bu64, 0x800000000000008bu64, 0x8000000000008089u64, 0x8000000000008003u64,
    0x8000000000008002u64, 0x8000000000000080u64, 0x800au64, 0x800000008000000au64,
    0x8000000080008081u64, 0x8000000000008080u64, 0x80000001u64, 0x8000000080008008u64
];

#[allow(unused_assignments)]
/// keccak-f[1600]
pub fn keccakf(a: &mut [u64; PLEN]) {
    let mut arrays: [[u64; 5]; 24] = [[0; 5]; 24];

    for i in 0..24 {
        // Theta
        for x in 0..5 {
            // This looks useless but it gets way slower without it. I tried using
            // `mem::uninitialized` for the initialisation of `arrays` but that also makes
            // it slower, although not by as much as removing this assignment. Optimisers
            // are weird. Maybe a different version of LLVM will react differently, so if
            // you see this comment in the future try deleting this assignment and using
            // uninit above and see how it affects the benchmarks.
            arrays[i][x] = 0;

            for y_count in 0..5 {
                let y = y_count * 5;
                arrays[i][x] ^= a[x + y];
            }
        }

        for x in 0..5 {
            for y_count in 0..5 {
                let y = y_count * 5;
                a[y + x] ^= arrays[i][(x + 4) % 5] ^ arrays[i][(x + 1) % 5].rotate_left(1);
            }
        }

        // Rho and pi
        let mut last = a[1];
        for x in 0..24 {
            arrays[i][0] = a[PI[x]];
            a[PI[x]] = last.rotate_left(RHO[x]);
            last = arrays[i][0];
        }

        // Chi
        for y_step in 0..5 {
            let y = y_step * 5;

            for x in 0..5 {
                arrays[i][x] = a[y + x];
            }

            for x in 0..5 {
                a[y + x] = arrays[i][x] ^ ((!arrays[i][(x + 1) % 5]) & (arrays[i][(x + 2) % 5]));
            }
        }

        // Iota
        a[0] ^= RC[i];
    }
}

fn setout(src: &[u8], dst: &mut [u8], len: usize) {
    dst[..len].copy_from_slice(&src[..len]);
}

fn xorin(dst: &mut [u8], src: &[u8]) {
    assert!(dst.len() <= src.len());
    let len = dst.len();
    let mut dst_ptr = dst.as_mut_ptr();
    let mut src_ptr = src.as_ptr();
    for _ in 0..len {
        unsafe {
            *dst_ptr ^= *src_ptr;
            src_ptr = src_ptr.offset(1);
            dst_ptr = dst_ptr.offset(1);
        }
    }
}

/// Total number of lanes.
const PLEN: usize = 25;

/// This structure should be used to create keccak/sha3 hash.
pub struct Keccak {
    a: [u64; PLEN],
    offset: usize,
    rate: usize,
    delim: u8
}

impl Clone for Keccak {
    fn clone(&self) -> Self {
        let mut res = Keccak::new(self.rate, self.delim);
        res.a.copy_from_slice(&self.a);
        res.offset = self.offset;
        res
    }
}

macro_rules! impl_constructor {
    ($name: ident, $alias: ident, $bits: expr, $delim: expr) => {
        pub fn $name() -> Keccak {
            Keccak::new(200 - $bits/4, $delim)
        }

        pub fn $alias(data: &[u8], result: &mut [u8]) {
            let mut keccak = Keccak::$name();
            keccak.update(data);
            keccak.finalize(result);

        }
    }
}

macro_rules! impl_global_alias {
    ($alias: ident, $size: expr) => {
        pub fn $alias(data: &[u8]) -> [u8; $size / 8] {
            let mut result = [0u8; $size / 8];
            Keccak::$alias(data, &mut result);
            result
        }
    }
}

impl_global_alias!(shake128,  128);
impl_global_alias!(shake256,  256);
impl_global_alias!(keccak224, 224);
impl_global_alias!(keccak256, 256);
impl_global_alias!(keccak384, 384);
impl_global_alias!(keccak512, 512);
impl_global_alias!(sha3_224,  224);
impl_global_alias!(sha3_256,  256);
impl_global_alias!(sha3_384,  384);
impl_global_alias!(sha3_512,  512);

impl Keccak {
    pub fn new(rate: usize, delim: u8) -> Keccak {
        Keccak {
            a: [0; PLEN],
            offset: 0,
            rate: rate,
            delim: delim
        }
    }

    impl_constructor!(new_shake128,  shake128,  128, 0x1f);
    impl_constructor!(new_shake256,  shake256,  256, 0x1f);
    impl_constructor!(new_keccak224, keccak224, 224, 0x01);
    impl_constructor!(new_keccak256, keccak256, 256, 0x01);
    impl_constructor!(new_keccak384, keccak384, 384, 0x01);
    impl_constructor!(new_keccak512, keccak512, 512, 0x01);
    impl_constructor!(new_sha3_224,  sha3_224,  224, 0x06);
    impl_constructor!(new_sha3_256,  sha3_256,  256, 0x06);
    impl_constructor!(new_sha3_384,  sha3_384,  384, 0x06);
    impl_constructor!(new_sha3_512,  sha3_512,  512, 0x06);

    fn a_bytes(&self) -> &[u8; PLEN * 8] {
        unsafe { transmute(&self.a) }
    }

    fn a_mut_bytes(&mut self) -> &mut [u8; PLEN * 8] {
        unsafe { transmute(&mut self.a) }
    }

    pub fn update(&mut self, input: &[u8]) {
        self.absorb(input);
    }

    #[inline]
    pub fn keccakf(&mut self) {
        keccakf(&mut self.a);
    }

    pub fn finalize(mut self, output: &mut [u8]) {
        self.pad();

        // apply keccakf
        keccakf(&mut self.a);

        // squeeze output
        self.squeeze(output);
    }

    // Absorb input
    pub fn absorb(&mut self, input: &[u8]) {
        //first foldp
        let mut ip = 0;
        let mut l = input.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            xorin(&mut self.a_mut_bytes()[offset..][..rate], &input[ip..]);
            keccakf(&mut self.a);
            ip += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        // Xor in the last block
        xorin(&mut self.a_mut_bytes()[offset..][..l], &input[ip..]);
        self.offset = offset + l;
    }

    pub fn pad(&mut self) {
        let offset = self.offset;
        let rate = self.rate;
        let delim = self.delim;
        let aa = self.a_mut_bytes();
        aa[offset] ^= delim;
        aa[rate - 1] ^= 0x80;
    }

    pub fn fill_block(&mut self) {
        self.keccakf();
        self.offset = 0;
    }

    // squeeze output
    pub fn squeeze(&mut self, output: &mut [u8]) {
        // second foldp
        let mut op = 0;
        let mut l = output.len();
        while l >= self.rate {
            setout(self.a_bytes(), &mut output[op..], self.rate);
            keccakf(&mut self.a);
            op += self.rate;
            l -= self.rate;
        }

        setout(self.a_bytes(), &mut output[op..], l);
    }

    #[inline]
    pub fn xof(mut self) -> XofReader {
        self.pad();

        keccakf(&mut self.a);

        XofReader { keccak: self, offset: 0 }
    }
}

pub struct XofReader {
    keccak: Keccak,
    offset: usize
}

impl XofReader {
    pub fn squeeze(&mut self, output: &mut [u8]) {
        // second foldp
        let mut op = 0;
        let mut l = output.len();
        let mut rate = self.keccak.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            setout(&self.keccak.a_bytes()[offset..], &mut output[op..], rate);
            self.keccak.keccakf();
            op += rate;
            l -= rate;
            rate = self.keccak.rate;
            offset = 0;
        }

        setout(&self.keccak.a_bytes()[offset..], &mut output[op..], l);
        self.offset = offset + l;
    }
}

#[test]
fn test_hello() {
    let msg = "hello";
    let mut result: [u8; 32] = [0; 32];

    let mut k = Keccak::new_keccak256();
    k.update(msg.as_bytes());
    k.finalize(&mut result);

    let expected = [
        28, 138, 255, 149, 6, 133, 194, 237,
        75, 195, 23, 79, 52, 114, 40, 123,
        86, 217, 81, 123, 156, 148, 129, 39,
        49, 154, 9, 167, 163, 109, 234, 200
    ];
    assert_eq!(result, expected);
}
